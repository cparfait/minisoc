"""Création et déduplication des alertes, exceptions (liste blanche)."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from minisoc.models import OPEN_STATUSES, Alert, AlertHistory, RuleException
from minisoc.rules.model import Rule

log = logging.getLogger(__name__)

MAX_EVENT_IDS = 50
SYSTEM = "système"
STORM_ENTITY = "*regroupement*"
STORM_WINDOW = timedelta(hours=1)
MAX_STORM_ENTITIES = 500
STORM_MIN_SEVERITY = 2  # moyenne
HISTORICAL_AFTER = timedelta(hours=24)  # détection plus ancienne : import d'historique (ni tempête, ni notification)


@dataclass
class Detection:
    """Résultat d'une règle, avant déduplication."""

    rule: Rule
    entity_key: str
    severity: int
    title: str
    first_seen: datetime
    last_seen: datetime
    count: int = 1
    metric: int = 1
    accumulate: bool = True  # True : les occurrences s'additionnent (match) ; False : fenêtre glissante
    event_ids: list[str] = field(default_factory=list)
    modules: list[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)
    reference: str = ""


async def upsert_alert(session: AsyncSession, det: Detection, allow_storm: bool = True) -> tuple[Alert, str]:
    """Fusionne la détection dans l'alerte ouverte de même (règle, entité), ou en crée une.

    Retourne (alerte, action) avec action ∈ {created, escalated, updated}. Seules `created` et
    `escalated` déclenchent une notification : une attaque de 10 000 événements = une notification.

    Anti-tempête : au-delà de `storm_limit` alertes créées par une règle en une heure (ex. un botnet de
    200 IP), les nouvelles entités sont regroupées dans une seule alerte de regroupement.
    """
    rule = det.rule
    existing = await _open_alert(session, rule.id, det.entity_key)
    if existing and det.last_seen - existing.last_seen <= rule.dedup_window:
        return existing, _update(session, existing, det)
    # Import d'historique (relecture des alertes passées d'un outil) : une alerte par entité, sans regroupement
    historical = datetime.now(timezone.utc) - det.last_seen > HISTORICAL_AFTER
    # Les détections jugées bénignes (sévérité faible) gardent leur propre alerte, hors regroupement
    if (allow_storm and not historical and rule.storm_limit and det.severity >= STORM_MIN_SEVERITY
            and await _storming(session, rule, det.last_seen)):
        return await _merge_into_storm(session, det)
    return await _create(session, det), "created"


async def _open_alert(session: AsyncSession, rule_id: str, entity_key: str) -> Alert | None:
    return await session.scalar(
        select(Alert)
        .where(Alert.rule_id == rule_id, Alert.entity_key == entity_key, Alert.status.in_(OPEN_STATUSES))
        .order_by(Alert.id.desc())
        .limit(1)
        .with_for_update()
    )


def _update(session: AsyncSession, existing: Alert, det: Detection) -> str:
    action = "updated"
    existing.first_seen = min(existing.first_seen, det.first_seen)  # import d'historique : détection plus ancienne
    existing.last_seen = max(existing.last_seen, det.last_seen)
    existing.count = existing.count + det.count if det.accumulate else max(existing.count, det.count)
    existing.metric = max(existing.metric, det.metric)
    existing.event_ids = _merge(existing.event_ids, det.event_ids)
    existing.modules = sorted(set(existing.modules) | set(det.modules))
    existing.details = {**existing.details, **det.details}
    if det.entity_key == STORM_ENTITY:
        existing.title = det.title  # le nombre d'entités regroupées évolue, sans nouvelle notification
    if det.severity > existing.severity:
        existing.severity = det.severity
        existing.title = det.title
        existing.notify_pending = True
        action = "escalated"
        session.add(AlertHistory(alert_id=existing.id, actor=SYSTEM, action="escalated", detail=det.title))
    return action


async def _storming(session: AsyncSession, rule: Rule, now: datetime) -> bool:
    storm = await _open_alert(session, rule.id, STORM_ENTITY)
    if storm and now - storm.last_seen <= rule.dedup_window:
        return True
    recent = await session.scalar(
        select(func.count()).where(
            Alert.rule_id == rule.id,
            Alert.entity_key != STORM_ENTITY,
            Alert.severity >= STORM_MIN_SEVERITY,
            Alert.created_at >= datetime.now(timezone.utc) - STORM_WINDOW,
        )
    )
    return (recent or 0) >= rule.storm_limit


async def _merge_into_storm(session: AsyncSession, det: Detection) -> tuple[Alert, str]:
    rule = det.rule
    storm = await _open_alert(session, rule.id, STORM_ENTITY)
    entities: dict[str, int] = dict((storm.details if storm else {}).get("entities", {}))
    if det.entity_key in entities or len(entities) < MAX_STORM_ENTITIES:
        previous = entities.get(det.entity_key, 0)
        entities[det.entity_key] = previous + det.count if det.accumulate else max(previous, det.count)
    grouped = replace(
        det,
        entity_key=STORM_ENTITY,
        title=f"{rule.name} : {len(entities)} entités regroupées (anti-tempête)",
        count=sum(entities.values()),
        metric=len(entities),
        accumulate=False,
        details={**det.details, "entities": entities, "storm": True},
    )
    if storm:
        return storm, _update(session, storm, grouped)
    return await _create(session, grouped), "created"


async def _create(session: AsyncSession, det: Detection) -> Alert:
    rule = det.rule
    alert = Alert(
        rule_id=rule.id,
        rule_name=rule.name,
        severity=det.severity,
        title=det.title,
        entity_key=det.entity_key[:512],
        status="new",
        first_seen=det.first_seen,
        last_seen=det.last_seen,
        count=det.count,
        metric=det.metric,
        event_ids=det.event_ids[-MAX_EVENT_IDS:],
        modules=sorted(set(det.modules)),
        details=det.details,
        reference=det.reference[:512],
        # Détection ancienne (import d'historique) : visible dans la liste, sans notification immédiate
        notify_pending=datetime.now(timezone.utc) - det.last_seen <= HISTORICAL_AFTER,
    )
    session.add(alert)
    await session.flush()
    session.add(AlertHistory(alert_id=alert.id, actor=SYSTEM, action="created", detail=det.title))
    return alert


def _merge(old: list[str], new: list[str]) -> list[str]:
    merged = list(dict.fromkeys([*old, *new]))
    return merged[-MAX_EVENT_IDS:]


class ExceptionCache:
    """Exceptions actives, rechargées périodiquement depuis la base."""

    def __init__(self, sessions: async_sessionmaker) -> None:
        self.sessions = sessions
        self.items: list[RuleException] = []

    async def refresh(self) -> None:
        now = datetime.now(timezone.utc)
        async with self.sessions() as session:
            result = await session.scalars(select(RuleException).where(RuleException.expires_at > now))
            self.items = list(result.all())

    def is_excepted(self, rule_id: str, values: dict[str, object]) -> bool:
        now = datetime.now(timezone.utc)
        for exc in self.items:
            if exc.expires_at <= now or exc.rule_id not in ("*", rule_id):
                continue
            if str(values.get(exc.field, "")) == exc.value:
                return True
        return False
