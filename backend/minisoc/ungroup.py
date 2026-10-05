"""Dégroupage d'une alerte de regroupement (anti-tempête) : une alerte par entité, recréée à partir des événements
déjà stockés (rien n'est réimporté ni renotifié). L'alerte de regroupement est ensuite clôturée."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.ext.asyncio import AsyncSession

from minisoc.alerts import MAX_EVENT_IDS, STORM_ENTITY, Detection, upsert_alert
from minisoc.ecs import FIELDS
from minisoc.models import Alert, AlertHistory
from minisoc.rules.engine import RuleSet, render_title

MAX_EVENTS_PER_ENTITY = 500


class UngroupError(ValueError):
    pass


def _parts(entity_key: str) -> dict[str, str]:
    out = {}
    for part in entity_key.split(" | "):
        field, sep, value = part.partition("=")
        if sep:
            out[field.strip()] = value.strip()
    return out


def _utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


async def ungroup(session: AsyncSession, store, rules: RuleSet, alert_id: int, actor: str) -> int:
    """Retourne le nombre d'alertes recréées. Règles « match » seulement (une alerte par entité regroupée)."""
    storm = await session.get(Alert, alert_id, with_for_update=True)
    if storm is None:
        raise UngroupError("Alerte introuvable")
    if storm.entity_key != STORM_ENTITY:
        raise UngroupError("Cette alerte n'est pas une alerte de regroupement")
    rule = rules.by_id.get(storm.rule_id)
    if rule is None or rule.type != "match":
        raise UngroupError("Dégroupage possible seulement pour les règles de correspondance (alertes d'outils, etc.)")
    since = _utc(storm.first_seen) - timedelta(hours=1)
    created = 0
    for entity in (storm.details or {}).get("entities", {}):
        parts = _parts(entity)
        conditions = [(FIELDS[f], v) for f, v in parts.items() if f in FIELDS]
        if not conditions:
            continue
        where = " AND ".join(f"{column} = {{p{i}:String}}" for i, (column, _) in enumerate(conditions))
        params = {f"p{i}": value for i, (_, value) in enumerate(conditions)}
        rows = await store.query(
            f"SELECT * FROM events WHERE {where} AND ts >= {{since:DateTime64(3)}} "
            f"ORDER BY ts LIMIT {MAX_EVENTS_PER_ENTITY}",
            {**params, "since": since.replace(tzinfo=None)},
        )
        if not rows:
            continue
        last = rows[-1]
        values = {ecs: last.get(column) for ecs, column in FIELDS.items()}
        severity = (
            max(int(r.get("severity") or 0) for r in rows) if rule.severity == "from_event" else rule.severity_level
        )
        det = Detection(
            rule=rule,
            entity_key=entity,
            severity=severity,
            title=render_title(rule.title, values),
            first_seen=_utc(rows[0]["ts"]),
            last_seen=_utc(last["ts"]),
            count=len(rows),
            event_ids=[str(r["event_id"]) for r in rows][-MAX_EVENT_IDS:],
            modules=sorted({r["module"] for r in rows}),
            reference=next((r["reference"] for r in reversed(rows) if r.get("reference")), ""),
            details={
                "sample": {
                    k: (v.isoformat() if hasattr(v, "isoformat") else v if isinstance(v, (int, float)) else str(v))
                    for k, v in values.items()
                    if v not in ("", 0, None)
                },
                "ungrouped_from": storm.id,
            },
        )
        alert, action = await upsert_alert(session, det, allow_storm=False)
        if action == "created":
            alert.notify_pending = False  # déjà signalée par l'alerte de regroupement
            session.add(
                AlertHistory(
                    alert_id=alert.id,
                    actor=actor,
                    action="comment",
                    detail=f"Recréée en dégroupant l'alerte n° {storm.id}",
                )
            )
            created += 1
    storm.status = "resolved"
    storm.notify_pending = False
    session.add(AlertHistory(alert_id=storm.id, actor=actor, action="status", detail="resolved"))
    session.add(
        AlertHistory(
            alert_id=storm.id, actor=actor, action="comment", detail=f"Dégroupée en {created} alerte(s), une par entité"
        )
    )
    return created
