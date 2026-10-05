"""Tâches de fond des briques SIEM (lancées par le worker) : chasse aux IOC et listes externes, scellement des
archives, synchronisation de l'inventaire."""

from __future__ import annotations

import asyncio
import json
import logging
from collections import defaultdict
from collections.abc import Callable
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import delete, or_, select

from minisoc import archives, assets, ioc
from minisoc.alerts import Detection, upsert_alert
from minisoc.models import Ioc, IocFeed
from minisoc.rules.engine import entity_key, render_title
from minisoc.settings_store import store as settings_store

log = logging.getLogger(__name__)

IOC_NOW_KEY = "minisoc:ioc:hunt_now"  # bouton « Chasser maintenant »
IOC_CURSOR_KEY = "minisoc:ioc:cursor"  # date de réception déjà parcourue (chasse incrémentale)
IOC_STATUS_KEY = "minisoc:ioc:status"
ASSETS_NOW_KEY = "minisoc:assets:sync_now"
ASSETS_STATUS_KEY = "minisoc:assets:status"
IOC_RULE = "UC-42"
FEED_MAX_BYTES = 5 * 1024 * 1024
FEED_MAX_IOCS = 50_000
FEED_EVERY = timedelta(hours=24)


async def fetch_feed(feed: IocFeed) -> list[tuple[str, str]]:
    async with httpx.AsyncClient(timeout=30, follow_redirects=True) as client:
        response = await client.get(feed.url, headers={"User-Agent": "Mini-SOC"})
        response.raise_for_status()
        if len(response.content) > FEED_MAX_BYTES:
            raise ValueError("liste trop volumineuse (5 Mo au plus)")
    found, _ = ioc.parse_text(response.text, feed.type)
    return found[:FEED_MAX_IOCS]


class IocHunter:
    def __init__(self, sessions, redis, store, rules: Callable, exceptions, notify: Callable) -> None:
        self.sessions, self.redis, self.store = sessions, redis, store
        self.rules, self.exceptions, self.notify = rules, exceptions, notify

    async def run(self) -> None:
        while True:
            try:
                await self.once()
            except Exception as exc:  # noqa: BLE001
                log.error("chasse aux IOC en échec : %s", exc)
                await self.redis.set(IOC_STATUS_KEY, json.dumps({"at": _now().isoformat(), "error": str(exc)[:300]}))
            for _ in range(60):  # toutes les 10 minutes, ou tout de suite sur demande
                if await self.redis.getdel(IOC_NOW_KEY):
                    break
                await asyncio.sleep(10)

    async def refresh_feeds(self, force: bool = False) -> int:
        added = 0
        async with self.sessions() as session:
            feeds = (await session.scalars(select(IocFeed).where(IocFeed.enabled.is_(True)))).all()
            for feed in feeds:
                if not force and feed.fetched_at and _now() - feed.fetched_at < FEED_EVERY:
                    continue
                source = f"liste : {feed.name}"[:128]
                try:
                    found = await fetch_feed(feed)
                except Exception as exc:  # noqa: BLE001
                    feed.error, feed.fetched_at = str(exc)[:500], _now()
                    continue
                current = {
                    (i.type, i.value): i for i in (await session.scalars(select(Ioc).where(Ioc.source == source))).all()
                }
                wanted = set(found)
                stale = [i.id for key, i in current.items() if key not in wanted]
                if stale:
                    await session.execute(delete(Ioc).where(Ioc.id.in_(stale)))
                existing = {(t, v) for t, v in (await session.execute(select(Ioc.type, Ioc.value))).all()}
                for kind, value in wanted - existing:
                    session.add(
                        Ioc(
                            type=kind,
                            value=value,
                            source=source,
                            author="liste externe",
                            description=f"Liste externe « {feed.name} »",
                        )
                    )
                    added += 1
                feed.count, feed.error, feed.fetched_at = len(wanted), "", _now()
            await session.commit()
        return added

    async def once(self) -> dict:
        started = _now()
        await self.refresh_feeds()
        async with self.sessions() as session:
            cfg = await settings_store.load(session)
            active = (
                await session.scalars(select(Ioc).where(or_(Ioc.expires_at.is_(None), Ioc.expires_at > started)))
            ).all()
            new = [(i.id, i.type, i.value) for i in active if i.hunted_at is None]
            known = [(i.id, i.type, i.value) for i in active if i.hunted_at is not None]
            meta = {
                i.id: {"type": i.type, "value": i.value, "source": i.source, "description": i.description}
                for i in active
            }
        retention = int(cfg.get("events_retention_days") or 365)
        report = {"at": started.isoformat(), "iocs": len(active), "new": len(new), "alerts": 0, "error": ""}
        if new:  # nouvel IOC : tout l'historique conservé
            hits = await ioc.hunt(self.store, new, started - timedelta(days=retention), column="ts")
            report["alerts"] += await self.raise_hits(hits, meta, retro=True)
            await self._mark_hunted([i for i, _, _ in new], hits, started)
        cursor = await self.redis.get(IOC_CURSOR_KEY)
        since = datetime.fromisoformat(cursor) if cursor else started - timedelta(minutes=15)
        if known:  # IOC déjà chassés : événements reçus depuis le dernier passage (marge de 2 min)
            hits = await ioc.hunt(self.store, known, since - timedelta(minutes=2), column="ingest_ts")
            report["alerts"] += await self.raise_hits(hits, meta, retro=False)
            await self._mark_hunted([], hits, started)
        await self.redis.set(IOC_CURSOR_KEY, started.isoformat())
        await self.redis.set(IOC_STATUS_KEY, json.dumps(report))
        return report

    async def _mark_hunted(self, ids: list[int], hits: dict, now: datetime) -> None:
        async with self.sessions() as session:
            for row in (await session.scalars(select(Ioc).where(Ioc.id.in_(set(ids) | set(hits))))).all():
                if row.id in ids:
                    row.hunted_at = now
                hit = hits.get(row.id)
                if hit:
                    row.hits = (row.hits or 0) + len(hit.events)
                    last = max(_aware(e["ts"]) for e in hit.events)
                    row.last_hit = max(filter(None, [row.last_hit, last]))
            await session.commit()

    async def raise_hits(self, hits: dict, meta: dict, retro: bool) -> int:
        rule = self.rules().by_id.get(IOC_RULE)
        if rule is None or not hits:
            return 0
        created = 0
        for ioc_id, hit in hits.items():
            info = meta.get(ioc_id, {})
            by_entity: dict[str, list[dict]] = defaultdict(list)
            for event in hit.events:
                by_entity[event.get("host_name") or event.get("user_name") or event.get("source_ip") or ""].append(
                    event
                )
            for target, events in by_entity.items():
                values = {"threat.intel": f"{hit.type}:{hit.value}", "host.name": target}
                if self.exceptions.is_excepted(rule.id, values):
                    continue
                events.sort(key=lambda e: e["ts"])
                severity = rule.severity_level if not str(info.get("source", "")).startswith("liste") else 2
                det = Detection(
                    rule=rule,
                    entity_key=entity_key(rule.group_by, values),
                    severity=severity,
                    title=render_title(rule.title, values),
                    first_seen=_aware(events[0]["ts"]),
                    last_seen=_aware(events[-1]["ts"]),
                    count=len(events),
                    event_ids=[str(e["event_id"]) for e in events][-50:],
                    modules=sorted({e["module"] for e in events}),
                    details={
                        "ioc": info,
                        "retro": retro,
                        "sample": {
                            k: v
                            for k, v in {
                                "host.name": events[-1].get("host_name"),
                                "user.name": events[-1].get("user_name"),
                                "source.ip": events[-1].get("source_ip"),
                                "destination.ip": events[-1].get("destination_ip"),
                            }.items()
                            if v
                        },
                    },
                )
                async with self.sessions() as session:
                    alert, action = await upsert_alert(session, det)
                    if action == "created":
                        alert.notify_pending = (
                            True  # découverte rétroactive : à signaler même si l'événement est ancien
                        )
                        created += 1
                    await session.commit()
                if action in ("created", "escalated"):
                    self.notify()
        return created


class ArchiveJob:
    def __init__(self, sessions, store) -> None:
        self.sessions, self.store = sessions, store

    async def run(self) -> None:
        while True:
            try:
                async with self.sessions() as session:
                    cfg = await settings_store.load(session)
                if cfg.get("archive_enabled", True):
                    sealed = await archives.seal_pending(self.sessions, self.store)
                    if sealed:
                        log.info("archives scellées : %s", ", ".join(sealed))
            except Exception as exc:  # noqa: BLE001
                log.error("scellement des archives en échec : %s", exc)
            await asyncio.sleep(1800)


class AssetJob:
    def __init__(self, sessions, redis) -> None:
        self.sessions, self.redis = sessions, redis

    async def run(self) -> None:
        await asyncio.sleep(120)  # laisse NinjaOne et l'AD faire leur premier relevé
        while True:
            try:
                async with self.sessions() as session:
                    cfg = await settings_store.load(session)
                    report = await assets.sync(session, self.redis, cfg)
                await self.redis.set(ASSETS_STATUS_KEY, json.dumps({"at": _now().isoformat(), **report}))
            except Exception as exc:  # noqa: BLE001
                log.error("synchronisation de l'inventaire en échec : %s", exc)
            for _ in range(6 * 360):  # toutes les 6 heures, ou tout de suite sur demande
                if await self.redis.getdel(ASSETS_NOW_KEY):
                    break
                await asyncio.sleep(10)


class RiskJob:
    """Toutes les 5 minutes : score de risque par entité (UC-43) et chaînes d'attaque (UC-44, incident)."""

    def __init__(self, sessions, store, rules: Callable, raise_alert: Callable) -> None:
        self.sessions, self.store, self.rules, self.raise_alert = sessions, store, rules, raise_alert

    async def run(self) -> None:
        await asyncio.sleep(90)
        while True:
            try:
                await self.once()
            except Exception as exc:  # noqa: BLE001
                log.error("score de risque en échec : %s", exc)
            await asyncio.sleep(300)

    async def backfill_tactics(self, session, alerts: list) -> None:
        """Tactiques des alertes d'outils créées avant ce calcul : relues dans les événements d'origine."""
        from minisoc.risk import tactics_from_raw

        todo = [a for a in alerts if "harfanglab" in (a.modules or []) and "tactics" not in (a.details or {})]
        for alert in todo[:300]:
            tactics: set[str] = set()
            try:
                for row in await self.store.by_ids(alert.event_ids, limit=5):
                    tactics.update(tactics_from_raw(row.get("raw", "")))
            except Exception:  # noqa: BLE001 - ClickHouse indisponible : on réessaiera
                return
            alert.details = {**(alert.details or {}), "tactics": sorted(tactics)}
        await session.commit()

    async def once(self) -> dict:
        from minisoc.models import Alert, Incident, IncidentEntry
        from minisoc.risk import CHAIN_RULE, CHAIN_WINDOW, RISK_RULE, RISK_WINDOW, compute_risk, find_chains

        now = _now()
        rules = self.rules()
        mitre = {r.id: r.mitre for r in rules.rules}
        async with self.sessions() as session:
            cfg = await settings_store.load(session)
            alerts = list((await session.scalars(select(Alert).where(Alert.last_seen >= now - RISK_WINDOW))).all())
            await self.backfill_tactics(session, alerts)
            index = await assets.INDEX.ensure(session)

        def criticality(kind: str, name: str) -> str | None:
            info = index.host(name) if kind == "host" else index.account(name)
            return info.criticality if info else None

        threshold = int(cfg.get("risk_threshold") or 60)
        report = {"entities": 0, "risk_alerts": 0, "chains": 0, "incidents": 0}
        risk_rule = rules.by_id.get(RISK_RULE)
        risks = compute_risk(alerts, mitre, criticality, now)
        for risk in risks.values():
            report["entities"] += 1
            if risk_rule is None or risk.score < threshold:
                continue
            field_name = "host.name" if risk.kind == "host" else "user.name"
            values = {field_name: risk.name, "value": round(risk.score)}
            contributors = sorted(risk.contributions.values(), key=lambda c: -c["points"])
            seen = [_aware(c["last_seen"]) for c in contributors]
            det = Detection(
                rule=risk_rule, entity_key=f"{field_name}={risk.name}",
                severity=4 if risk.score >= 2 * threshold else risk_rule.severity_level,
                title=render_title(risk_rule.title, values), first_seen=min(seen), last_seen=max(seen),
                count=len(contributors), metric=round(risk.score), accumulate=False,
                details={"risk": risk.to_dict(), "sample": {field_name: risk.name}},
            )
            _, action = await self.raise_alert(det)
            report["risk_alerts"] += int(action == "created")
        report["risk_resolved"] = await self._resolve_lowered(RISK_RULE, threshold, risks)
        chain_rule = rules.by_id.get(CHAIN_RULE)
        if chain_rule is not None:
            for chain in find_chains(alerts, mitre, now):
                field_name = "host.name" if chain.kind == "host" else "user.name"
                values = {field_name: chain.name, "value": len(chain.tactics)}
                det = Detection(
                    rule=chain_rule, entity_key=f"{field_name}={chain.name}", severity=chain_rule.severity_level,
                    title=render_title(chain_rule.title, values), first_seen=_aware(chain.steps[0]["ts"]),
                    last_seen=now, count=len(chain.steps), metric=len(chain.tactics), accumulate=False,
                    details={"chain": {"tactics": chain.tactics, "steps": chain.steps,
                                       "window_hours": int(CHAIN_WINDOW.total_seconds() // 3600)},
                             "sample": {field_name: chain.name}},
                )
                alert, action = await self.raise_alert(det)
                report["chains"] += 1
                if action == "created" and cfg.get("chain_auto_incident", True):
                    await self._incident(Incident, IncidentEntry, Alert, chain, alert)
                    report["incidents"] += 1
        return report

    async def _resolve_lowered(self, rule_id: str, threshold: int, risks: dict) -> int:
        """Alerte de risque dont le score est repassé sous le seuil : clôturée, avec une trace (le score dépend de
        détections qui ont été traitées, requalifiées ou qui ont vieilli)."""
        from minisoc.models import OPEN_STATUSES, Alert, AlertHistory
        from minisoc.risk import _norm

        resolved = 0
        async with self.sessions() as session:
            rows = (await session.scalars(select(Alert).where(
                Alert.rule_id == rule_id, Alert.status.in_(OPEN_STATUSES)).with_for_update())).all()
            for alert in rows:
                field_name, _, name = alert.entity_key.partition("=")
                kind = "host" if field_name == "host.name" else "user"
                risk = risks.get((kind, _norm(kind, name)))
                score = round(risk.score) if risk else 0
                if score >= threshold:
                    continue
                alert.status, alert.notify_pending = "resolved", False
                session.add(AlertHistory(alert_id=alert.id, actor="système", action="status", detail="resolved"))
                session.add(AlertHistory(alert_id=alert.id, actor="système", action="comment",
                                         detail=f"Score de risque redescendu à {score} (seuil {threshold}) : "
                                         "clôture automatique."))
                resolved += 1
            await session.commit()
        return resolved

    async def _incident(self, Incident, IncidentEntry, Alert, chain, chain_alert) -> None:  # noqa: N803
        """Incident ouvert automatiquement pour une chaîne d'attaque, avec les alertes de la chaîne rattachées."""
        from minisoc.models import AlertHistory

        actor = "système"
        async with self.sessions() as session:
            ids = [chain_alert.id, *chain.alert_ids]
            linked = (await session.scalars(select(Alert).where(Alert.id.in_(ids)))).all()
            existing = next((a.incident_id for a in linked if a.incident_id), None)
            if existing:  # une étape est déjà dans un incident : la chaîne le rejoint
                incident = await session.get(Incident, existing)
            else:
                steps = "\n".join(f"- {s['ts'][:16].replace('T', ' ')} : {s['title']} ({', '.join(s['tactics'])})"
                                  for s in chain.steps)
                incident = Incident(
                    title=f"Chaîne d'attaque sur {chain.name}"[:300],
                    description=(f"Ouvert automatiquement : {len(chain.tactics)} tactiques en 24 heures "
                                 f"({', '.join(chain.tactics)}).\n\n{steps}"),
                    category="intrusion", severity=4, status="open", created_by=actor,
                )
                session.add(incident)
                await session.flush()
                session.add(IncidentEntry(incident_id=incident.id, actor=actor, kind="created",
                                          detail="Incident ouvert automatiquement (chaîne d'attaque, règle UC-44)"))
            for alert in linked:
                if alert.incident_id:
                    continue
                alert.incident_id = incident.id
                session.add(AlertHistory(alert_id=alert.id, actor=actor, action="comment",
                                         detail=f"Rattachée à l'incident n° {incident.id} : {incident.title}"))
                session.add(IncidentEntry(incident_id=incident.id, actor=actor, kind="alert_added",
                                          detail=f"Alerte n° {alert.id} : {alert.title}"))
            await session.commit()
            log.warning("chaîne d'attaque sur %s : incident n° %s", chain.name, incident.id)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value) -> datetime:
    if isinstance(value, str):
        value = datetime.fromisoformat(value)
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
