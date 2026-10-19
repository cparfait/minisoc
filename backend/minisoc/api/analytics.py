"""Statistiques (page Statistiques) : chargement des données de la période, calculs dans `minisoc.analytics`."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defer

from minisoc import analytics, hostdisk
from minisoc.api.deps import ANY_USER, get_db
from minisoc.models import OPEN_STATUSES, Alert, AlertHistory, AuditLog, Block, Incident, IncidentEntry, User
from minisoc.risk import BUILTIN_ACCOUNTS
from minisoc.settings_store import store as settings_store

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/analytics", tags=["analytics"])

_PERIOD = "ts >= {s:DateTime64(3)} AND ts < {e:DateTime64(3)}"
_LOCAL = "toTimeZone(ts, {tz:String})"
# Connexion d'une personne : ni compte machine, ni compte système, ni connexion sans compte
_NAMED = ("user_name != '' AND NOT endsWith(user_name, '$') AND lower(user_name) NOT IN {builtin:Array(String)} "
          "AND NOT match(lower(user_name), '^(dwm|umfd)-')")


def _naive(value: datetime) -> datetime:
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def expected_silences(cfg: dict, absence_rules) -> dict[str, timedelta]:
    """Délai de silence toléré par source : celui de l'intégration, sinon de la règle d'absence (comme
    `stats.sources_status`)."""
    from minisoc.integrations import configured_missing, disabled_modules, monitored_sources

    missing = configured_missing(cfg)
    expected = {m: d for m, d in monitored_sources(cfg).items() if m not in missing}
    for rule in absence_rules:
        expected.update(rule.sources)
    return {m: d for m, d in expected.items() if m not in disabled_modules(cfg)}


async def events_data(store, since: datetime, until: datetime, gran: str, tz: str, expected: dict[str, timedelta],
                      business_days: list[int], start: int, end: int) -> dict:
    """Agrégats ClickHouse : volumes et silences par source, authentification par jour × heure."""
    previous_since = since - (until - since)
    params = {"s": _naive(since), "e": _naive(until), "ps": _naive(previous_since), "tz": tz,
              "mods": list(expected), "thr": [max(1, int(d.total_seconds() // 60)) for d in expected.values()],
              "builtin": sorted(BUILTIN_ACCOUNTS), "days": business_days, "start": start, "end": end}
    bucket = "toDate(ts, {tz:String})" if gran == "day" else "toMonday(toDate(ts, {tz:String}))"
    volume = await store.query(
        f"SELECT module, {bucket} AS b, count() AS n FROM events WHERE {_PERIOD} GROUP BY module, b", params)
    previous = await store.query(
        "SELECT module, count() AS n FROM events WHERE ts >= {ps:DateTime64(3)} AND ts < {s:DateTime64(3)} "
        "GROUP BY module", params)
    seen = await store.query(
        f"SELECT module, min(ts) AS first, max(ts) AS last FROM events WHERE {_PERIOD} GROUP BY module", params)
    gaps = []
    if expected:
        # Tranches de 5 minutes ayant reçu des événements ; un écart avec la précédente au moins égal au délai
        # toléré de la source est un silence
        gaps = await store.query(
            "SELECT module, gap_start, gap_end FROM ("
            " SELECT module, b AS gap_end, lagInFrame(b) OVER (PARTITION BY module ORDER BY b ASC"
            "  ROWS BETWEEN 1 PRECEDING AND CURRENT ROW) AS gap_start FROM ("
            "  SELECT module, toStartOfInterval(toDateTime(ts), INTERVAL 5 MINUTE) AS b FROM events"
            f"  WHERE {_PERIOD} AND has({{mods:Array(String)}}, module) GROUP BY module, b))"
            " WHERE toUnixTimestamp(gap_start) > 0 AND dateDiff('minute', gap_start, gap_end) - 5 >= "
            "  arrayElement({thr:Array(UInt32)}, indexOf({mods:Array(String)}, module))"
            " ORDER BY module, gap_start LIMIT 5000", params)
    auth = await store.query(
        f"SELECT toDayOfWeek({_LOCAL}) AS d, toHour({_LOCAL}) AS h, countIf(outcome = 'failure') AS failures, "
        f"countIf(outcome = 'success' AND {_NAMED}) AS successes FROM events "
        f"WHERE {_PERIOD} AND category = 'authentication' GROUP BY d, h", params)
    offhours = await store.query(
        "SELECT user_name AS user, count() AS n, uniqExact(source_ip) AS ips, uniqExact(host_name) AS hosts, "
        "groupUniqArray(3)(module) AS modules, max(ts) AS last FROM events "
        f"WHERE {_PERIOD} AND category = 'authentication' AND outcome = 'success' AND {_NAMED} "
        f"AND (NOT has({{days:Array(UInt8)}}, toDayOfWeek({_LOCAL})) OR toHour({_LOCAL}) < {{start:UInt8}} "
        f"OR toHour({_LOCAL}) >= {{end:UInt8}}) GROUP BY user ORDER BY n DESC LIMIT 10", params)
    return {"volume": volume, "previous": previous, "seen": seen, "gaps": gaps, "auth": auth,
            "offhours": [{**r, "last": analytics.aware(r["last"]).isoformat()} for r in offhours]}


@router.get("")
async def get_analytics(
    request: Request,
    since: datetime | None = Query(None, description="début de la période (ISO 8601), 30 jours par défaut"),
    until: datetime | None = Query(None, description="fin de la période (ISO 8601), maintenant par défaut"),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(ANY_USER),
):
    """Volumes d'alertes, qualité des détections, délais de traitement, MITRE et cibles, santé des sources, carte
    jour × heure, corrélation et réponse, avec leur méthode de calcul. Période : alertes créées entre `since`
    (inclus) et `until` (exclu), 366 jours au plus."""
    now = datetime.now(timezone.utc)
    until = analytics.aware(until) if until else now
    since = analytics.aware(since) if since else until - timedelta(days=30)
    if since >= until:
        raise HTTPException(422, "Le début de la période doit précéder sa fin")
    if until - since > timedelta(days=analytics.MAX_DAYS):
        raise HTTPException(422, f"Période limitée à {analytics.MAX_DAYS} jours")
    previous_since = since - (until - since)

    in_period = (Alert.created_at >= since, Alert.created_at < until)
    alerts = list((await db.scalars(select(Alert).options(defer(Alert.event_ids)).where(*in_period))).all())
    previous_total = await db.scalar(select(func.count()).select_from(Alert).where(
        Alert.created_at >= previous_since, Alert.created_at < since)) or 0
    history = list((await db.scalars(
        select(AlertHistory).join(Alert, Alert.id == AlertHistory.alert_id)
        .where(*in_period, AlertHistory.action == "status")
    )).all())
    open_now = [(s, c) for s, c in (await db.execute(
        select(Alert.severity, Alert.created_at).where(Alert.status.in_(OPEN_STATUSES)))).all()]
    incidents = list((await db.scalars(select(Incident).where(or_(
        (Incident.created_at >= since) & (Incident.created_at < until),
        (Incident.closed_at >= since) & (Incident.closed_at < until),
    )))).all())
    entries = list((await db.scalars(select(IncidentEntry).where(
        IncidentEntry.incident_id.in_([i.id for i in incidents]), IncidentEntry.kind == "status"
    ))).all()) if incidents else []
    blocks = list((await db.scalars(select(Block).where(Block.created_at >= since, Block.created_at < until))).all())
    audit_rows = (await db.scalars(select(AuditLog).where(
        AuditLog.ts >= since, AuditLog.ts < until, AuditLog.action.in_(("endpoint_isolate", "endpoint_release"))
    ))).all()
    isolations = [{"action": a.action, "ok": bool((a.detail or {}).get("ok")),
                   "host": str((a.detail or {}).get("host") or "")} for a in audit_rows]
    cfg = await settings_store.load(db)

    state = request.app.state
    tz_name = state.settings.timezone
    tz = ZoneInfo(tz_name)
    rule_mitre = {r.id: list(r.mitre) for r in state.rules.rules}
    absence_ids = {r.id for r in state.rules.absence_rules}
    expected = expected_silences(cfg, state.rules.absence_rules)
    business_days = sorted({int(d) for d in cfg.get("business_days") or ["1", "2", "3", "4", "5"] if str(d).isdigit()})
    start, end = int(cfg.get("business_hours_start", 8)), int(cfg.get("business_hours_end", 18))
    retention = int(cfg.get("events_retention_days") or 365)
    try:
        events = await events_data(state.store, since, until, analytics.granularity(since, until), tz_name, expected,
                                   business_days, start, end)
        events_error = ""
    except Exception as exc:  # noqa: BLE001 - les statistiques d'alertes restent utiles sans la base des événements
        log.warning("Statistiques : base des événements indisponible (%s)", exc)
        events = {"volume": [], "previous": [], "seen": [], "gaps": [], "auth": [], "offhours": []}
        events_error = f"base des événements indisponible ou trop lente ({type(exc).__name__})"

    closings = analytics.closing_entries(alerts, history)
    sources = analytics.source_health(
        events["volume"], events["previous"], events["gaps"], events["seen"], {} if events_error else expected,
        since, until, now, tz, retention, sum(1 for a in alerts if a.rule_id in absence_ids))
    return {
        "period": {"since": since.isoformat(), "until": until.isoformat(),
                   "previous_since": previous_since.isoformat(), "timezone": tz_name},
        "events_error": events_error,
        "volumes": analytics.volumes(alerts, previous_total, since, until, tz),
        "quality": analytics.quality(alerts, closings),
        "delays": analytics.delays(alerts, closings, open_now, incidents, entries, since, until, tz, now),
        "mitre": analytics.mitre_targets(alerts, rule_mitre),
        "sources": sources,
        "disks": await hostdisk.load_status(state.redis),  # espace des disques de la VM, dernier relevé
        "heatmap": analytics.heatmap(alerts, events["auth"], events["offhours"], set(business_days), start, end, tz),
        "correlation": analytics.correlation(alerts, incidents, blocks, isolations, since, until),
    }
