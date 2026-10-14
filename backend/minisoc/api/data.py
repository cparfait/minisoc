"""Recherche d'événements, statistiques du tableau de bord, état des sources, règles."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc import stats
from minisoc.api.alerts import _event
from minisoc.api.deps import ANY_USER, get_db
from minisoc.ecs import SEVERITY_NAMES, severity_name
from minisoc.frameworks import coverage, describe
from minisoc.models import OPEN_STATUSES, Alert, User
from minisoc.resolver import annotate
from minisoc.settings_store import store as settings_store
from minisoc.stats import auth_activity

router = APIRouter(prefix="/api", tags=["data"])

_LIST_COLUMNS = (
    "ts, module, kind, category, action, outcome, reason, severity, source_ip, source_port, source_country, "
    "source_as, intel, destination_ip, "
    "destination_port, user_name, host_name, host_ip, network_service, rule_name, threat_name, file_path, "
    "observer, reference, message, substring(raw, 1, 2000) AS raw, toString(event_id) AS event_id"
)


@router.get("/events")
async def search_events(
    request: Request,
    q: str | None = Query(None, max_length=200),
    module: str | None = Query(None, max_length=64),
    category: str | None = Query(None, max_length=64),
    outcome: str | None = Query(None, max_length=16),
    ip: str | None = Query(None, max_length=64),
    user: str | None = Query(None, max_length=128),
    host: str | None = Query(None, max_length=128),
    since: datetime | None = None,
    until: datetime | None = None,
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0, le=10_000),
    _: User = Depends(ANY_USER),
):
    now = datetime.now(timezone.utc)
    params: dict = {
        "since": since or now - timedelta(hours=24),
        "until": until or now + timedelta(minutes=5),
        "limit": limit,
        "offset": offset,
    }
    where = ["ts >= {since:DateTime64(3)}", "ts <= {until:DateTime64(3)}"]
    for key, column, value in (("module", "module", module), ("category", "category", category),
                               ("outcome", "outcome", outcome)):
        if value:
            where.append(f"{column} = {{{key}:String}}")
            params[key] = value
    if ip:
        where.append("(source_ip = {ip:String} OR destination_ip = {ip:String} OR host_ip = {ip:String})")
        params["ip"] = ip
    if user:
        where.append("user_name = {user:String}")
        params["user"] = user
    if host:
        where.append("host_name = {host:String}")
        params["host"] = host
    if q:
        where.append(
            "(positionCaseInsensitiveUTF8(message, {q:String}) > 0"
            " OR positionCaseInsensitiveUTF8(raw, {q:String}) > 0)"
        )
        params["q"] = q
    sql = (
        f"SELECT {_LIST_COLUMNS} FROM events WHERE {' AND '.join(where)} "
        "ORDER BY ts DESC LIMIT {limit:UInt32} OFFSET {offset:UInt32}"
    )
    rows = await request.app.state.store.query(sql, params)
    return {"items": [_event(r) for r in rows]}


@router.get("/stats/overview")
async def overview(request: Request, db: AsyncSession = Depends(get_db), _: User = Depends(ANY_USER)):
    state = request.app.state
    now = datetime.now(timezone.utc)
    open_by_severity = await count_open_by_severity(db)
    new_24h = await count_new_24h(db)

    tz = state.settings.timezone
    trend_rows = await db.execute(
        text(
            "SELECT to_char(date_trunc('day', created_at AT TIME ZONE :tz), 'YYYY-MM-DD') AS day, severity, count(*) "
            "FROM alerts WHERE created_at >= :since GROUP BY 1, 2 ORDER BY 1"
        ),
        {"tz": tz, "since": now - timedelta(days=30)},
    )
    trend: dict[str, dict[str, int]] = {}
    for day, severity, count in trend_rows.all():
        trend.setdefault(day, {name: 0 for name in SEVERITY_NAMES})[severity_name(severity)] = count

    top_rules = await db.execute(
        select(Alert.rule_id, Alert.rule_name, func.count())
        .where(Alert.status.in_(OPEN_STATUSES))
        .group_by(Alert.rule_id, Alert.rule_name)
        .order_by(func.count().desc())
        .limit(8)
    )

    cfg_dns = str((await settings_store.load(db)).get("dns_server") or "")
    try:
        ch = await auth_activity(state.store, top=10)
        await annotate(ch["top_attackers"], cfg_dns)
        ch["events_by_module"] = await state.store.query(
            "SELECT module, count() AS count FROM events WHERE ts >= now64(3) - INTERVAL 24 HOUR "
            "GROUP BY module ORDER BY count DESC"
        )
    except Exception:  # noqa: BLE001 - le tableau de bord reste utilisable sans ClickHouse
        ch = {"top_attackers": [], "auth_failures_hourly": [], "failures_by_country": [], "events_by_module": [],
              "clickhouse_error": True}

    return {
        "open_by_severity": open_by_severity,
        "new_24h": new_24h,
        "trend": [{"day": day, **counts} for day, counts in sorted(trend.items())],
        "top_rules": [{"rule_id": r, "rule_name": n, "count": c} for r, n, c in top_rules.all()],
        **ch,
        "sources": await sources_status(state),
    }


@router.get("/stats/vpn")
async def vpn_stats(
    request: Request,
    recent: int = Query(12, ge=1, le=50),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(ANY_USER),
):
    """Accès distants (VPN, portail VPN, administration du pare-feu) sur 24 h, pour le tableau de bord."""
    from minisoc.settings_store import store as settings_store
    from minisoc.stats import vpn_activity

    cfg = await settings_store.load(db)
    try:
        result = await vpn_activity(request.app.state.store, recent=recent,
                                    home_countries=cfg.get("home_countries") or ["FR"])
        await annotate(result["recent"], str(cfg.get("dns_server") or ""))
        return result
    except Exception:  # noqa: BLE001 - le tableau de bord reste utilisable sans ClickHouse
        return {"summary": {}, "services": [], "targeted": [], "recent": [], "clickhouse_error": True}


async def count_open_by_severity(db: AsyncSession) -> dict[str, int]:
    rows = await db.execute(
        select(Alert.severity, func.count()).where(Alert.status.in_(OPEN_STATUSES)).group_by(Alert.severity)
    )
    counts = {name: 0 for name in SEVERITY_NAMES}
    for severity, count in rows.all():
        counts[severity_name(severity)] = count
    return counts


async def count_new_24h(db: AsyncSession) -> int:
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    return await db.scalar(select(func.count()).where(Alert.created_at >= since)) or 0


@router.get("/sources")
async def sources(request: Request, _: User = Depends(ANY_USER)):
    return {"items": await sources_status(request.app.state)}


async def sources_status(state) -> list[dict]:
    return await stats.sources_status(state.redis, state.rules.absence_rules)


@router.get("/rules")
async def rules(request: Request, _: User = Depends(ANY_USER)):
    out = []
    for r in request.app.state.rules.rules:
        cond = r.condition
        out.append({
            "id": r.id,
            "name": r.name,
            "type": r.type,
            "severity": r.severity,
            "description": r.description,
            "enabled": r.enabled,
            "window": str(r.window) if r.type in ("threshold", "sequence") else None,
            "condition": f"{cond.function}({cond.field}) {cond.op} {cond.value}" if cond else None,
            "group_by": r.group_by,
            "file": r.path,
            "mitre": [describe(t) for t in r.mitre],
        })
    return {"items": out}


@router.get("/rules/coverage")
async def rules_coverage(request: Request, _: User = Depends(ANY_USER)):
    """Couverture MITRE ATT&CK des règles actives, par tactique."""
    active = {r.id: r.mitre for r in request.app.state.rules.rules if r.enabled and r.mitre}
    return {"tactics": coverage(active)}


@router.get("/veille")
async def veille(request: Request, _: User = Depends(ANY_USER)):
    """Catalogue CISA KEV (dernières entrées) et publications récentes du CERT-FR."""
    return await threat_feeds_summary(request.app.state.redis)


@router.get("/ninjaone/posture")
async def ninjaone_posture(request: Request, _: User = Depends(ANY_USER)):
    """Synthèse de sécurité du parc (dernier relevé NinjaOne) : postes les plus exposés."""
    import json

    from minisoc.connectors.ninjaone import SUMMARY_KEY

    raw = await request.app.state.redis.get(SUMMARY_KEY)
    return json.loads(raw) if raw else {"devices": 0, "exposed": [], "at": None}


@router.get("/cyberwatch/summary")
async def cyberwatch_summary(request: Request, _: User = Depends(ANY_USER)):
    """Synthèse des vulnérabilités (dernier relevé Cyberwatch) : actifs les plus exposés."""
    import json

    from minisoc.connectors.cyberwatch import SUMMARY_KEY

    raw = await request.app.state.redis.get(SUMMARY_KEY)
    return json.loads(raw) if raw else {"assets": 0, "exposed": [], "at": None}


@router.get("/cyberwatch/hosts")
async def cyberwatch_hosts(
    request: Request,
    names: str = Query("", max_length=10000, description="machines séparées par des virgules"),
    _: User = Depends(ANY_USER),
):
    """Correctifs en attente par machine, d'après le dernier relevé Cyberwatch : quoi mettre à jour, et pourquoi."""
    from minisoc.connectors import cyberwatch

    states = cyberwatch.load_states(await request.app.state.redis.hgetall(cyberwatch.STATE_KEY))
    return {"hosts": cyberwatch.hosts_patches(states, [n for n in names.split(",") if n.strip()][:200])}


async def threat_feeds_summary(redis, kev_limit: int = 40) -> dict:
    import json

    from minisoc.threat_feeds import CERTFR_KEY, KEV_KEY, KEV_META

    meta = await redis.hgetall(KEV_META)
    entries = [json.loads(v) for v in (await redis.hvals(KEV_KEY))]
    entries.sort(key=lambda e: e.get("added", ""), reverse=True)
    raw = await redis.get(CERTFR_KEY)
    return {
        "kev": {
            "updated": meta.get("updated"),
            "count": int(meta.get("count") or len(entries)),
            "ransomware": sum(1 for e in entries if e.get("ransomware")),
            "recent": entries[:kev_limit],
        },
        "certfr": json.loads(raw) if raw else [],
    }
