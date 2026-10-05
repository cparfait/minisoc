"""Indicateurs partagés par l'API, l'écran mural, le résumé quotidien et l'assistant IA."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import redis.asyncio as aioredis

from minisoc import bus
from minisoc.events_store import EventStore
from minisoc.rules.model import Rule


def utc_iso(value: datetime) -> str:
    """Date ClickHouse (UTC, sans fuseau) → ISO 8601 avec fuseau explicite pour le navigateur."""
    return (value if value.tzinfo else value.replace(tzinfo=timezone.utc)).isoformat()


async def auth_activity(store: EventStore, top: int) -> dict:
    """IP les plus actives en échec d'authentification et échecs par heure, sur 24 h."""
    attackers = await store.query(
        "SELECT source_ip AS ip, count() AS failures, uniqExact(user_name) AS users, "
        "groupUniqArray(5)(user_name) AS sample_users, any(source_country) AS country, any(source_as) AS asn, "
        "anyIf(intel, intel != '') AS intel FROM events "
        "WHERE ts >= now64(3) - INTERVAL 24 HOUR AND category = 'authentication' AND outcome = 'failure' "
        "AND source_ip != '' GROUP BY source_ip ORDER BY failures DESC LIMIT {top:UInt32}",
        {"top": top},
    )
    hourly = await store.query(
        "SELECT toStartOfHour(ts) AS hour, count() AS count FROM events "
        "WHERE ts >= now64(3) - INTERVAL 24 HOUR AND category = 'authentication' AND outcome = 'failure' "
        "GROUP BY hour ORDER BY hour"
    )
    countries = await store.query(
        "SELECT source_country AS country, count() AS failures, uniqExact(source_ip) AS ips FROM events "
        "WHERE ts >= now64(3) - INTERVAL 24 HOUR AND category = 'authentication' AND outcome = 'failure' "
        "AND source_country != '' GROUP BY country ORDER BY failures DESC LIMIT 12"
    )
    return {
        "top_attackers": attackers,
        "failures_by_country": countries,
        "auth_failures_hourly": [{"hour": utc_iso(r["hour"]), "count": r["count"]} for r in hourly],
    }


async def sources_status(redis: aioredis.Redis, absence_rules: list[Rule]) -> list[dict]:
    last_seen = await bus.sources_last_seen(redis)
    expected: dict[str, timedelta] = {}
    for rule in absence_rules:
        expected.update(rule.sources)
    now = datetime.now(timezone.utc)
    items = []
    for module in sorted(set(last_seen) | set(expected)):
        seen = last_seen.get(module)
        delay = expected.get(module)
        if seen is None:
            status = "unknown"
        elif delay is not None and now - seen > delay:
            status = "silent"
        else:
            status = "ok"
        items.append({
            "module": module,
            "last_seen": seen.isoformat() if seen else None,
            "max_silence_minutes": int(delay.total_seconds() // 60) if delay else None,
            "monitored": delay is not None,
            "status": status,
        })
    return items
