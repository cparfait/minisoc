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
        # 127.0.0.1 : adresse masquée par un relais interne (portail VPN Sophos), sans valeur de classement
        "AND source_ip != '' AND NOT startsWith(source_ip, '127.') "
        "GROUP BY source_ip ORDER BY failures DESC LIMIT {top:UInt32}",
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


VPN_SERVICES = ("ssl_vpn", "ipsec", "l2tp", "user_portal", "admin_console")
_VPN_WHERE = (
    "module = 'sophos_xgs' AND category = 'authentication' AND network_service IN {services:Array(String)} "
    "AND ts >= now64(3) - INTERVAL 24 HOUR"
)


# Connexion réussie « à signaler » : depuis une adresse publique hors des pays habituels (Paramètres › Détection)
_ABROAD = (
    # Pays connu seulement : sans base GeoIP (ou adresse absente de la base), le pays est vide et rien ne permet de
    # dire que la connexion vient de l'étranger
    "outcome = 'success' AND source_ip != '' AND source_country != '' AND source_country NOT IN {home:Array(String)} "
    "AND NOT (isIPAddressInRange(source_ip, '10.0.0.0/8') OR isIPAddressInRange(source_ip, '172.16.0.0/12') "
    "OR isIPAddressInRange(source_ip, '192.168.0.0/16') OR isIPAddressInRange(source_ip, '127.0.0.0/8'))"
)


async def vpn_activity(store: EventStore, recent: int = 12, home_countries: list[str] | None = None) -> dict:
    """Accès distants du pare-feu sur 24 h : synthèse, par service, et tentatives à regarder en priorité (échecs et
    connexions réussies depuis l'étranger ; les connexions réussies depuis la France ou le réseau interne sont
    seulement comptées)."""
    home = [c.upper() for c in (home_countries or ["FR"])]
    params = {"services": list(VPN_SERVICES), "recent": recent, "home": home}
    summary = (await store.query(
        "SELECT countIf(outcome = 'failure') AS failures, countIf(outcome = 'success') AS successes, "
        "uniqExactIf(user_name, outcome = 'failure') AS users_failed, "
        "uniqExactIf(source_ip, outcome = 'failure' AND NOT startsWith(source_ip, '127.')) AS ips_failed, "
        "countIf(outcome = 'failure' AND startsWith(source_ip, '127.')) AS masked, "
        f"countIf({_ABROAD}) AS successes_abroad "
        f"FROM events WHERE {_VPN_WHERE}",
        params,
    ) or [{}])[0]
    services = await store.query(
        "SELECT network_service AS service, countIf(outcome = 'failure') AS failures, "
        "countIf(outcome = 'success') AS successes, uniqExactIf(user_name, outcome = 'failure') AS users_failed "
        f"FROM events WHERE {_VPN_WHERE} GROUP BY service ORDER BY failures DESC",
        params,
    )
    last = await store.query(
        "SELECT ts, network_service AS service, user_name AS user, source_ip AS ip, source_country AS country, "
        f"outcome, reason FROM events WHERE {_VPN_WHERE} AND (outcome = 'failure' OR ({_ABROAD})) "
        "ORDER BY ts DESC LIMIT {recent:UInt32}",
        params,
    )
    targeted = await store.query(
        "SELECT user_name AS user, count() AS failures FROM events "
        f"WHERE {_VPN_WHERE} AND outcome = 'failure' AND user_name != '' "
        "GROUP BY user ORDER BY failures DESC LIMIT 8",
        params,
    )
    return {
        "summary": {k: int(v or 0) for k, v in summary.items()},
        "services": services,
        "targeted": targeted,
        "recent": [{**r, "ts": utc_iso(r["ts"])} for r in last],
        "home_countries": home,
    }


_M365_WHERE = "module = 'm365' AND ts >= now64(3) - INTERVAL 24 HOUR"
_M365_AUTH = f"{_M365_WHERE} AND category = 'authentication'"
# Changements sensibles du tenant (rôles, MFA, consentements, mots de passe, transferts de messagerie)
M365_CHANGES = ("role_member_added", "mfa_disabled", "app_consent", "password_reset", "mail_forwarding_rule")


async def m365_activity(store: EventStore, recent: int = 10, home_countries: list[str] | None = None) -> dict:
    """Comptes Microsoft 365 / Entra ID sur 24 h (journal d'audit unifié) : connexions, échecs par motif, comptes
    visés, connexions réussies depuis l'étranger et changements sensibles, pour le tableau de bord."""
    home = [c.upper() for c in (home_countries or ["FR"])]
    params = {"home": home, "recent": recent, "changes": list(M365_CHANGES)}
    summary = (await store.query(
        "SELECT countIf(outcome = 'failure') AS failures, countIf(outcome = 'success') AS successes, "
        "uniqExactIf(user_name, outcome = 'success') AS users_ok, "
        "uniqExactIf(user_name, outcome = 'failure') AS users_failed, "
        "uniqExactIf(source_ip, outcome = 'failure') AS ips_failed, "
        "countIf(reason = 'mfa_failed') AS mfa_failed, "
        f"countIf({_ABROAD}) AS successes_abroad, "
        f"uniqExactIf(user_name, {_ABROAD}) AS users_abroad "
        f"FROM events WHERE {_M365_AUTH}",
        params,
    ) or [{}])[0]
    # Par motif : nombre d'échecs et comptes distincts concernés (un échec sans nom de compte n'en ajoute pas)
    reasons = await store.query(
        "SELECT reason, count() AS n, uniqExactIf(user_name, user_name != '') AS users FROM events "
        f"WHERE {_M365_AUTH} AND outcome = 'failure' GROUP BY reason ORDER BY n DESC LIMIT 6",
        params,
    )
    targeted = await store.query(
        "SELECT user_name AS user, count() AS failures, uniqExact(source_country) AS countries FROM events "
        f"WHERE {_M365_AUTH} AND outcome = 'failure' AND user_name != '' "
        "GROUP BY user ORDER BY failures DESC LIMIT 6",
        params,
    )
    last = await store.query(
        "SELECT ts, user_name AS user, source_ip AS ip, source_country AS country, outcome, reason FROM events "
        f"WHERE {_M365_AUTH} AND (outcome = 'failure' OR ({_ABROAD})) ORDER BY ts DESC LIMIT {{recent:UInt32}}",
        params,
    )
    changes = await store.query(
        "SELECT ts, action, user_name AS user, rule_name AS what, threat_name AS detail FROM events "
        f"WHERE {_M365_WHERE} AND action IN {{changes:Array(String)}} ORDER BY ts DESC LIMIT 6",
        params,
    )
    return {
        "summary": {k: int(v or 0) for k, v in summary.items()},
        "reasons": reasons,
        "targeted": targeted,
        "recent": [{**r, "ts": utc_iso(r["ts"])} for r in last],
        "changes": [{**r, "ts": utc_iso(r["ts"])} for r in changes],
        "home_countries": home,
    }


async def sources_status(redis: aioredis.Redis, absence_rules: list[Rule], cfg: dict | None = None) -> list[dict]:
    """État de chaque source. Délai de silence : celui de l'intégration (Intégrations, ex. 30 min pour le pare-feu),
    sinon celui de la règle UC-16 — le même calcul que la fiche de l'intégration et que l'alerte « source
    silencieuse ». Les intégrations désactivées n'apparaissent pas."""
    from minisoc.integrations import configured_missing, disabled_modules, monitored_sources

    last_seen = await bus.sources_last_seen(redis)
    expected: dict[str, timedelta] = {}
    if cfg is not None:  # intégration pas encore configurée : « à configurer » sur sa fiche, pas silencieuse
        missing = configured_missing(cfg)
        expected = {m: d for m, d in monitored_sources(cfg).items() if m not in missing}
    for rule in absence_rules:
        expected.update(rule.sources)
    disabled = disabled_modules(cfg) if cfg is not None else set()
    now = datetime.now(timezone.utc)
    items = []
    for module in sorted((set(last_seen) | set(expected)) - set(disabled)):
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
