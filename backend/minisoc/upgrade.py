"""Reprise des réglages d'une installation existante lors d'une mise à jour (lancée au démarrage de l'API).

Les intégrations étaient actives par défaut ; elles sont désormais désactivées tant que la DSI ne les active pas.
Sur une installation déjà en service, une intégration jamais réglée explicitement mais qui fonctionne (données
reçues, veille récupérée, bases GeoIP présentes) reste active : la mise à jour ne coupe aucune source. Une
intégration désactivée à la main garde son réglage. Sans effet sur une installation neuve.
"""

from __future__ import annotations

import json
import logging

import redis.asyncio as aioredis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc import audit, bus
from minisoc.integrations import CATALOG, GEOIP_STATUS_KEY
from minisoc.models import Setting
from minisoc.settings_store import store as settings_store
from minisoc.threat_feeds import KEV_META

log = logging.getLogger(__name__)


async def keep_working_integrations(session: AsyncSession, redis: aioredis.Redis) -> list[str]:
    """Active explicitement les intégrations en service jamais réglées ; retourne les clés écrites."""
    explicit = {s.key for s in (await session.scalars(select(Setting))).all()}
    last_seen = await bus.sources_last_seen(redis)
    working = {i.enable_key for i in CATALOG
               if i.enable_key and i.modules and any(m in last_seen for m in i.modules)}
    if (await redis.hgetall(KEV_META)).get("updated"):
        working.add("threat_feeds_enabled")
    if (json.loads(await redis.get(GEOIP_STATUS_KEY) or "{}")).get("files"):
        working.add("geoip_enabled")
    keep = sorted(working - explicit)
    if keep:
        await settings_store.update_keys(session, set(keep), {k: True for k in keep}, "mise à jour")
        await audit.record(session, actor="mise à jour", action="integrations_kept", obj="settings",
                           detail={"enabled": keep})
        await session.commit()
        settings_store.invalidate()
        log.info("mise à jour : intégrations en service conservées actives : %s", ", ".join(keep))
    return keep


async def categorize_rule_alerts(session: AsyncSession, rules) -> int:
    """Alertes ouvertes de règles d'hygiène ou d'information créées avant que la règle ne précise sa catégorie :
    classées comme leur règle (filtre « Hygiène du parc », poids dans le risque)."""
    from minisoc.models import OPEN_STATUSES, Alert

    categories = {r.id: r.category for r in rules.rules if r.category != "threat"}
    if not categories:
        return 0
    rows = (await session.scalars(select(Alert).where(Alert.rule_id.in_(categories),
                                                      Alert.status.in_(OPEN_STATUSES)))).all()
    changed = 0
    for alert in rows:
        if not (alert.details or {}).get("category"):
            alert.details = {**(alert.details or {}), "category": categories[alert.rule_id]}
            changed += 1
    if changed:
        await session.commit()
        log.info("mise à jour : %d alerte(s) ouverte(s) classée(s) selon leur règle (hygiène, information)", changed)
    return changed


async def retire_unreliable_antivirus(session: AsyncSession) -> int:
    """Alertes « Aucun antivirus actif » de NinjaOne fondées sur un produit « NONE » ou sur un serveur (pas de Centre
    de sécurité Windows) : état inconnu, pas une absence. Clôturées une fois ; l'absence d'antivirus ou d'EDR est
    désormais établie par GravityZone et HarfangLab (règles UC-58 et UC-59)."""
    from minisoc.alerts import SYSTEM
    from minisoc.models import OPEN_STATUSES, Alert, AlertHistory

    rows = (await session.scalars(select(Alert).where(
        Alert.rule_id == "UC-11", Alert.status.in_(OPEN_STATUSES), Alert.entity_key.contains("antivirus_disabled"),
    ))).all()
    closed = 0
    for alert in rows:
        sample = (alert.details or {}).get("sample") or {}
        text = f"{alert.title} {sample.get('message') or ''}"
        if "(NONE)" not in text.upper() and "produit inconnu" not in text and not _server_alert(alert):
            continue
        alert.status, alert.notify_pending = "resolved", False
        session.add(AlertHistory(alert_id=alert.id, actor=SYSTEM, action="status", detail="resolved"))
        session.add(AlertHistory(alert_id=alert.id, actor=SYSTEM, action="comment", detail=(
            "NinjaOne ne sait pas lire l'antivirus de cette machine (produit « NONE » ou serveur sans Centre de "
            "sécurité Windows) : état inconnu, pas une absence. L'absence d'antivirus et d'EDR est désormais "
            "vérifiée dans GravityZone et HarfangLab (UC-58, UC-59). Clôture automatique.")))
        closed += 1
    if closed:
        await session.commit()
        log.info("mise à jour : %d alerte(s) « Aucun antivirus actif » de NinjaOne non fiables clôturées", closed)
    return closed


def _server_alert(alert) -> bool:
    from minisoc.assets import SERVER_NAME

    host = str(((alert.details or {}).get("sample") or {}).get("host.name") or "")
    return bool(SERVER_NAME.match(host))


TRIVY_RULES = ("UC-52", "UC-53")
TRIVY_SETTINGS = ("src_trivy_enabled", "trivy_alert_high")


async def retire_trivy(session: AsyncSession, redis: aioredis.Redis) -> int:
    """Trivy retiré du Mini-SOC (21/10/2026) : efface ses rapports gardés dans Redis, la source « trivy » de l'état
    des sources et ses réglages, et clôture avec une explication les alertes ouvertes des règles UC-52 et UC-53.
    Une fois fait, ne trouve plus rien. Les vulnérabilités du parc restent suivies par Cyberwatch."""
    from sqlalchemy import delete

    from minisoc.alerts import SYSTEM
    from minisoc.integrations import DROPPED_KEY
    from minisoc.models import OPEN_STATUSES, Alert, AlertHistory

    keys = [k async for k in redis.scan_iter(match="minisoc:trivy:*")]
    if keys:
        await redis.delete(*keys)
    await redis.hdel(bus.SOURCES_KEY, "trivy")
    await redis.hdel(DROPPED_KEY, "trivy")
    await session.execute(delete(Setting).where(Setting.key.in_(TRIVY_SETTINGS)))
    rows = (await session.scalars(select(Alert).where(
        Alert.rule_id.in_(TRIVY_RULES), Alert.status.in_(OPEN_STATUSES),
    ))).all()
    for alert in rows:
        alert.status, alert.notify_pending = "resolved", False
        session.add(AlertHistory(alert_id=alert.id, actor=SYSTEM, action="status", detail="resolved"))
        session.add(AlertHistory(alert_id=alert.id, actor=SYSTEM, action="comment", detail=(
            "Trivy a été retiré du Mini-SOC : cette faille n'est plus suivie ici. Les vulnérabilités du parc "
            "restent suivies par Cyberwatch. Clôture automatique.")))
    await session.commit()
    if rows or keys:
        log.info("mise à jour : Trivy retiré (%d clé(s) Redis effacée(s), %d alerte(s) ouverte(s) clôturée(s))",
                 len(keys), len(rows))
    return len(rows)
