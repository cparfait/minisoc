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
