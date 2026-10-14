"""CrowdSec : décisions de bannissement lues sur l'API locale (LAPI) avec une clé de bouncer (lecture seule).

    cscli bouncers add minisoc      → clé à saisir dans Paramètres > Connecteurs

- Décisions locales (scénarios déclenchés sur vos serveurs, cscli, AppSec) → événements « crowdsec ».
- Toutes les décisions sur des IP (y compris liste communautaire) → base de renseignement en Redis, utilisée pour
  enrichir chaque événement (champ threat.intel) et repérer une IP bannie qui réussit à se connecter (UC-18).
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import re
import time

import httpx
import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import async_sessionmaker

from minisoc import bus
from minisoc.settings_store import store as settings_store

log = logging.getLogger(__name__)

MODULE = "crowdsec"
INTEL_KEY = "minisoc:intel:crowdsec"  # hash ip -> {"scenario", "origin", "until"}
RANGES_KEY = "minisoc:intel:crowdsec:ranges"  # hash cidr -> idem
LOCAL_ORIGINS = {"crowdsec", "cscli", "appsec", "console"}
POLL_SECONDS = 60
_DURATION = re.compile(r"(\d+(?:\.\d+)?)(ms|h|m|s)")
_FACTOR = {"h": 3600, "m": 60, "s": 1, "ms": 0.001}


def duration_seconds(value: str) -> float:
    """Durée au format Go (« 3h59m58.5s ») en secondes ; négative ou illisible = 0."""
    if not value or value.startswith("-"):
        return 0.0
    return sum(float(n) * _FACTOR[unit] for n, unit in _DURATION.findall(value))


class CrowdSecConnector:
    def __init__(self, sessions: async_sessionmaker, redis: aioredis.Redis) -> None:
        self.sessions = sessions
        self.redis = redis

    async def run(self) -> None:
        startup = True
        configured_for: tuple = ()
        while True:
            async with self.sessions() as session:
                cfg = await settings_store.load(session)
            current = (cfg.get("crowdsec_url"), cfg.get("crowdsec_api_key"), cfg.get("crowdsec_community"))
            if not current[0] or not current[1] or not cfg.get("src_crowdsec_enabled", False):
                await asyncio.sleep(POLL_SECONDS)
                continue
            if current != configured_for:  # nouvelle configuration : relecture complète
                startup, configured_for = True, current
            try:
                count = await self.poll(cfg, startup)
                startup = False
                await bus.heartbeat(self.redis, MODULE)
                if count:
                    log.info("CrowdSec : %d nouvelle(s) décision(s) locale(s)", count)
            except httpx.HTTPStatusError as exc:
                log.error("CrowdSec : HTTP %s (clé de bouncer invalide ?)", exc.response.status_code)
            except Exception as exc:  # noqa: BLE001
                log.error("CrowdSec : interrogation en échec : %s", exc)
            await asyncio.sleep(POLL_SECONDS)

    async def poll(self, cfg: dict, startup: bool) -> int:
        params = {"startup": "true" if startup else "false"}
        if not cfg.get("crowdsec_community"):
            params["origins"] = ",".join(sorted(LOCAL_ORIGINS))
        async with httpx.AsyncClient(timeout=60) as client:
            response = await client.get(cfg["crowdsec_url"].rstrip("/") + "/v1/decisions/stream", params=params,
                                        headers={"X-Api-Key": cfg["crowdsec_api_key"], "User-Agent": "minisoc"})
            response.raise_for_status()
            data = response.json() or {}
        if startup:
            await self.redis.delete(INTEL_KEY, RANGES_KEY)
        return await self.apply(data.get("new") or [], data.get("deleted") or [])

    async def apply(self, new: list[dict], deleted: list[dict]) -> int:
        now = time.time()
        pipe = self.redis.pipeline(transaction=False)
        local_events = []
        for decision in deleted:
            key = RANGES_KEY if str(decision.get("scope", "")).lower() == "range" else INTEL_KEY
            pipe.hdel(key, str(decision.get("value", "")))
        for decision in new:
            scope = str(decision.get("scope", "")).lower()
            value = str(decision.get("value", ""))
            info = json.dumps({
                "scenario": decision.get("scenario", ""),
                "origin": decision.get("origin", ""),
                "until": now + duration_seconds(str(decision.get("duration", ""))),
            })
            if scope == "ip":
                pipe.hset(INTEL_KEY, value, info)
            elif scope == "range":
                pipe.hset(RANGES_KEY, value, info)
            if str(decision.get("origin", "")).lower() in LOCAL_ORIGINS and not decision.get("simulated"):
                local_events.append(json.dumps(decision, ensure_ascii=False))
        await pipe.execute()
        await bus.publish(self.redis, MODULE, local_events)
        return len(local_events)


class ThreatIntel:
    """Cache en mémoire des IP bannies (rafraîchi chaque minute) pour enrichir les événements sans latence."""

    def __init__(self, redis: aioredis.Redis) -> None:
        self.redis = redis
        self.ips: dict[str, tuple[str, float]] = {}
        self.ranges: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, str, float]] = []

    async def refresh(self) -> None:
        ips, ranges = {}, []
        for ip, raw in (await self.redis.hgetall(INTEL_KEY)).items():
            data = json.loads(raw)
            ips[ip] = (data.get("scenario") or "ban", float(data.get("until") or 0))
        for cidr, raw in (await self.redis.hgetall(RANGES_KEY)).items():
            data = json.loads(raw)
            try:
                ranges.append((ipaddress.ip_network(cidr, strict=False), data.get("scenario") or "ban",
                               float(data.get("until") or 0)))
            except ValueError:
                continue
        self.ips, self.ranges = ips, ranges

    def lookup(self, ip: str) -> str:
        if not ip:
            return ""
        now = time.time()
        hit = self.ips.get(ip)
        if hit and hit[1] > now:
            return f"crowdsec:{hit[0]}"
        if self.ranges:
            try:
                addr = ipaddress.ip_address(ip)
            except ValueError:
                return ""
            for net, scenario, until in self.ranges:
                if until > now and addr.version == net.version and addr in net:
                    return f"crowdsec:{scenario}"
        return ""
