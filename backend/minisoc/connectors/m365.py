"""Microsoft 365 / Entra ID : journal d'audit unifié lu par l'API Office 365 Management Activity (lecture seule).

Inscription d'application Entra ID (Paramètres › Intégrations › Microsoft 365) :
  - API « Office 365 Management APIs », permission d'application ActivityFeed.Read, consentement administrateur ;
  - un secret client (à renouveler avant expiration).
Aucune licence Entra ID P1 n'est requise (l'audit unifié est actif par défaut sur les tenants Microsoft 365).

Fonctionnement : abonnement aux flux Audit.AzureActiveDirectory (connexions, rôles, consentements) et, en option,
Audit.Exchange (règles de transfert) ; toutes les 5 minutes, liste des blocs publiés depuis le dernier passage
(fenêtre de 24 h au plus, 7 jours d'historique), lecture des blocs non encore vus, tri des opérations utiles.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta, timezone

import httpx
import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import async_sessionmaker

from minisoc import bus
from minisoc.parsers.m365 import interesting
from minisoc.settings_store import store as settings_store

log = logging.getLogger(__name__)

MODULE = "m365"
LOGIN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
API_URL = "https://manage.office.com/api/v1.0/{tenant}/activity/feed"
SCOPE = "https://manage.office.com/.default"
CURSOR_KEY = "minisoc:cursor:m365:{content}"
SEEN_PREFIX = "minisoc:seen:m365:"
SEEN_TTL = 8 * 24 * 3600
POLL_SECONDS = 300
OVERLAP = timedelta(minutes=15)  # chevauchement entre deux passages (blocs déjà vus ignorés)
MAX_WINDOW = timedelta(hours=24)
MAX_HISTORY = timedelta(days=7) - timedelta(hours=1)
MAX_BLOBS = 500


class M365Error(RuntimeError):
    pass


def content_types(cfg: dict) -> list[str]:
    types = ["Audit.AzureActiveDirectory"]
    if cfg.get("m365_exchange", True):
        types.append("Audit.Exchange")
    return types


def configured(cfg: dict) -> bool:
    return all(cfg.get(k) for k in ("m365_tenant_id", "m365_client_id", "m365_client_secret"))


class M365Client:
    def __init__(self, cfg: dict, client: httpx.AsyncClient) -> None:
        self.cfg = cfg
        self.client = client
        self.tenant = str(cfg["m365_tenant_id"]).strip()
        self.base = API_URL.format(tenant=self.tenant)
        self._token: tuple[str, float] | None = None

    async def token(self) -> str:
        if self._token and self._token[1] > time.monotonic() + 60:
            return self._token[0]
        response = await self.client.post(LOGIN_URL.format(tenant=self.tenant), data={
            "grant_type": "client_credentials", "client_id": self.cfg["m365_client_id"],
            "client_secret": self.cfg["m365_client_secret"], "scope": SCOPE,
        })
        if response.status_code != 200:
            detail = response.json().get("error_description", "") if response.headers.get(
                "content-type", "").startswith("application/json") else response.text
            raise M365Error(f"jeton refusé par Entra ID (HTTP {response.status_code}) : {str(detail)[:200]}")
        data = response.json()
        self._token = (data["access_token"], time.monotonic() + int(data.get("expires_in", 3600)))
        return self._token[0]

    async def get(self, url: str, params: dict | None = None) -> httpx.Response:
        response = await self.client.get(url, params=params, headers={"Authorization": f"Bearer {await self.token()}"})
        if response.status_code == 401 or response.status_code == 403:
            raise M365Error(f"accès refusé (HTTP {response.status_code}) : permission ActivityFeed.Read et "
                            "consentement administrateur à vérifier")
        response.raise_for_status()
        return response

    async def subscriptions(self) -> dict[str, str]:
        response = await self.get(f"{self.base}/subscriptions/list")
        return {s.get("contentType", ""): s.get("status", "") for s in response.json() or []}

    async def start(self, content_type: str) -> None:
        response = await self.client.post(f"{self.base}/subscriptions/start", params={"contentType": content_type},
                                          headers={"Authorization": f"Bearer {await self.token()}"})
        if response.status_code >= 400 and "AF20024" not in response.text:  # AF20024 : abonnement déjà actif
            raise M365Error(f"abonnement {content_type} impossible (HTTP {response.status_code}) : "
                            f"{response.text[:200]}")

    async def blobs(self, content_type: str, start: datetime, end: datetime) -> list[dict]:
        fmt = "%Y-%m-%dT%H:%M:%S"
        url: str | None = f"{self.base}/subscriptions/content"
        params: dict | None = {"contentType": content_type, "startTime": start.strftime(fmt),
                               "endTime": end.strftime(fmt)}
        out: list[dict] = []
        while url and len(out) < MAX_BLOBS:
            response = await self.get(url, params)
            out.extend(response.json() or [])
            url, params = response.headers.get("NextPageUri"), None
        return out

    async def records(self, blob: dict) -> list[dict]:
        response = await self.get(blob["contentUri"])
        data = response.json()
        return data if isinstance(data, list) else []


class M365Connector:
    def __init__(self, sessions: async_sessionmaker, redis: aioredis.Redis) -> None:
        self.sessions = sessions
        self.redis = redis
        self.started: tuple = ()

    async def run(self) -> None:
        while True:
            async with self.sessions() as session:
                cfg = await settings_store.load(session)
            if configured(cfg) and cfg.get("src_m365_enabled", True):
                try:
                    async with httpx.AsyncClient(timeout=60) as http:
                        count = await self.poll(M365Client(cfg, http), cfg)
                    await bus.heartbeat(self.redis, MODULE)
                    if count:
                        log.info("Microsoft 365 : %d événement(s) utile(s)", count)
                except M365Error as exc:
                    log.error("Microsoft 365 : %s", exc)
                except Exception as exc:  # noqa: BLE001
                    log.error("Microsoft 365 : interrogation en échec : %s", exc)
            await asyncio.sleep(POLL_SECONDS)

    async def poll(self, api: M365Client, cfg: dict) -> int:
        types = content_types(cfg)
        key = (cfg["m365_tenant_id"], cfg["m365_client_id"], tuple(types))
        if key != self.started:  # abonnements (idempotent) à chaque changement de configuration
            for content_type in types:
                await api.start(content_type)
            self.started = key
        published = 0
        now = datetime.now(timezone.utc)
        for content_type in types:
            cursor_key = CURSOR_KEY.format(content=content_type)
            raw = await self.redis.get(cursor_key)
            start = datetime.fromisoformat(raw) if raw else now - timedelta(hours=24)
            start = max(start - OVERLAP, now - MAX_HISTORY)
            while start < now:
                end = min(start + MAX_WINDOW, now)
                for blob in await api.blobs(content_type, start, end):
                    blob_id = str(blob.get("contentId", ""))
                    if not blob_id or not await self.redis.set(SEEN_PREFIX + blob_id, 1, nx=True, ex=SEEN_TTL):
                        continue
                    try:
                        records = await api.records(blob)
                    except Exception:
                        await self.redis.delete(SEEN_PREFIX + blob_id)  # relu au prochain passage
                        raise
                    keep = [json.dumps(r, ensure_ascii=False, default=str) for r in records if interesting(r)]
                    published += await bus.publish(self.redis, MODULE, keep)
                await self.redis.set(cursor_key, end.isoformat())
                start = end
        return published


async def test(cfg: dict) -> tuple[bool, str]:
    """Jeton, puis état des abonnements (démarrés si besoin) : bouton « Tester » de l'intégration."""
    if not configured(cfg):
        return False, "Identifiant du tenant, identifiant d'application ou secret manquant"
    async with httpx.AsyncClient(timeout=30) as http:
        api = M365Client(cfg, http)
        try:
            await api.token()
            for content_type in content_types(cfg):
                await api.start(content_type)
            states = await api.subscriptions()
        except M365Error as exc:
            return False, str(exc)
        except httpx.HTTPError as exc:
            return False, f"API Microsoft injoignable : {type(exc).__name__}"
    wanted = content_types(cfg)
    detail = ", ".join(f"{k.removeprefix('Audit.')} : {v}" for k, v in sorted(states.items()) if k in wanted)
    return True, f"Connexion réussie, abonnements {detail or 'en cours de création'}"
