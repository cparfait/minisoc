"""Vectra AI (NDR) : détections et scores d'entités, lus par l'API REST v3 (lecture seule, flux sortant uniquement).

Alternative au syslog CEF (parsers/cef.py) quand Vectra n'envoie rien vers le Mini-SOC :
- POST /oauth2/token (client d'API en authentification Basic, grant_type=client_credentials) : jeton temporaire ;
- GET /api/v3.4/events/detections?from=<point de reprise> : chaque détection, à sa création et à chaque mise à
  jour (détections triées et de catégorie « info » exclues, comme dans la console) ;
- GET /api/v3.4/events/entity_scoring?type=host|account&from=… : changements de score des hôtes et des comptes
  (règle UC-19, entité critique).
Les réponses donnent le point de reprise suivant (`next_checkpoint`) et le nombre restant : rien n'est perdu ni lu
deux fois après une coupure. Client d'API au rôle « Read-Only » (Paramètres › Clients d'API) ; rien n'est modifié
dans Vectra.
"""

from __future__ import annotations

import asyncio
import json
import logging
import ssl
import time
from datetime import datetime, timedelta, timezone

import httpx
import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import async_sessionmaker

from minisoc import bus
from minisoc.settings_store import store as settings_store

log = logging.getLogger(__name__)

MODULE = "vectra"
API = "/api/v3.4"
CURSOR_PREFIX = "minisoc:cursor:vectra:"  # + detections | host | account : prochain identifiant d'événement
SEEN_PREFIX = "minisoc:seen:vectra:"
SEEN_TTL = 30 * 86400
POLL_SECONDS = 60
FIRST_DAYS = 7  # premier passage : événements des 7 derniers jours
PAGE = 500
MAX_PAGES = 10
# (flux, chemin, paramètres fixes)
STREAMS = (
    ("detections", "/events/detections", {}),
    ("host", "/events/entity_scoring", {"type": "host"}),
    ("account", "/events/entity_scoring", {"type": "account"}),
)


class VectraError(RuntimeError):
    pass


def base_url(cfg: dict) -> str:
    url = str(cfg.get("vectra_url") or "").strip().rstrip("/")
    if url and not url.startswith("https://"):
        url = "https://" + url.removeprefix("http://")
    return url


def configured(cfg: dict) -> bool:
    return bool(base_url(cfg) and cfg.get("vectra_client_id") and cfg.get("vectra_client_secret"))


def tls(cfg: dict) -> ssl.SSLContext | bool:
    """Brain sur site : certificat de la PKI interne (autorité à fournir) ; SaaS : certificat public."""
    if not cfg.get("vectra_verify_tls", True):
        return False
    return ssl.create_default_context(cadata=cfg.get("vectra_ca_cert") or None)


def make_http(cfg: dict) -> httpx.AsyncClient:
    return httpx.AsyncClient(verify=tls(cfg), timeout=60, headers={"Accept": "application/json"})


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class VectraClient:
    def __init__(self, cfg: dict, http: httpx.AsyncClient) -> None:
        self.cfg = cfg
        self.http = http
        self.base = base_url(cfg)
        self._token: tuple[str, float] | None = None

    async def token(self, force: bool = False) -> str:
        if not force and self._token and self._token[1] > time.monotonic() + 60:
            return self._token[0]
        response = await self.http.post(
            f"{self.base}/oauth2/token",
            data={"grant_type": "client_credentials"},
            auth=(str(self.cfg["vectra_client_id"]), str(self.cfg["vectra_client_secret"])),
        )
        if response.status_code in (400, 401, 403):
            raise VectraError("identifiants du client d'API Vectra refusés (client supprimé ou secret changé)")
        response.raise_for_status()
        data = response.json()
        self._token = (str(data["access_token"]), time.monotonic() + float(data.get("expires_in") or 3600))
        return self._token[0]

    async def get(self, path: str, params: dict) -> dict:
        for attempt in range(2):
            response = await self.http.get(f"{self.base}{API}{path}", params=params,
                                           headers={"Authorization": f"Bearer {await self.token(force=attempt > 0)}"})
            if response.status_code == 401 and attempt == 0:
                continue  # jeton expiré côté Vectra : un nouveau, une seule fois
            if response.status_code in (401, 403):
                raise VectraError("accès refusé à l'API Vectra (rôle du client d'API)")
            response.raise_for_status()
            return response.json() or {}
        raise VectraError("accès refusé à l'API Vectra")

    async def events(self, path: str, fixed: dict, checkpoint: int | None, since: datetime | None,
                     limit: int = PAGE) -> dict:
        params = {**fixed, "limit": limit}
        if checkpoint is not None:
            params["from"] = checkpoint
        elif since is not None:
            params["event_timestamp_gte"] = _iso(since)
        return await self.get(path, params)


def record(kind: str, event: dict) -> dict:
    """Message publié : type d'événement, événement brut de l'API, techniques MITRE en étiquettes."""
    tags = [f"attack.{str(t).lower()}" for t in event.get("mitre") or [] if str(t).upper().startswith("T")]
    return {"type": "detection" if kind == "detections" else f"{kind}_scoring", "event": event, "tags": tags}


class VectraConnector:
    def __init__(self, sessions: async_sessionmaker, redis: aioredis.Redis) -> None:
        self.sessions = sessions
        self.redis = redis

    async def run(self) -> None:
        while True:
            async with self.sessions() as session:
                cfg = await settings_store.load(session)
            if configured(cfg) and cfg.get("src_vectra_enabled", False):
                try:
                    async with make_http(cfg) as http:
                        count = await self.poll(VectraClient(cfg, http))
                    await bus.heartbeat(self.redis, MODULE)
                    if count:
                        log.info("Vectra : %d nouvel(s) événement(s)", count)
                except VectraError as exc:
                    log.error("Vectra : %s", exc)
                except Exception as exc:  # noqa: BLE001
                    log.error("Vectra : interrogation en échec : %s", exc)
            await asyncio.sleep(POLL_SECONDS)

    async def poll(self, api: VectraClient, now: datetime | None = None) -> int:
        """Chaque flux depuis son point de reprise, par lots ; les événements déjà publiés sont écartés."""
        now = now or datetime.now(timezone.utc)
        published = 0
        for kind, path, fixed in STREAMS:
            saved = await self.redis.get(CURSOR_PREFIX + kind)
            checkpoint = int(saved) if saved not in (None, "") else None
            for _ in range(MAX_PAGES):
                data = await api.events(path, fixed, checkpoint, now - timedelta(days=FIRST_DAYS))
                fresh = []
                for event in data.get("events") or []:
                    event_id = str(event.get("id") or "")
                    if event_id and await self.redis.set(f"{SEEN_PREFIX}{kind}:{event_id}", 1, nx=True, ex=SEEN_TTL):
                        fresh.append(json.dumps(record(kind, event), ensure_ascii=False, default=str))
                published += await bus.publish(self.redis, MODULE, fresh)
                following = data.get("next_checkpoint")
                if following is not None:
                    checkpoint = int(following)
                    await self.redis.set(CURSOR_PREFIX + kind, str(checkpoint))
                if not data.get("remaining_count") or following is None:
                    break
        return published


async def test(cfg: dict) -> tuple[bool, str]:
    """Jeton puis lecture des détections et des scores des dernières 24 h (lecture seule) : bouton « Tester »."""
    if not configured(cfg):
        return False, "Adresse, identifiant ou secret du client d'API manquant"
    since = datetime.now(timezone.utc) - timedelta(days=1)
    try:
        async with make_http(cfg) as http:
            api = VectraClient(cfg, http)
            counts = []
            for kind, path, fixed in STREAMS:
                data = await api.events(path, fixed, None, since, limit=1)
                counts.append(len(data.get("events") or []) + int(data.get("remaining_count") or 0))
    except VectraError as exc:
        return False, str(exc)
    except httpx.HTTPStatusError as exc:
        hint = " (API v3.4 absente : version de Vectra trop ancienne ?)" if exc.response.status_code == 404 else ""
        return False, f"Vectra : HTTP {exc.response.status_code}{hint}"
    except httpx.HTTPError as exc:
        return False, f"Vectra injoignable ({type(exc).__name__}) : {base_url(cfg)}"
    return True, (f"Connexion réussie à {base_url(cfg)} : ces dernières 24 h, {counts[0]} événement(s) de détection, "
                  f"{counts[1]} score(s) d'hôte, {counts[2]} score(s) de compte")
