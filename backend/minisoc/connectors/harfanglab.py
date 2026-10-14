"""Interrogation périodique des alertes de l'EDR HarfangLab (jeton d'API en lecture seule)."""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone

import httpx
import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import async_sessionmaker

from minisoc import bus
from minisoc.settings_store import store as settings_store

log = logging.getLogger(__name__)

MODULE = "harfanglab"
CURSOR_KEY = "minisoc:cursor:harfanglab"
SEEN_PREFIX = "minisoc:seen:harfanglab:"
SEEN_TTL = 3 * 365 * 24 * 3600  # une relecture complète de l'historique ne réimporte pas les alertes déjà lues
DEFAULT_HISTORY_DAYS = 0  # 0 : tout l'historique de la console
PAGE_SIZE = 200
MAX_PAGES = 25
POLL_SECONDS = 60


class HarfangLabConnector:
    """Paramètres relus à chaque passage (Paramètres > Connecteurs) : pas de redémarrage nécessaire."""

    def __init__(self, sessions: async_sessionmaker, redis: aioredis.Redis) -> None:
        self.sessions = sessions
        self.redis = redis

    async def run(self) -> None:
        while True:
            async with self.sessions() as session:
                cfg = await settings_store.load(session)
            if configured(cfg):
                try:
                    async with make_client(cfg) as client:
                        days = cfg.get("harfanglab_history_days")
                        count = await self.poll(client, DEFAULT_HISTORY_DAYS if days is None else int(days))
                    await bus.heartbeat(self.redis, MODULE)
                    if count:
                        log.info("HarfangLab : %d nouvelle(s) alerte(s)", count)
                except httpx.HTTPStatusError as exc:
                    log.error("HarfangLab : HTTP %s (jeton expiré ou droits insuffisants ?)", exc.response.status_code)
                except Exception as exc:  # noqa: BLE001
                    log.error("HarfangLab : interrogation en échec : %s", exc)
            await asyncio.sleep(POLL_SECONDS)

    async def poll(self, client: httpx.AsyncClient, history_days: int = DEFAULT_HISTORY_DAYS) -> int:
        """Alertes depuis le curseur ; au premier passage (ou après « Relire l'historique »), `history_days` jours
        (0 : tout l'historique). Les alertes déjà lues (identifiant) sont ignorées : une relecture n'ajoute que les
        manquantes. Au-delà de MAX_PAGES pages, la suite est lue au passage suivant (le curseur avance)."""
        cursor = await self.redis.get(CURSOR_KEY)
        if cursor:
            since = cursor
        elif history_days > 0:
            since = (datetime.now(timezone.utc) - timedelta(days=history_days)).isoformat()
        else:
            since = ""
        newest = since
        published = 0
        offset = 0
        for _ in range(MAX_PAGES):
            params = {"ordering": "alert_time", "limit": PAGE_SIZE, "offset": offset}
            if since:
                params["alert_time__gte"] = since
            response = await client.get("/api/data/alert/alert/Alert/", params=params)
            response.raise_for_status()
            data = response.json()
            items = data.get("results", data if isinstance(data, list) else [])
            fresh = []
            for alert in items:
                alert_id = str(alert.get("id", ""))
                # Déduplication par identifiant : robuste même si le filtre de date n'est pas appliqué
                if alert_id and not await self.redis.set(SEEN_PREFIX + alert_id, 1, nx=True, ex=SEEN_TTL):
                    continue
                fresh.append(json.dumps(alert, ensure_ascii=False, default=str))
                newest = max(newest, str(alert.get("alert_time") or newest))
            published += await bus.publish(self.redis, MODULE, fresh)
            if len(items) < PAGE_SIZE or not data.get("next"):
                break
            offset += PAGE_SIZE
        if newest != since:
            await self.redis.set(CURSOR_KEY, newest)
        return published


def configured(cfg: dict) -> bool:
    return bool(cfg.get("harfanglab_url") and cfg.get("harfanglab_token") and cfg.get("src_harfanglab_enabled", False))


def make_client(cfg: dict) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=str(cfg["harfanglab_url"]).rstrip("/"),
        headers={"Authorization": f"Token {cfg['harfanglab_token']}", "Accept": "application/json"},
        verify=bool(cfg.get("harfanglab_verify_tls", True)),
        timeout=30,
    )


OPEN_STATUSES = ("new", "investigating")
MAX_STATUS_PAGES = 500  # 100 000 alertes ouvertes


async def open_alert_ids(client: httpx.AsyncClient) -> dict[str, str]:
    """Identifiants des alertes encore à traiter dans HarfangLab (seuls l'identifiant et le statut sont demandés).
    Lève une exception si la liste n'a pas pu être lue en entier : aucune clôture ne doit se fonder sur une
    liste partielle."""
    ids: dict[str, str] = {}  # identifiant -> statut (new | investigating)
    for status in OPEN_STATUSES:
        offset = 0
        for _ in range(MAX_STATUS_PAGES):
            response = await client.get(
                "/api/data/alert/alert/Alert/",
                params={"status": status, "fields": "id,status", "limit": PAGE_SIZE, "offset": offset},
            )
            response.raise_for_status()
            data = response.json()
            items = data.get("results", [])
            # Contrôle : si le filtre de statut était ignoré, les alertes clôturées seraient comptées comme ouvertes
            ids.update(
                (str(a["id"]), str(a.get("status", status)))
                for a in items
                if str(a.get("status", status)) in OPEN_STATUSES
            )
            if len(items) < PAGE_SIZE or not data.get("next"):
                break
            offset += PAGE_SIZE
        else:
            raise RuntimeError("liste des alertes ouvertes HarfangLab trop longue : synchronisation interrompue")
    return ids


async def alert_status(client: httpx.AsyncClient, alert_id: str) -> dict | None:
    """Statut et historique de statut d'une alerte ; None si elle n'existe plus dans HarfangLab."""
    response = await client.get(
        f"/api/data/alert/alert/Alert/{alert_id}/", params={"fields": "id,status,status_history"}
    )
    if response.status_code == 404:
        return None
    response.raise_for_status()
    return response.json()


async def reread_history(redis: aioredis.Redis) -> None:
    """Relecture de l'historique au prochain passage (profondeur : réglage harfanglab_history_days, 0 = tout)."""
    await redis.delete(CURSOR_KEY)
