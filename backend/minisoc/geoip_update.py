"""Téléchargement des bases GeoLite2 de MaxMind (pays et opérateur), réglé depuis l'interface : fiche
« Géolocalisation » › identifiant de compte et clé de licence MaxMind (compte gratuit).

Le worker télécharge GeoLite2-City et GeoLite2-ASN dès que l'identifiant et la clé sont enregistrés, puis tous les
3 jours (la licence GeoLite2 impose des bases à jour). Adresse officielle :
https://download.maxmind.com/geoip/databases/<édition>/download?suffix=tar.gz (authentification Basic : identifiant
du compte et clé de licence), qui renvoie vers le stockage de MaxMind. Chaque base est écrite à côté puis remplacée
d'un coup : le worker ne lit jamais un fichier à moitié écrit (geoip.py relit les bases quand elles changent).
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import logging
import os
import tarfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx
import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import async_sessionmaker

from minisoc.settings_store import store as settings_store

log = logging.getLogger(__name__)

EDITIONS = ("GeoLite2-City", "GeoLite2-ASN")
URL = "https://download.maxmind.com/geoip/databases/{edition}/download"
STATE_KEY = "minisoc:geoip:download"  # dernier téléchargement : date, erreur, identifiant et empreinte de la clé
REFRESH = timedelta(days=3)
RETRY_AFTER_ERROR = timedelta(hours=1)
CHECK_SECONDS = 300


class GeoIPError(RuntimeError):
    pass


def configured(cfg: dict) -> bool:
    return bool(str(cfg.get("maxmind_account_id") or "").strip() and cfg.get("maxmind_license_key"))


def _auth(cfg: dict) -> tuple[str, str]:
    return str(cfg["maxmind_account_id"]).strip(), str(cfg["maxmind_license_key"]).strip()


def _fingerprint(cfg: dict) -> str:
    account, key = _auth(cfg)
    return hashlib.sha256(f"{account}:{key}".encode()).hexdigest()[:16]


def make_http() -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=300, follow_redirects=True)


async def _get(http: httpx.AsyncClient, cfg: dict, edition: str, suffix: str) -> httpx.Response:
    response = await http.get(URL.format(edition=edition), params={"suffix": suffix}, auth=_auth(cfg))
    if response.status_code in (401, 403):
        raise GeoIPError("identifiant de compte ou clé de licence MaxMind refusés")
    response.raise_for_status()
    return response


def extract_mmdb(archive: bytes) -> bytes:
    """Fichier .mmdb contenu dans l'archive MaxMind (GeoLite2-City_AAAAMMJJ/GeoLite2-City.mmdb)."""
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        for member in tar.getmembers():
            if member.isfile() and member.name.endswith(".mmdb"):
                data = tar.extractfile(member)
                if data is not None:
                    return data.read()
    raise GeoIPError("archive MaxMind sans base .mmdb")


async def download(http: httpx.AsyncClient, cfg: dict, directory: str) -> list[str]:
    target = Path(directory)
    target.mkdir(parents=True, exist_ok=True)
    written = []
    for edition in EDITIONS:
        content = extract_mmdb((await _get(http, cfg, edition, "tar.gz")).content)
        tmp = target / f".{edition}.mmdb.tmp"
        tmp.write_bytes(content)
        os.replace(tmp, target / f"{edition}.mmdb")
        written.append(f"{edition}.mmdb")
    return written


async def state(redis: aioredis.Redis) -> dict:
    return json.loads(await redis.get(STATE_KEY) or "{}")


def _date(value) -> datetime | None:
    try:
        return datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


async def maybe_update(cfg: dict, redis: aioredis.Redis, directory: str, http: httpx.AsyncClient | None = None,
                       now: datetime | None = None) -> bool:
    """Télécharge les bases si elles manquent, si l'identifiant ou la clé ont changé ou tous les 3 jours."""
    if not cfg.get("geoip_enabled") or not configured(cfg):
        return False
    now = now or datetime.now(timezone.utc)
    previous = await state(redis)
    fingerprint = _fingerprint(cfg)
    changed = previous.get("key") != fingerprint
    missing = any(not (Path(directory) / f"{e}.mmdb").exists() for e in EDITIONS)
    updated, tried = _date(previous.get("updated")), _date(previous.get("tried"))
    if not changed and previous.get("error") and tried and now - tried < RETRY_AFTER_ERROR:
        return False  # erreur récente avec les mêmes identifiants : pas d'essai à chaque passage
    if not (changed or missing or not updated or now - updated >= REFRESH):
        return False
    record = {"key": fingerprint, "tried": now.isoformat(), "updated": previous.get("updated"), "error": ""}
    try:
        if http is None:
            async with make_http() as client:
                files = await download(client, cfg, directory)
        else:
            files = await download(http, cfg, directory)
        record["updated"] = now.isoformat()
        log.info("bases GeoIP téléchargées : %s", ", ".join(files))
    except GeoIPError as exc:
        record["error"] = str(exc)
    except httpx.HTTPStatusError as exc:
        record["error"] = f"MaxMind : HTTP {exc.response.status_code}"
    except (httpx.HTTPError, OSError, tarfile.TarError) as exc:
        record["error"] = f"téléchargement impossible ({type(exc).__name__})"
    if record["error"]:
        log.error("GeoIP : %s", record["error"])
    await redis.set(STATE_KEY, json.dumps(record))
    return not record["error"]


class GeoIPUpdater:
    """Tâche du worker : vérifie toutes les 5 minutes s'il faut télécharger les bases."""

    def __init__(self, sessions: async_sessionmaker, redis: aioredis.Redis, directory: str) -> None:
        self.sessions = sessions
        self.redis = redis
        self.directory = directory

    async def run(self) -> None:
        while True:
            async with self.sessions() as session:
                cfg = await settings_store.load(session)
            await maybe_update(cfg, self.redis, self.directory)
            await asyncio.sleep(CHECK_SECONDS)


async def test(cfg: dict) -> tuple[bool, str]:
    """Vérifie l'identifiant et la clé sans télécharger les bases (fichiers d'empreinte seulement)."""
    if not configured(cfg):
        return False, "Identifiant de compte ou clé de licence MaxMind manquant"
    try:
        async with make_http() as http:
            for edition in EDITIONS:
                await _get(http, cfg, edition, "tar.gz.sha256")
    except GeoIPError as exc:
        return False, str(exc)
    except httpx.HTTPStatusError as exc:
        return False, f"MaxMind : HTTP {exc.response.status_code}"
    except httpx.HTTPError as exc:
        return False, f"MaxMind injoignable ({type(exc).__name__})"
    return True, ("Identifiant et clé acceptés par MaxMind : les bases GeoLite2 (pays et opérateur) seront "
                  "téléchargées dans les 5 minutes si la géolocalisation est activée")
