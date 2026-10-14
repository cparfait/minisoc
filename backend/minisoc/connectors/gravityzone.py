"""Bitdefender GravityZone (cloud) : incidents EDR et fichiers mis en quarantaine, lus par l'API publique.

Le Mini-SOC n'est jamais joignable depuis Internet : au lieu du service « Event Push » (GravityZone pousse vers une
adresse publique), il interroge l'API JSON-RPC de la console (HTTPS sortant, clé d'API en authentification Basic) :
- incidents (v1.2) › getIncidentsList : incidents Endpoint et Organisation modifiés depuis le dernier passage
  (filtre changeStartDate/changeEndDate, GravityZone 6.77 et plus ; à défaut startDate/endDate) ;
- quarantine/computers (v1.0) › getQuarantineItemsList : fichiers mis en quarantaine depuis le dernier passage ;
- incidents (v1.2) › getIncidentsByIds : statut des incidents, pour clôturer ici ce qui est traité dans GravityZone.

Couverture : les détections antivirus nettoyées ou supprimées sans quarantaine, l'antihameçonnage, les attaques
réseau et les modules désactivés ne sont disponibles que par Event Push (non utilisé : il exige une publication sur
Internet). Seules des lectures sont faites ; la clé d'API ne doit avoir que les API Incidents, Quarantaine et Réseau.

Les événements sont publiés au format du service Push (module « new-incident » ou « av ») : le même analyseur et
les mêmes règles s'appliquent.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
import uuid
from datetime import datetime, timedelta, timezone

import httpx
import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import async_sessionmaker

from minisoc import bus
from minisoc.settings_store import store as settings_store

log = logging.getLogger(__name__)

MODULE = "bitdefender"
INCIDENTS_CURSOR = "minisoc:cursor:gravityzone:incidents"
QUARANTINE_CURSOR = "minisoc:cursor:gravityzone:quarantine"
SEEN_PREFIX = "minisoc:seen:gravityzone:"
SEEN_TTL = 365 * 86400
POLL_SECONDS = 60
DEFAULT_HISTORY_DAYS = 365  # relu au raccordement (Paramètres : bitdefender_history_days, 0 = tout)
WINDOW = timedelta(days=30)  # rattrapage de l'historique par tranches de 30 jours (une par passage)
MAX_PAGES = 20
# Limite de l'API publique pour ces méthodes : 10 requêtes par seconde et par clé (file de 10, puis HTTP 429).
# Le Mini-SOC s'en tient à 5 par seconde au plus (support Bitdefender, « API rate limits »).
MIN_INTERVAL = 0.2
CLOSED = {"closed": "clôturé (menace confirmée, traitée)", "false_positive": "faux positif",
          "closed_mdr_reviewed": "clôturé par le SOC MDR de Bitdefender"}
STATUS_FR = {"open": "ouvert", "in_progress": "en investigation", **CLOSED}


class GravityZoneError(RuntimeError):
    def __init__(self, message: str, code: int | None = None) -> None:
        super().__init__(message)
        self.code = code


class RateLimited(GravityZoneError):
    """Limite de requêtes atteinte : pause demandée par GravityZone (en-tête Retry-After)."""

    def __init__(self, seconds: float) -> None:
        super().__init__(f"limite de requêtes de l'API atteinte, reprise dans {int(seconds)} s")
        self.seconds = seconds


def retry_after(value: str | None) -> float:
    """En-tête Retry-After, parfois dupliqué par un relais (« 60, 60 ») : premier nombre, 2 s à défaut."""
    match = re.match(r"\s*(\d+(?:\.\d+)?)", value or "")
    return float(match.group(1)) if match else 2.0


DEFAULT_API_URL = "https://cloudgz.gravityzone.bitdefender.com/api"


def api_url(cfg: dict) -> str:
    """Access URL de la console, normalisée : « https://cloudgz.gravityzone.bitdefender.com », « …/api » ou une adresse
    de méthode collée en entier (« …/api/v1.0/jsonrpc/network ») donnent toutes « …/api »."""
    url = str(cfg.get("bitdefender_api_url") or DEFAULT_API_URL).strip().rstrip("/")
    if not url.startswith(("https://", "http://")):
        url = "https://" + url
    url = re.sub(r"/v1\.\d+(/jsonrpc.*)?$", "", url)
    return url if url.endswith("/api") else url + "/api"


def configured(cfg: dict) -> bool:
    return bool(cfg.get("bitdefender_read_api_key"))


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds")


def _date(value) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


class GravityZoneClient:
    def __init__(self, cfg: dict, http: httpx.AsyncClient) -> None:
        self.base = api_url(cfg)
        self.http = http
        self.auth = (str(cfg["bitdefender_read_api_key"]), "")
        self._last = 0.0

    async def _pace(self) -> None:
        wait = MIN_INTERVAL - (time.monotonic() - self._last)
        if wait > 0:
            await asyncio.sleep(wait)
        self._last = time.monotonic()

    async def call(self, path: str, method: str, params: dict) -> dict | list:
        body = {"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": method, "params": params}
        for _ in range(3):
            await self._pace()
            response = await self.http.post(f"{self.base}/{path}", json=body, auth=self.auth)
            if response.status_code == 429:  # limite de requêtes de la clé
                wait = retry_after(response.headers.get("retry-after"))
                if wait > 5:
                    raise RateLimited(wait)  # longue attente : passage interrompu, reprise après le délai
                await asyncio.sleep(wait)
                continue
            break
        if response.status_code == 401:
            raise GravityZoneError("clé d'API GravityZone refusée")
        if response.status_code == 404:
            raise GravityZoneError(f"adresse introuvable ({self.base}/{path}) : vérifier l'Access URL "
                                   "(Mon compte › Control Center API)")
        response.raise_for_status()
        data = response.json()
        if data.get("error"):
            error = data["error"]
            detail = (error.get("data") or {}).get("details") if isinstance(error.get("data"), dict) else ""
            raise GravityZoneError(f"{error.get('message')}{f' : {detail}' if detail else ''}", error.get("code"))
        return data.get("result")

    async def pages(self, path: str, method: str, params: dict, per_page: int) -> list[dict]:
        items: list[dict] = []
        for page in range(1, MAX_PAGES + 1):
            result = await self.call(path, method, {**params, "page": page, "perPage": per_page}) or {}
            items += result.get("items") or []
            if page >= int(result.get("pagesCount") or 1) or not result.get("items"):
                return items
        raise GravityZoneError(f"{method} : plus de {MAX_PAGES * per_page} éléments, lecture interrompue")

    async def incidents_changed(self, start: datetime, end: datetime) -> list[dict]:
        window = {"changeStartDate": _iso(start), "changeEndDate": _iso(end)}
        try:
            return await self.pages("v1.2/jsonrpc/incidents", "getIncidentsList",
                                    {"filters": window, "options": {"sortBy": "lastIncidentChange"}}, 1000)
        except GravityZoneError as exc:
            if exc.code != -32602:  # paramètres invalides : console antérieure à la version 6.77
                raise
        return await self.pages("v1.2/jsonrpc/incidents", "getIncidentsList",
                                {"filters": {"startDate": _iso(start), "endDate": _iso(end)}}, 1000)

    async def incidents_by_ids(self, ids: list[str]) -> list[dict]:
        out: list[dict] = []
        for i in range(0, len(ids), 10):  # 10 identifiants au plus par appel
            out += await self.call("v1.2/jsonrpc/incidents", "getIncidentsByIds", {"ids": ids[i : i + 10]}) or []
        return out

    async def quarantined(self, start: datetime, end: datetime) -> list[dict]:
        window = {"startDate": _iso(start).removesuffix("+00:00"), "endDate": _iso(end).removesuffix("+00:00")}
        return await self.pages("v1.0/jsonrpc/quarantine/computers", "getQuarantineItemsList",
                                {"filters": window}, 100)


def incident_record(incident: dict) -> dict:
    """Incident GravityZone → événement au format Push « new-incident »."""
    details = incident.get("details") or {}
    attacks = ", ".join(str(a) for a in incident.get("attackTypes") or [])
    organization = incident.get("incidentType") == "extendedIncident"
    counters = details.get("counters") or {}
    return {
        "module": "new-incident",
        "source": "api",
        "incident_id": incident.get("incidentId"),
        "incident_number": incident.get("incidentNumber"),
        "incident_type": "incident d'organisation" if incident.get("incidentType") == "extendedIncident"
        else "incident",
        "detection_name": details.get("detectionName") or attacks or "Incident GravityZone",
        "attack_type": attacks,
        "computer_name": details.get("computerName") or details.get("computerFqdn") or "",
        "computer_ip": details.get("computerIp") or "",
        "final_status": incident.get("mainAction") or "",
        "incident_status": incident.get("status") or "",
        "priority": incident.get("priority") or "",
        "severity_score": incident.get("severityScore"),
        "created": incident.get("created"),
        "last_updated": incident.get("lastUpdated"),
        "incident_link": incident.get("incidentLink") or "",
        # Incident d'organisation : corrélation d'incidents de postes ; nombre de machines concernées
        "organization": organization,
        "endpoints": int(counters.get("endpoints") or 0) + int(counters.get("servers") or 0),
    }


def quarantine_record(item: dict) -> dict:
    """Fichier mis en quarantaine → événement au format Push « av » (menace neutralisée)."""
    details = item.get("details") or {}
    return {
        "module": "av",
        "source": "api",
        "quarantine_id": item.get("id"),
        "computer_name": item.get("endpointName") or "",
        "computer_ip": item.get("endpointIP") or "",
        "malware_name": item.get("threatName") or details.get("threatName") or "fichier mis en quarantaine",
        "file_path": details.get("filePath") or "",
        "hash": details.get("fileSha256") or "",
        "final_status": "quarantined",
        "timestamp": item.get("quarantinedOn"),
    }


class GravityZoneConnector:
    def __init__(self, sessions: async_sessionmaker, redis: aioredis.Redis) -> None:
        self.sessions = sessions
        self.redis = redis
        self.paused_until = 0.0

    async def run(self) -> None:
        while True:
            async with self.sessions() as session:
                cfg = await settings_store.load(session)
            ready = configured(cfg) and cfg.get("src_bitdefender_enabled", False)
            if ready and time.monotonic() >= self.paused_until:
                try:
                    days = cfg.get("bitdefender_history_days")
                    async with httpx.AsyncClient(timeout=60) as http:
                        count = await self.poll(GravityZoneClient(cfg, http),
                                                history_days=DEFAULT_HISTORY_DAYS if days is None else int(days))
                    await bus.heartbeat(self.redis, MODULE)
                    if count:
                        log.info("GravityZone : %d événement(s)", count)
                except RateLimited as exc:
                    self.paused_until = time.monotonic() + exc.seconds
                    log.warning("GravityZone : %s", exc)
                except GravityZoneError as exc:
                    log.error("GravityZone : %s", exc)
                except Exception as exc:  # noqa: BLE001
                    log.error("GravityZone : interrogation en échec : %s", exc)
            await asyncio.sleep(POLL_SECONDS)

    async def _range(self, key: str, now: datetime, history_days: int) -> tuple[datetime, datetime]:
        """Tranche à lire : depuis le curseur (au raccordement, l'historique demandé), 30 jours au plus."""
        start = _date(await self.redis.get(key)) or now - timedelta(days=history_days or 3650)
        return start, min(now, start + WINDOW)

    async def _advance(self, key: str, end: datetime, now: datetime) -> None:
        # Marge d'une minute au présent : un élément daté juste avant la fin de la tranche n'est pas perdu
        await self.redis.set(key, _iso(end if end < now else now - timedelta(minutes=1)))

    async def _read(self, kind: str, api: GravityZoneClient, now: datetime, history_days: int,
                    payloads: list[str]) -> None:
        cursor = INCIDENTS_CURSOR if kind == "incidents" else QUARANTINE_CURSOR
        start, end = await self._range(cursor, now, history_days)
        if kind == "incidents":
            for incident in await api.incidents_changed(start, end):
                # Nouvel incident, ou nouvelle activité (lastUpdated) : un événement ; un simple changement de
                # statut dans la console n'en produit pas (il sert à la clôture, relue à part)
                key = f"{SEEN_PREFIX}i:{incident.get('incidentId')}:{incident.get('lastUpdated')}"
                if incident.get("incidentId") and await self.redis.set(key, 1, nx=True, ex=SEEN_TTL):
                    payloads.append(json.dumps(incident_record(incident), ensure_ascii=False, default=str))
        else:
            for item in await api.quarantined(start, end):
                if item.get("id") and await self.redis.set(f"{SEEN_PREFIX}q:{item['id']}", 1, nx=True, ex=SEEN_TTL):
                    payloads.append(json.dumps(quarantine_record(item), ensure_ascii=False, default=str))
        await self._advance(cursor, end, now)

    async def poll(self, api: GravityZoneClient, now: datetime | None = None,
                   history_days: int = DEFAULT_HISTORY_DAYS) -> int:
        """Une tranche d'incidents et une de quarantaine par passage ; l'historique est rattrapé 30 jours à la fois."""
        now = now or datetime.now(timezone.utc)
        payloads: list[str] = []
        errors: list[str] = []
        try:
            for kind in ("incidents", "quarantaine"):
                try:
                    await self._read(kind, api, now, history_days, payloads)
                except RateLimited:
                    raise
                except GravityZoneError as exc:
                    errors.append(f"{kind} : {exc}")
        finally:
            count = await bus.publish(self.redis, MODULE, payloads)  # ce qui a été lu est gardé, même en pause
        if len(errors) == 2:
            raise GravityZoneError(" ; ".join(errors))
        for error in errors:
            log.warning("GravityZone : %s", error)
        return count


async def test(cfg: dict) -> tuple[bool, str]:
    """Lecture des incidents et de la quarantaine du dernier jour (lecture seule) : bouton « Tester »."""
    if not configured(cfg):
        return False, "Clé d'API de lecture manquante"
    now = datetime.now(timezone.utc)
    parts, ok = [], False
    try:
        async with httpx.AsyncClient(timeout=30) as http:
            api = GravityZoneClient(cfg, http)
            for label, read in (("incidents", api.incidents_changed), ("quarantaine", api.quarantined)):
                try:
                    items = await read(now - timedelta(days=1), now)
                    parts.append(f"{label} : lecture possible ({len(items)} sur 24 h)")
                    ok = True
                except GravityZoneError as exc:
                    parts.append(f"{label} : {exc}")
    except httpx.HTTPStatusError as exc:
        return False, f"GravityZone : HTTP {exc.response.status_code}"
    except httpx.HTTPError as exc:
        return False, f"GravityZone injoignable ({type(exc).__name__}) : {api_url(cfg)}"
    return ok, f"{api_url(cfg)} : " + " ; ".join(parts)
