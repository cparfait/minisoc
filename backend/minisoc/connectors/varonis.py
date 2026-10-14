"""Varonis SaaS : alertes des modèles de menace, lues par l'API (lecture seule, flux sortant uniquement).

Le Mini-SOC n'est jamais joignable depuis Internet : au lieu d'attendre un syslog du cloud Varonis, il interroge
l'API de l'instance (https://<tenant>.varonis.io), comme les intégrations officielles (Cortex XSOAR, Sentinel) :
- POST /api/authentication/api_keys/token (en-tête x-api-key, grant_type=varonis_custom) : jeton temporaire ;
- POST /app/dataquery/api/search/v2/search : recherche d'alertes (entité « Alert ») ; la réponse donne l'adresse
  des résultats, à lire par GET /app/dataquery/api/search/<adresse>?from=0&to=N (le calcul peut prendre quelques
  secondes : réponses 206/304/405 tant qu'il n'est pas prêt).
Clé d'API au rôle « Threat Detection Integrator » (Configuration › API Keys). Seules des recherches sont faites :
aucun changement de statut ni note n'est envoyé à Varonis.

Les alertes sont relevées par heure d'arrivée dans le cloud (Alert.IngestTime) : une alerte peut décrire une
activité bien antérieure (collecte par lots, modèles comportementaux). Le délai entre l'activité et l'alerte est
gardé avec chaque alerte (`delay_seconds`) pour le mesurer.
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
from minisoc.settings_store import store as settings_store

log = logging.getLogger(__name__)

MODULE = "varonis"
CURSOR_KEY = "minisoc:cursor:varonis"  # dernière heure d'arrivée lue (ISO 8601, UTC)
SEEN_PREFIX = "minisoc:seen:varonis:"
SEEN_TTL = 365 * 86400
POLL_SECONDS = 60
FIRST_DAYS = 7  # premier passage : alertes arrivées depuis 7 jours
MAX_WINDOW = timedelta(days=7)
PAGE = 500
MAX_PAGES = 10
READY_RETRIES = 10

STATUS_FR = {"new": "nouvelle", "under investigation": "en investigation", "closed": "fermée"}
SEVERITY = {"high": 3, "medium": 2, "low": 1, "informational": 0}
# Motifs de fermeture Varonis qui disent « activité légitime » : faux positif côté Mini-SOC
BENIGN_REASONS = {"benign activity", "authorized activity", "inaccurate alert logic", "environment misconfiguration",
                  "alert recently customized"}

COLUMNS = [
    "Alert.ID",
    "Alert.Rule.Name",
    "Alert.Rule.ID",
    "Alert.Rule.Severity.Name",
    "Alert.Rule.Category.Name",
    "Alert.TimeUTC",
    "Alert.IngestTime",
    "Alert.Status.Name",
    "Alert.CloseReason.Name",
    "Alert.EventsCount",
    "Alert.User.Name",
    "Alert.User.SamAccountName",
    "Alert.User.AccountType.Name",
    "Alert.Device.HostName",
    "Alert.Device.IsMaliciousExternalIP",
    "Alert.Device.ExternalIPThreatTypesName",
    "Alert.Filer.Name",
    "Alert.Filer.Platform.Name",
    "Alert.Asset.Path",
    "Alert.Data.IsSensitive",
    "Alert.Data.IsFlagged",
    "Alert.Location.CountryName",
    "Alert.Location.BlacklistedLocation",
    "Alert.Location.AbnormalLocation",
    "Alert.MitreTactic.Name",
]


class VaronisError(RuntimeError):
    pass


def base_url(cfg: dict) -> str:
    url = str(cfg.get("varonis_url") or "").strip().rstrip("/")
    if url and not url.startswith("https://"):
        url = "https://" + url.removeprefix("http://")
    return url


def configured(cfg: dict) -> bool:
    return bool(base_url(cfg) and cfg.get("varonis_api_key"))


def console_url(cfg: dict, alert_id: str) -> str:
    return f"{base_url(cfg)}/analytics/entity/Alert/{alert_id}" if alert_id else ""


def _filter(path: str, operator: str, *values: dict) -> dict:
    return {"path": path, "operator": operator, "values": list(values)}


def alert_query(filters: list[dict]) -> dict:
    """Corps de recherche (même forme que l'intégration Cortex XSOAR de Varonis)."""
    return {
        "query": {
            "entityName": "Alert",
            "filter": {"filterOperator": 0, "filters": [_filter("Alert.AggregationFilter", "Equals",
                                                                  {"Alert.AggregationFilter": 1}), *filters]},
        },
        "rows": {"columns": COLUMNS, "filter": [], "grouping": "",
                 "ordering": [{"path": "Alert.IngestTime", "sortOrder": "Asc"}]},
        "requestParams": {"searchSource": 1, "searchSourceName": "MainTab"},
    }


def ingest_filter(start: datetime, end: datetime) -> dict:
    return _filter("Alert.IngestTime", "Between",
                   {"Alert.IngestTime": _iso(start), "Alert.IngestTime0": _iso(end)})


def ids_filter(ids: list[str]) -> dict:
    return _filter("Alert.ID", "In", *({"Alert.ID": i, "displayValue": i} for i in ids))


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(tzinfo=None).isoformat(timespec="seconds")


def _date(value) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def rows_to_dicts(data: dict) -> list[dict]:
    columns = data.get("columns") or []
    return [dict(zip(columns, row, strict=False)) for row in data.get("rows") or []]


class VaronisClient:
    def __init__(self, cfg: dict, http: httpx.AsyncClient) -> None:
        self.cfg = cfg
        self.http = http
        self.base = base_url(cfg)
        self._token: tuple[str, float] | None = None

    async def token(self) -> str:
        if self._token and self._token[1] > time.monotonic() + 60:
            return self._token[0]
        response = await self.http.post(
            f"{self.base}/api/authentication/api_keys/token",
            content="grant_type=varonis_custom",
            headers={"x-api-key": str(self.cfg["varonis_api_key"]),
                     "content-type": "application/x-www-form-urlencoded"},
        )
        if response.status_code in (400, 401, 403):
            raise VaronisError("clé d'API Varonis refusée (révoquée, ou sans le rôle « Threat Detection Integrator »)")
        response.raise_for_status()
        data = response.json()
        value = f"{data.get('token_type') or 'Bearer'} {data['access_token']}"
        self._token = (value, time.monotonic() + float(data.get("expires_in") or 600))
        return value

    async def _headers(self) -> dict:
        return {"authorization": await self.token(), "content-type": "application/json",
                "varonis-integration": "Mini-SOC"}

    async def search(self, body: dict, limit: int = PAGE) -> list[dict]:
        response = await self.http.post(f"{self.base}/app/dataquery/api/search/v2/search",
                                        content=json.dumps(body), headers=await self._headers())
        if response.status_code in (401, 403):
            raise VaronisError("accès refusé à la recherche Varonis (rôle de la clé d'API)")
        response.raise_for_status()
        location = (response.json() or [{}])[0].get("location")
        if not location:
            raise VaronisError("réponse de recherche Varonis inattendue (pas d'adresse de résultats)")
        for _ in range(READY_RETRIES):
            result = await self.http.get(f"{self.base}/app/dataquery/api/search/{location}",
                                         params={"from": 0, "to": limit - 1}, headers=await self._headers())
            if result.status_code in (206, 304, 405):  # calcul en cours
                await asyncio.sleep(1)
                continue
            result.raise_for_status()
            return rows_to_dicts(result.json() or {})
        raise VaronisError("résultats de recherche Varonis non prêts, nouvel essai au prochain passage")

    async def alerts_since(self, start: datetime, end: datetime, limit: int = PAGE) -> list[dict]:
        return await self.search(alert_query([ingest_filter(start, end)]), limit)

    async def alerts_by_ids(self, ids: list[str]) -> list[dict]:
        return await self.search(alert_query([ids_filter(ids)]), max(len(ids), 1))


def tactic_tags(value) -> list[str]:
    """« Credential Access, Lateral Movement » → étiquettes attack.credential_access… (chaînes d'attaque)."""
    return [f"attack.{t.strip().lower().replace(' ', '_')}" for t in str(value or "").split(",") if t.strip()]


def record(cfg: dict, alert: dict) -> dict:
    occurred, ingested = _date(alert.get("Alert.TimeUTC")), _date(alert.get("Alert.IngestTime"))
    delay = int((ingested - occurred).total_seconds()) if occurred and ingested else None
    return {
        "type": "alert",
        "alert": alert,
        "console": console_url(cfg, str(alert.get("Alert.ID") or "")),
        "delay_seconds": delay,
        "tags": tactic_tags(alert.get("Alert.MitreTactic.Name")),
    }


def make_http(cfg: dict) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=60)  # instance SaaS : certificat public, toujours vérifié


class VaronisConnector:
    def __init__(self, sessions: async_sessionmaker, redis: aioredis.Redis) -> None:
        self.sessions = sessions
        self.redis = redis

    async def run(self) -> None:
        while True:
            async with self.sessions() as session:
                cfg = await settings_store.load(session)
            if configured(cfg) and cfg.get("src_varonis_enabled", False):
                try:
                    async with make_http(cfg) as http:
                        count = await self.poll(VaronisClient(cfg, http), cfg)
                    await bus.heartbeat(self.redis, MODULE)
                    if count:
                        log.info("Varonis : %d nouvelle(s) alerte(s)", count)
                except VaronisError as exc:
                    log.error("Varonis : %s", exc)
                except Exception as exc:  # noqa: BLE001
                    log.error("Varonis : interrogation en échec : %s", exc)
            await asyncio.sleep(POLL_SECONDS)

    async def poll(self, api: VaronisClient, cfg: dict, now: datetime | None = None) -> int:
        """Alertes arrivées depuis le curseur, par fenêtres de 7 jours au plus ; les alertes déjà lues sont ignorées."""
        now = now or datetime.now(timezone.utc)
        cursor = _date(await self.redis.get(CURSOR_KEY)) or now - timedelta(days=FIRST_DAYS)
        published = 0
        for _ in range(MAX_PAGES):
            end = min(now, cursor + MAX_WINDOW)
            alerts = await api.alerts_since(cursor, end)
            fresh = []
            for alert in alerts:
                alert_id = str(alert.get("Alert.ID") or "")
                if alert_id and await self.redis.set(SEEN_PREFIX + alert_id, 1, nx=True, ex=SEEN_TTL):
                    fresh.append(json.dumps(record(cfg, alert), ensure_ascii=False, default=str))
            published += await bus.publish(self.redis, MODULE, fresh)
            latest = max((d for a in alerts if (d := _date(a.get("Alert.IngestTime")))), default=None)
            if len(alerts) >= PAGE and latest and latest > cursor:
                cursor = latest  # page pleine : la suite dans la même fenêtre (doublons écartés par l'identifiant)
                continue
            cursor = end
            if end >= now:
                break
        # Marge d'une minute : une alerte dont l'arrivée est datée juste avant la fin de la fenêtre n'est pas perdue
        await self.redis.set(CURSOR_KEY, _iso(min(cursor, now - timedelta(minutes=1))))
        return published


def closure_of(alert: dict) -> tuple[str, str] | None:
    """(statut Mini-SOC, libellé) si l'alerte est fermée dans Varonis, sinon None."""
    if str(alert.get("Alert.Status.Name") or "").strip().lower() != "closed":
        return None
    reason = str(alert.get("Alert.CloseReason.Name") or "").strip()
    status = "false_positive" if reason.lower() in BENIGN_REASONS else "resolved"
    return status, f"fermée{f' ({reason})' if reason and reason.lower() != 'none' else ''}"


async def test(cfg: dict) -> tuple[bool, str]:
    """Jeton puis recherche des alertes du dernier jour (lecture seule) : bouton « Tester »."""
    if not configured(cfg):
        return False, "Adresse de l'instance ou clé d'API manquante"
    try:
        async with make_http(cfg) as http:
            api = VaronisClient(cfg, http)
            now = datetime.now(timezone.utc)
            alerts = await api.alerts_since(now - timedelta(days=1), now, 100)
    except VaronisError as exc:
        return False, str(exc)
    except httpx.HTTPStatusError as exc:
        return False, f"Varonis : HTTP {exc.response.status_code}"
    except httpx.HTTPError as exc:
        return False, f"Varonis injoignable ({type(exc).__name__}) : {base_url(cfg)}"
    return True, f"Connexion réussie à {base_url(cfg)} : {len(alerts)} alerte(s) arrivée(s) ces dernières 24 h"
