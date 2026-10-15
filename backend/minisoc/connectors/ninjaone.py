"""NinjaOne (gestion du parc) : alertes et état de sécurité des postes, en lecture seule.

API publique v2 de NinjaOne, jeton OAuth2
« client credentials » en portée « monitoring » (lecture seule), POST https://<instance>/ws/oauth/token.
Application à créer dans NinjaOne : Administration › Applications › API › Ajouter une application client ›
« Services API (de machine à machine) », portée Surveillance, autorisation « Identifiants du client ».

Deux lectures :
- toutes les 2 minutes, les alertes actives (/v2/alerts) : chaque nouvelle alerte devient un événement ;
- toutes les 30 minutes, l'état de sécurité du parc : inventaire (/v2/devices-detailed), santé
  (/v2/queries/device-health : vulnérabilités par gravité, correctifs en échec, menaces actives) et antivirus
  (/v2/queries/antivirus-status). Seuls les changements produisent des événements (antivirus coupé ou obsolète,
  menace active, vulnérabilités critiques apparues ou en hausse, correctifs en échec) ; la synthèse (postes les plus
  exposés) est gardée pour la page Veille.
L'API ne fournit pas les numéros CVE par poste (seulement des nombres par gravité) : pas de croisement direct avec le
catalogue KEV.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time

import httpx
import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import async_sessionmaker

from minisoc import bus
from minisoc.settings_store import store as settings_store

log = logging.getLogger(__name__)

MODULE = "ninjaone"
INSTANCES = {"eu": "eu.ninjarmm.com", "us": "app.ninjarmm.com", "ca": "ca.ninjarmm.com", "oc": "oc.ninjarmm.com"}
POSTURE_KEY = "minisoc:ninjaone:posture"  # hash id appareil -> état précédent (JSON)
SUMMARY_KEY = "minisoc:ninjaone:summary"  # synthèse pour la page Veille
ACTIVE_KEY = "minisoc:ninjaone:active"  # alertes actives au dernier passage (synchronisation des statuts)
POSTURE_AT_KEY = "minisoc:ninjaone:posture_at"  # horodatage du dernier relevé de posture
SEEN_PREFIX = "minisoc:seen:ninjaone:"
SEEN_TTL = 30 * 86400
ALERTS_SECONDS = 120
POSTURE_SECONDS = 1800
SERVER_CLASSES = {"WINDOWS_SERVER", "LINUX_SERVER", "MAC_SERVER", "VMWARE_VM_HOST", "HYPERV_VMM_HOST", "NMS_SERVER"}


class NinjaError(RuntimeError):
    pass


def host(cfg: dict) -> str:
    instance = str(cfg.get("ninjaone_instance") or "eu").strip()
    return INSTANCES.get(instance, instance.removeprefix("https://").strip("/"))


def configured(cfg: dict) -> bool:
    return bool(cfg.get("ninjaone_client_id") and cfg.get("ninjaone_client_secret"))


def console_url(cfg: dict, device_id) -> str:
    return f"https://{host(cfg)}/#/deviceDashboard/{int(device_id)}/overview" if device_id else ""


class NinjaClient:
    def __init__(self, cfg: dict, client: httpx.AsyncClient) -> None:
        self.cfg = cfg
        self.client = client
        self.base = f"https://{host(cfg)}"
        self._token: tuple[str, float] | None = None

    async def token(self) -> str:
        if self._token and self._token[1] > time.monotonic() + 60:
            return self._token[0]
        response = await self.client.post(
            f"{self.base}/ws/oauth/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self.cfg["ninjaone_client_id"],
                "client_secret": self.cfg["ninjaone_client_secret"],
                "scope": "monitoring",
            },
        )
        if response.status_code in (400, 401, 403):
            raise NinjaError("identifiants NinjaOne refusés (identifiant client, secret ou portée « monitoring »)")
        response.raise_for_status()
        data = response.json()
        self._token = (data["access_token"], time.monotonic() + float(data.get("expires_in", 3600)))
        return self._token[0]

    async def get(self, path: str, params: dict | None = None):
        for _attempt in range(2):  # jeton expiré ou révoqué côté NinjaOne : un nouvel essai avec un jeton neuf
            response = await self.client.get(
                f"{self.base}{path}", params=params or {}, headers={"Authorization": f"Bearer {await self.token()}"}
            )
            if response.status_code not in (401, 403):
                break
            self._token = None
        if response.status_code in (401, 403):
            raise NinjaError("accès NinjaOne refusé (portée « monitoring » ?)")
        response.raise_for_status()
        return response.json()

    async def devices(self) -> list[dict]:
        """Inventaire détaillé, pages de 1 000 (curseur « after » = dernier identifiant)."""
        devices, after = [], None
        for _ in range(20):
            page = await self.get("/v2/devices-detailed", {"pageSize": 1000, **({"after": after} if after else {})})
            devices += page
            if len(page) < 1000:
                break
            after = page[-1]["id"]
        return devices

    async def query(self, path: str) -> list[dict]:
        """Requête de parc (/v2/queries/…) : curseur « cursor.name », jusqu'au total annoncé (« cursor.count »)."""
        rows: list[dict] = []
        cursor = None
        total = None
        for _ in range(50):
            page = await self.get(path, {"pageSize": 1000, **({"cursor": cursor} if cursor else {})})
            if not isinstance(page, dict):  # ancienne forme : simple liste
                return rows + list(page or [])
            batch = page.get("results") or []
            rows += batch
            info = page.get("cursor") or {}
            total = info.get("count", total)
            cursor = info.get("name")
            if (
                not batch
                or not cursor
                or (total is not None and len(rows) >= int(total))
                or (total is None and len(batch) < 1000)
            ):
                break
        if total is not None and len(rows) < int(total):
            raise NinjaError(
                f"{path} : lecture incomplète ({len(rows)} lignes sur {total}), nouvel essai au prochain passage"
            )
        return rows


NO_PRODUCT = {"NONE", "UNKNOWN", "N/A"}


def antivirus_state(products: list[dict], server: bool = False) -> str:
    """« ok », « outdated » (définitions obsolètes), « inactive » (aucun produit actif) ou « unknown ».

    Fiable seulement quand NinjaOne voit un produit réel : sur Windows Server (pas de Centre de sécurité) et pour un
    produit « NONE », l'état est inconnu. L'absence d'antivirus est établie par GravityZone (minisoc/coverage.py)."""
    products = [p for p in products if str(p.get("productName") or "").strip().upper() not in NO_PRODUCT]
    if not products:
        return "unknown"
    active = [p for p in products if str(p.get("productState") or "").upper() == "ON"]
    if not active:
        return "unknown" if server else "inactive"
    if all("out" in str(p.get("definitionStatus") or "").lower() for p in active):
        return "outdated"
    return "ok"


def posture(device: dict, health: dict, products: list[dict]) -> dict:
    return {
        "name": device.get("systemName") or device.get("displayName") or str(device.get("id")),
        "class": device.get("nodeClass") or "",
        "offline": bool(device.get("offline")),
        "last_contact": float(device.get("lastContact") or 0),  # secondes epoch (couverture antivirus et EDR)
        "ip": (device.get("ipAddresses") or [""])[0],
        "critical": int(health.get("criticalVulnerabilityCount") or 0),
        "high": int(health.get("highVulnerabilityCount") or 0),
        "medium": int(health.get("mediumVulnerabilityCount") or 0),
        "pending": int(health.get("pendingOSPatchesCount") or 0),
        "failed": int(health.get("failedOSPatchesCount") or 0),
        "threats": int(health.get("activeThreatsCount") or 0),
        "antivirus": antivirus_state(products, server="SERVER" in str(device.get("nodeClass") or "").upper()),
        "products": ", ".join(str(p.get("productName") or "?") for p in products)[:200],
    }


def alert_key(alert: dict) -> str:
    """Identifiant d'une alerte NinjaOne (uid, à défaut empreinte du poste, de la date et du message)."""
    return str(
        alert.get("uid")
        or hashlib.sha256(
            f"{alert.get('deviceId')}|{alert.get('createTime')}|{alert.get('message') or alert.get('subject')}".encode()
        ).hexdigest()[:32]
    )


def changes(device_id, now: dict, before: dict | None, baseline: bool = False) -> list[dict]:
    """Événements de changement d'état.

    - premier relevé du parc (`baseline`) : état des lieux sans alerte (page Veille), sauf menace active ;
    - machine vue pour la première fois ensuite : seulement ce qui est grave (menace, antivirus coupé), pas le stock
      de vulnérabilités ni les correctifs en échec ;
    - ensuite : les aggravations par rapport au relevé précédent.
    """
    out = []
    if now["threats"] > int((before or {}).get("threats") or 0):
        out.append({"kind": "active_threat"})
    if baseline:
        return [{**c, "device_id": device_id, "device": now} for c in out]
    if now["antivirus"] in ("inactive", "outdated") and (before or {}).get("antivirus") != now["antivirus"]:
        out.append({"kind": "antivirus_" + now["antivirus"]})
    if before:
        if now["critical"] > int(before.get("critical") or 0):
            out.append({"kind": "critical_vulnerabilities", "previous": int(before.get("critical") or 0)})
        if now["failed"] > int(before.get("failed") or 0):
            out.append({"kind": "patches_failed"})
    return [{**c, "device_id": device_id, "device": now} for c in out]


class NinjaOneConnector:
    def __init__(self, sessions: async_sessionmaker, redis: aioredis.Redis) -> None:
        self.sessions = sessions
        self.redis = redis
        self.last_posture = 0.0

    async def run(self) -> None:
        while True:
            async with self.sessions() as session:
                cfg = await settings_store.load(session)
            if configured(cfg) and cfg.get("src_ninjaone_enabled", False):
                try:
                    async with httpx.AsyncClient(timeout=60) as http:
                        api = NinjaClient(cfg, http)
                        count = await self.poll_alerts(api, cfg)
                        if time.monotonic() - self.last_posture > POSTURE_SECONDS or not self.last_posture:
                            count += await self.poll_posture(api, cfg)
                            self.last_posture = time.monotonic()
                    await bus.heartbeat(self.redis, MODULE)
                    if count:
                        log.info("NinjaOne : %d événement(s)", count)
                except NinjaError as exc:
                    log.error("NinjaOne : %s", exc)
                except Exception as exc:  # noqa: BLE001
                    log.error("NinjaOne : interrogation en échec : %s", exc)
            await asyncio.sleep(ALERTS_SECONDS)

    async def poll_alerts(self, api: NinjaClient, cfg: dict) -> int:
        alerts = await api.get("/v2/alerts", {"lang": "fr", "tz": "Europe/Paris"}) or []
        fresh = []
        await self.redis.set(
            ACTIVE_KEY, json.dumps({"at": time.time(), "keys": [alert_key(a) for a in alerts]}), ex=3600
        )
        for alert in alerts:
            key = alert_key(alert)
            if await self.redis.set(SEEN_PREFIX + key, 1, nx=True, ex=SEEN_TTL):
                fresh.append(
                    json.dumps(
                        {"type": "alert", "alert": alert, "console": console_url(cfg, alert.get("deviceId"))},
                        ensure_ascii=False,
                        default=str,
                    )
                )
        return await bus.publish(self.redis, MODULE, fresh)

    async def poll_posture(self, api: NinjaClient, cfg: dict) -> int:
        devices = await api.devices()
        health = {x.get("deviceId"): x for x in await api.query("/v2/queries/device-health")}
        products: dict = {}
        for x in await api.query("/v2/queries/antivirus-status"):
            products.setdefault(x.get("deviceId"), []).append(x)
        previous = {k: json.loads(v) for k, v in (await self.redis.hgetall(POSTURE_KEY)).items()}
        current, events = {}, []
        for device in devices:
            device_id = device.get("id")
            state = posture(device, health.get(device_id, {}), products.get(device_id, []))
            current[str(device_id)] = json.dumps(state, ensure_ascii=False)
            for change in changes(device_id, state, previous.get(str(device_id)), baseline=not previous):
                events.append(
                    json.dumps(
                        {"type": "posture", **change, "console": console_url(cfg, device_id)}, ensure_ascii=False
                    )
                )
        pipe = self.redis.pipeline(transaction=True)
        pipe.delete(POSTURE_KEY)
        if current:
            pipe.hset(POSTURE_KEY, mapping=current)
        pipe.set(SUMMARY_KEY, json.dumps(summary(cfg, devices, current), ensure_ascii=False))
        pipe.set(POSTURE_AT_KEY, time.time())
        await pipe.execute()
        return await bus.publish(self.redis, MODULE, events)


def summary(cfg: dict, devices: list[dict], current: dict[str, str]) -> dict:
    states = {k: json.loads(v) for k, v in current.items()}
    exposed = sorted(
        (
            (k, s)
            for k, s in states.items()
            if s["critical"] or s["high"] or s["threats"] or s["antivirus"] in ("inactive", "outdated")
        ),
        key=lambda ks: (-ks[1]["threats"], -ks[1]["critical"], -ks[1]["high"]),
    )
    return {
        "at": time.time(),
        "devices": len(devices),
        "offline": sum(1 for s in states.values() if s["offline"]),
        "critical": sum(s["critical"] for s in states.values()),
        "high": sum(s["high"] for s in states.values()),
        "with_critical": sum(1 for s in states.values() if s["critical"]),
        "antivirus_issues": sum(1 for s in states.values() if s["antivirus"] in ("inactive", "outdated")),
        "threats": sum(s["threats"] for s in states.values()),
        "failed_patches": sum(1 for s in states.values() if s["failed"]),
        "exposed": [
            {**s, "id": k, "server": s["class"] in SERVER_CLASSES, "console": console_url(cfg, k)}
            for k, s in exposed[:30]
        ],
    }


async def test(cfg: dict) -> tuple[bool, str]:
    """Jeton puis lecture d'une page d'inventaire (lecture seule) : bouton « Tester »."""
    if not configured(cfg):
        return False, "Identifiant client ou secret manquant"
    async with httpx.AsyncClient(timeout=30) as http:
        api = NinjaClient(cfg, http)
        try:
            page = await api.get("/v2/devices", {"pageSize": 1})
            alerts = await api.get("/v2/alerts", {"lang": "fr"})
        except NinjaError as exc:
            return False, str(exc)
        except httpx.HTTPError as exc:
            return False, f"NinjaOne injoignable ({type(exc).__name__}) : instance {host(cfg)}"
    return (
        True,
        f"Connexion réussie à {host(cfg)} : inventaire accessible"
        f"{'' if page else ' mais vide (aucun appareil visible avec ces droits)'}, {len(alerts)} alerte(s) active(s). "
        "Le parc complet est lu au premier relevé, puis toutes les 30 minutes.",
    )
