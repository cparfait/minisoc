"""Couverture du parc : machines sans antivirus (Bitdefender GravityZone) ou sans EDR (HarfangLab).

Chaque heure, trois listes sont croisées (lecture seule) :
- les machines en service : relevé NinjaOne (contact depuis moins de 7 jours) et agents HarfangLab actifs ;
- les postes protégés par l'antivirus : machines gérées dans GravityZone (API Réseau, getEndpointsList) ;
- les postes protégés par l'EDR : agents HarfangLab ayant donné signe de vie depuis moins de 7 jours.

Une machine en service absente de GravityZone (ou seulement « découverte », sans agent) donne une alerte UC-58
« pas d'antivirus » ; absente de HarfangLab (ou agent muet depuis plus de 7 jours), une alerte UC-59 « pas d'EDR ».
Seuls les systèmes Windows et macOS sont attendus (appliances, hyperviseurs et équipements réseau n'en ont pas).

Garde-fous : une liste lue partiellement ou en erreur ne produit aucune alerte (et n'en clôture aucune) ; une
machine doit manquer depuis 24 heures (déploiement en cours d'une nouvelle machine) ; quand elle redevient couverte
ou n'est plus en service, l'alerte est clôturée automatiquement, avec une trace. Une machine volontairement non
équipée se déclare en exception (Règles › Exceptions, champ host.name).

Le relevé NinjaOne « Aucun antivirus » n'est plus utilisé pour l'absence : faux sur Windows Server (pas de Centre de
sécurité) et pour les produits non reconnus (« NONE »).

Les adresses IP vues par les agents alimentent aussi la table adresse → machine (minisoc/identity.py).
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

import httpx
from sqlalchemy import select

from minisoc import identity
from minisoc.alerts import SYSTEM, Detection, _last_closed, upsert_alert
from minisoc.identity import base_host_key
from minisoc.models import OPEN_STATUSES, Alert, AlertHistory
from minisoc.rules.engine import entity_key, render_title
from minisoc.settings_store import store as settings_store

log = logging.getLogger(__name__)

NO_AV_RULE = "UC-58"
NO_EDR_RULE = "UC-59"
STATUS_KEY = "minisoc:coverage:status"
MISSING_KEY = "minisoc:coverage:missing:"  # + règle : hash machine -> première constatation (ISO)
NOW_KEY = "minisoc:coverage:now"  # vérification immédiate demandée
ALIVE = timedelta(days=7)  # machine en service / agent actif
GRACE = timedelta(hours=24)  # délai avant alerte (installation d'une nouvelle machine)
POSTURE_FRESH = 3 * 3600  # relevé NinjaOne de moins de 3 heures
EXPECTED_NINJA = ("WINDOWS_WORKSTATION", "WINDOWS_SERVER", "MAC", "MAC_SERVER")
EXPECTED_OS = ("windows", "macos", "mac", "darwin")
HL_PAGE = 200
HL_MAX_PAGES = 250  # 50 000 agents


@dataclass
class Machine:
    name: str
    server: bool = False
    sources: set[str] = field(default_factory=set)  # ninjaone, harfanglab


@dataclass
class Inventory:
    alive: dict[str, Machine] = field(default_factory=dict)  # clé -> machine en service
    antivirus: dict[str, str] | None = None  # clé -> état GravityZone (« géré », « non géré ») ; None : non lu
    edr: dict[str, datetime | None] | None = None  # clé -> dernier signe de vie de l'agent ; None : non lu
    errors: list[str] = field(default_factory=list)
    complete: bool = True  # faux si une source attendue des machines en service manque (aucune conclusion)


def _date(value) -> datetime | None:
    if not value:
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc)
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _alive(inv: Inventory, name: str, source: str, server: bool) -> None:
    key = base_host_key(name)
    if not key or identity.is_ip(key):
        return
    machine = inv.alive.setdefault(key, Machine(name=name.split(".")[0]))
    machine.server = machine.server or server
    machine.sources.add(source)


def add_ninjaone(inv: Inventory, devices: list[dict], now: datetime) -> list[tuple[str, str, datetime | None]]:
    """Relevé NinjaOne (état de sécurité, minisoc/connectors/ninjaone.py) : machines Windows et macOS en service."""
    pairs = []
    for device in devices:
        seen = _date(device.get("last_contact"))
        if device.get("name") and device.get("ip"):
            pairs.append((device["name"], device["ip"], seen))
        if str(device.get("class") or "") not in EXPECTED_NINJA or not device.get("name"):
            continue
        if seen is None or now - seen > ALIVE:
            continue
        _alive(inv, device["name"], "ninjaone", "SERVER" in str(device.get("class")))
    return pairs


def add_harfanglab(inv: Inventory, agents: list[dict], now: datetime) -> list[tuple[str, str, datetime | None]]:
    """Agents HarfangLab : protection EDR (agent actif) et machines en service."""
    inv.edr = {}
    pairs = []
    for agent in agents:
        name = str(agent.get("hostname") or "").strip()
        if not name:
            continue
        seen = _date(agent.get("lastseen"))
        key = base_host_key(name)
        if key not in inv.edr or (seen and (inv.edr[key] is None or seen > inv.edr[key])):
            inv.edr[key] = seen
        for ip in _ips(agent.get("ipaddress")):
            pairs.append((name, ip, seen))
        os_type = str(agent.get("ostype") or "").lower()
        if seen and now - seen <= ALIVE and (not os_type or os_type.startswith(EXPECTED_OS)):
            server = "server" in str(agent.get("osproducttype") or agent.get("osversion") or "").lower()
            _alive(inv, name, "harfanglab", server)
    return pairs


def add_gravityzone(inv: Inventory, endpoints: list[dict]) -> list[tuple[str, str, datetime | None]]:
    """Machines connues de GravityZone : « géré » (agent Bitdefender installé) ou « non géré » (seulement découverte
    sur le réseau ou dans l'annuaire, sans protection)."""
    inv.antivirus = {}
    pairs = []
    for endpoint in endpoints:
        name = str(endpoint.get("name") or endpoint.get("fqdn") or "").strip()
        if not name:
            continue
        managed = bool(endpoint.get("isManaged")) and endpoint.get("managedWithBest") is not False
        key = base_host_key(name)
        if inv.antivirus.get(key) != "géré":
            inv.antivirus[key] = "géré" if managed else "non géré"
        for ip in _ips(endpoint.get("ip")):
            pairs.append((name, ip, None))
    return pairs


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _ips(value) -> list[str]:
    values = value if isinstance(value, list) else str(value or "").replace(";", ",").split(",")
    return [v.strip() for v in values if identity.is_ip(str(v).strip())]


def gaps(inv: Inventory, now: datetime) -> dict[str, dict[str, dict]]:
    """Machines en service sans protection : {règle: {clé: {name, server, reason, sources}}}."""
    out: dict[str, dict[str, dict]] = {NO_AV_RULE: {}, NO_EDR_RULE: {}}
    for key, machine in inv.alive.items():
        base = {"name": machine.name, "server": machine.server, "sources": sorted(machine.sources)}
        if inv.antivirus is not None and inv.antivirus.get(key) != "géré":
            reason = ("non géré dans GravityZone (machine découverte, agent Bitdefender absent)"
                      if inv.antivirus.get(key) == "non géré" else "absente de GravityZone")
            out[NO_AV_RULE][key] = {**base, "reason": reason}
        # Sans EDR : établi seulement d'après une autre source que HarfangLab lui-même
        if inv.edr is not None and machine.sources - {"harfanglab"}:
            seen = inv.edr.get(key, "absent")
            if seen == "absent":
                out[NO_EDR_RULE][key] = {**base, "reason": "aucun agent HarfangLab"}
            elif seen is None or now - seen > ALIVE:
                days = f"depuis {(now - seen).days} jours" if seen else "depuis une date inconnue"
                out[NO_EDR_RULE][key] = {**base, "reason": f"agent HarfangLab muet {days}"}
    return out


# ---------- Lecture des consoles ----------


async def harfanglab_agents(client: httpx.AsyncClient) -> list[dict]:
    """Tous les agents HarfangLab (champs utiles seulement). Lève une exception si la liste est incomplète."""
    agents: list[dict] = []
    offset = 0
    for _ in range(HL_MAX_PAGES):
        response = await client.get("/api/data/endpoint/Agent/", params={
            "fields": "id,hostname,domainname,ipaddress,lastseen,status,ostype,osproducttype,osversion",
            "limit": HL_PAGE, "offset": offset,
        })
        response.raise_for_status()
        data = response.json()
        items = data.get("results", [])
        agents += items
        if len(items) < HL_PAGE or not data.get("next"):
            return agents
        offset += HL_PAGE
    raise RuntimeError("liste des agents HarfangLab trop longue : vérification de couverture interrompue")


async def gravityzone_endpoints(api) -> list[dict]:
    """Postes et machines virtuelles de GravityZone, tous groupes confondus (API Réseau, lecture seule)."""
    return await api.pages("v1.0/jsonrpc/network", "getEndpointsList", {
        "filters": {"type": {"computers": True, "virtualMachines": True}, "depth": {"allItemsRecursive": True}},
    }, 100)


# ---------- Tâche périodique ----------


class CoverageJob:
    def __init__(self, sessions, redis, store, rules, exceptions, notify) -> None:
        self.sessions, self.redis, self.store = sessions, redis, store
        self.rules, self.exceptions, self.notify = rules, exceptions, notify

    async def run(self) -> None:
        await asyncio.sleep(180)  # laisse NinjaOne faire son premier relevé
        while True:
            try:
                await self.once()
            except Exception as exc:  # noqa: BLE001
                log.error("vérification de couverture en échec : %s", exc)
            for _ in range(360):  # chaque heure, ou tout de suite sur demande
                if await self.redis.getdel(NOW_KEY):
                    break
                await asyncio.sleep(10)

    async def collect(self, cfg: dict, now: datetime) -> tuple[Inventory, list]:
        from minisoc.connectors import gravityzone, harfanglab
        from minisoc.connectors.ninjaone import POSTURE_AT_KEY, POSTURE_KEY

        inv, pairs = Inventory(), []
        posture_at = float(await self.redis.get(POSTURE_AT_KEY) or 0)
        if cfg.get("src_ninjaone_enabled", False):
            if time.time() - posture_at < POSTURE_FRESH:
                devices = [json.loads(v) for v in (await self.redis.hgetall(POSTURE_KEY)).values()]
                pairs += add_ninjaone(inv, devices, now)
            else:  # sans le relevé, des machines manqueraient : leurs alertes seraient closes à tort
                inv.complete = False
                inv.errors.append("NinjaOne : relevé de l'état du parc absent ou de plus de 3 heures")
        if harfanglab.configured(cfg):
            try:
                async with harfanglab.make_client(cfg) as client:
                    pairs += add_harfanglab(inv, await harfanglab_agents(client), now)
            except Exception as exc:  # noqa: BLE001 - liste incomplète : aucune conclusion sur l'EDR
                inv.edr = None
                inv.errors.append(f"HarfangLab : {str(exc)[:200]}")
        if gravityzone.configured(cfg) and cfg.get("src_bitdefender_enabled", False):
            try:
                async with httpx.AsyncClient(timeout=60) as http:
                    endpoints = await gravityzone_endpoints(gravityzone.GravityZoneClient(cfg, http))
                pairs += add_gravityzone(inv, endpoints)
            except Exception as exc:  # noqa: BLE001 - droits « Réseau » absents de la clé, quota… : aucune conclusion
                inv.antivirus = None
                inv.errors.append(f"GravityZone : {str(exc)[:200]} (la clé d'API doit avoir l'API Réseau)")
        return inv, pairs

    async def once(self) -> dict:
        now = datetime.now(timezone.utc)
        async with self.sessions() as session:
            cfg = await settings_store.load(session)
        inv, pairs = await self.collect(cfg, now)
        await identity.sync_hosts(self.redis, self.store, pairs)
        found = gaps(inv, now)
        report = {"at": now.isoformat(), "machines": len(inv.alive), "errors": inv.errors,
                  "antivirus_checked": inv.antivirus is not None, "edr_checked": inv.edr is not None}
        for rule_id, checked in ((NO_AV_RULE, inv.antivirus is not None), (NO_EDR_RULE, inv.edr is not None)):
            if not checked or not inv.complete or not inv.alive:
                report[rule_id] = None  # source non lue : ni alerte, ni clôture
                continue
            report[rule_id] = await self.apply(rule_id, found[rule_id], now)
        await self.redis.set(STATUS_KEY, json.dumps(report, ensure_ascii=False))
        for error in inv.errors:
            log.warning("couverture : %s", error)
        return report

    async def apply(self, rule_id: str, missing: dict[str, dict], now: datetime) -> dict:
        """Alertes pour les machines non couvertes depuis 24 h ; clôture de celles qui le sont redevenues."""
        rule = self.rules().by_id.get(rule_id)
        key = MISSING_KEY + rule_id
        since = await self.redis.hgetall(key)
        pipe = self.redis.pipeline(transaction=True)
        pipe.delete(key)
        kept = {k: since.get(k) or now.isoformat() for k in missing}
        if kept:
            pipe.hset(key, mapping=kept)
        await pipe.execute()
        raised = 0
        for host, gap in missing.items():
            first = _date(kept[host]) or now
            values = {"host.name": gap["name"], "threat.name": gap["reason"]}
            if rule is None or now - first < GRACE or self.exceptions.is_excepted(rule_id, values):
                continue
            entity = entity_key(rule.group_by, values)
            async with self.sessions() as session:
                # Alerte clôturée par la DSI depuis le début de ce manque : pas recréée tant que la machine n'a pas
                # été couverte puis de nouveau découverte sans protection
                closed = await _last_closed(session, rule_id, entity)
                if closed and _aware(closed.last_seen) >= first:
                    continue
                _, action = await upsert_alert(session, Detection(
                    rule=rule, entity_key=entity,
                    severity=3 if gap["server"] else rule.severity_level,
                    title=render_title(rule.title, values), first_seen=first, last_seen=now,
                    accumulate=False, modules=gap["sources"],
                    details={"category": rule.category, "sample": values,
                             "coverage": {"reason": gap["reason"], "seen_by": gap["sources"],
                                          "server": gap["server"], "since": first.isoformat()}},
                ))
                await session.commit()
            if action == "created":
                raised += 1
        if raised:
            self.notify()
        resolved = await self.resolve_covered(rule_id, set(missing))
        return {"missing": len(missing), "raised": raised, "resolved": resolved}

    async def resolve_covered(self, rule_id: str, missing: set[str]) -> int:
        from minisoc.detections import entity_parts

        closed = 0
        async with self.sessions() as session:
            alerts = (await session.scalars(select(Alert).where(
                Alert.rule_id == rule_id, Alert.status.in_(OPEN_STATUSES)).with_for_update())).all()
            what = "l'antivirus Bitdefender" if rule_id == NO_AV_RULE else "l'EDR HarfangLab"
            for alert in alerts:
                if (alert.details or {}).get("storm"):  # regroupement : les machines couvertes en sortent
                    entities = (alert.details or {}).get("entities") or {}
                    left = {e: n for e, n in entities.items()
                            if base_host_key(entity_parts(e).get("host.name", "")) in missing}
                    if left:
                        if len(left) != len(entities):
                            alert.details = {**alert.details, "entities": left}
                            alert.metric = len(left)
                            alert.title = f"{alert.rule_name} : {len(left)} entités regroupées (anti-tempête)"
                        continue
                    host = f"{len(entities)} machines"
                else:
                    host = entity_parts(alert.entity_key).get("host.name", "")
                    if not host or base_host_key(host) in missing:
                        continue
                alert.status, alert.notify_pending = "resolved", False
                session.add(AlertHistory(alert_id=alert.id, actor=SYSTEM, action="status", detail="resolved"))
                session.add(AlertHistory(alert_id=alert.id, actor=SYSTEM, action="comment", detail=(
                    f"{host} : de nouveau protégée(s) par {what}, ou plus en service (aucun contact depuis "
                    "7 jours). Clôture automatique.")))
                closed += 1
            await session.commit()
        return closed


async def status(redis) -> dict | None:
    raw = await redis.get(STATUS_KEY)
    return json.loads(raw) if raw else None
