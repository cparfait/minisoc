"""Synchronisation des statuts avec les outils d'origine.

Une alerte traitée dans l'outil qui l'a émise est clôturée dans le Mini-SOC :
- HarfangLab : alerte passée en « faux positif », « faux positif probable » ou « clôturée » (ou supprimée) ;
- NinjaOne : alerte réinitialisée (absente des alertes actives), problème de posture résolu (antivirus réactivé,
  menace traitée, vulnérabilités critiques corrigées, correctifs réinstallés) ;
- Cyberwatch : CVE signalées corrigées ou ignorées, système d'exploitation mis à niveau ;
- Varonis SaaS : alerte fermée dans Varonis (motif « activité légitime » : faux positif) ;
- GravityZone : incident clôturé ou classé faux positif (les fichiers mis en quarantaine restent à clôturer ici).

Rien n'est supprimé : l'historique de l'alerte garde la trace (outil, statut, auteur et date quand l'outil les
fournit), le journal d'audit aussi, et `details.source_closure` la résume pour l'affichage.

Garde-fous :
- seules les alertes issues d'un seul outil sont concernées (une corrélation entre plusieurs sources reste à
  clôturer à la main) ;
- une alerte qui regroupe plusieurs alertes de l'outil n'est clôturée que lorsque toutes le sont ;
- les alertes d'origine sont relevées avant la liste des alertes ouvertes de l'outil : une alerte arrivée entre
  les deux n'est jamais prise pour clôturée ; le statut de la plus récente est en plus relu un par un ;
- en cas d'erreur de lecture ou de liste incomplète, rien n'est clôturé ;
- l'alerte est relue (verrouillée) juste avant sa clôture : si une nouvelle détection est arrivée entre-temps,
  elle reste ouverte.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

import httpx
import redis.asyncio as aioredis
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from minisoc import audit
from minisoc.connectors import cyberwatch as cw
from minisoc.connectors import gravityzone as gz
from minisoc.connectors import harfanglab as hl
from minisoc.connectors import ninjaone as ninja
from minisoc.connectors import varonis as vr
from minisoc.ecs import FIELDS
from minisoc.models import OPEN_STATUSES, Alert, AlertHistory
from minisoc.parsers.harfanglab import STATUS_FR as HL_STATUS_FR
from minisoc.settings_store import store as settings_store

log = logging.getLogger(__name__)

SYNC_SECONDS = 300
MAX_SOURCE_EVENTS = 5000
MAX_ENTITIES = 500
ACTIVE_MAX_AGE = 15 * 60  # liste des alertes actives NinjaOne plus ancienne : pas de synchronisation
POSTURE_MAX_AGE = 3 * 3600
CYBERWATCH_MAX_AGE = 2 * 3600  # relevé Cyberwatch plus ancien : pas de synchronisation
HL_REFERENCE = re.compile(r"/security-event/([^/?#]+)")
HL_FALSE_POSITIVE = {"false_positive", "probable_false_positive"}
TZ = ZoneInfo("Europe/Paris")

POSTURE_LABEL = {
    "antivirus_inactive": "antivirus de nouveau actif",
    "antivirus_outdated": "définitions antivirus à jour",
    "active_threat": "plus aucune menace active",
    "critical_vulnerabilities": "plus de vulnérabilité critique",
    "patches_failed": "plus de correctif en échec",
}
# Changements de posture publiés en événements simples (pas en « alertes ») : relus pour la synchronisation
NINJA_POSTURE_ACTIONS = ("antivirus_disabled", "antivirus_outdated", "active_threat", "critical_vulnerabilities",
                         "patches_failed")
CYBERWATCH_RULE_KINDS = {"UC-48": "kev_vulnerabilities", "UC-49": "prioritized_vulnerabilities",
                         "UC-50": "os_end_of_life"}


@dataclass
class Closure:
    tool: str  # outil d'origine, ex. « HarfangLab »
    status: str  # statut Mini-SOC : resolved ou false_positive
    label: str  # état dans l'outil, en clair
    by: str = ""  # auteur dans l'outil, s'il est connu
    at: str = ""  # date du changement dans l'outil (ISO 8601), sinon date du constat
    observed: bool = False  # True : date du constat par le Mini-SOC (l'outil ne date pas le changement)
    sources: int = 1  # nombre d'alertes de l'outil derrière l'alerte du Mini-SOC

    def text(self) -> str:
        msg = f"Clôturée dans {self.tool} : {self.label}"
        if self.by:
            msg += f", par {self.by}"
        if self.at:
            msg += (", constaté le " if self.observed else ", le ") + _fr(self.at)
        if self.sources > 1:
            msg += f" ({self.sources} alertes {self.tool}, toutes traitées)"
        return msg + ". Alerte clôturée automatiquement par synchronisation, sans suppression."


def _fr(iso: str) -> str:
    try:
        value = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return iso
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(TZ).strftime("%d/%m/%Y %H:%M")


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------- Décisions (sans entrée/sortie, testées unitairement) ----------


def harfanglab_closure(detail: dict | None, sources: int) -> Closure | None:
    """Clôture d'après le statut HarfangLab de l'alerte la plus récente ; None si elle est encore à traiter."""
    if detail is None:
        return Closure(
            "HarfangLab", "resolved", "alerte supprimée de la console", at=_now_iso(), observed=True, sources=sources
        )
    status = str(detail.get("status") or "")
    if not status or status in hl.OPEN_STATUSES:
        return None
    change = next((h for h in reversed(detail.get("status_history") or []) if h.get("to_status") == status), {})
    return Closure(
        "HarfangLab",
        "false_positive" if status in HL_FALSE_POSITIVE else "resolved",
        HL_STATUS_FR.get(status, status),
        by=str(change.get("username") or ""),
        at=str(change.get("timestamp") or ""),
        sources=sources,
    )


def posture_resolved(kind: str, state: dict | None) -> bool:
    """Le problème de posture signalé (kind) a-t-il disparu de l'état actuel du poste ?"""
    if not state:
        return False  # poste absent du dernier relevé : on ne conclut pas
    if kind == "antivirus_inactive":
        return state.get("antivirus") in ("ok", "outdated")
    if kind == "antivirus_outdated":
        return state.get("antivirus") == "ok"
    if kind == "active_threat":
        return int(state.get("threats") or 0) == 0
    if kind == "critical_vulnerabilities":
        return int(state.get("critical") or 0) == 0
    if kind == "patches_failed":
        return int(state.get("failed") or 0) == 0
    return False


def ninjaone_closure(records: list[dict], active: set[str] | None, posture: dict[str, dict] | None) -> Closure | None:
    """records : alertes NinjaOne d'origine (JSON publiés par le connecteur). Toutes doivent être traitées."""
    if not records:
        return None
    if all(r.get("type") == "alert" for r in records):
        if active is None:
            return None
        keys = {ninja.alert_key(r.get("alert") or {}) for r in records}
        if keys & active:
            return None
        return Closure(
            "NinjaOne",
            "resolved",
            "alerte réinitialisée (plus active)",
            at=_now_iso(),
            observed=True,
            sources=len(keys),
        )
    if all(r.get("type") == "posture" for r in records):
        if posture is None:
            return None
        if not all(posture_resolved(str(r.get("kind")), posture.get(str(r.get("device_id")))) for r in records):
            return None
        labels = sorted({POSTURE_LABEL.get(str(r.get("kind")), "problème résolu") for r in records})
        return Closure("NinjaOne", "resolved", ", ".join(labels), at=_now_iso(), observed=True, sources=len(records))
    return None  # mélange d'alertes et de posture : à traiter à la main


def cyberwatch_closure(records: list[dict], kind: str | None, states: dict[str, dict] | None) -> Closure | None:
    """records : changements publiés par le connecteur ; kind : changement suivi par la règle de l'alerte ;
    states : état actuel des actifs (identifiant -> état). Toutes les CVE signalées doivent avoir disparu."""
    if not kind or states is None:
        return None
    records = [r for r in records if r.get("type") == "posture" and r.get("kind") == kind]
    if not records:
        return None
    fixed, ignored = set(), set()
    for record in records:
        state = states.get(str(record.get("asset_id")))
        if not state or "cves" not in state:
            return None  # actif absent du dernier relevé, ou CVE pas encore relues : on ne conclut pas
        if kind == "os_end_of_life":
            if state.get("eol_passed"):
                return None
            continue
        for cve in record.get("cves") or []:
            if cve in state["cves"]:
                return None
            (ignored if cve in (state.get("ignored") or []) else fixed).add(cve)
    if kind == "os_end_of_life":
        os = next((s.get("os") for r in records if (s := states.get(str(r.get("asset_id"))))), "")
        return Closure("Cyberwatch", "resolved", f"système mis à niveau ({os})" if os else "système mis à niveau",
                       at=_now_iso(), observed=True, sources=len(records))
    parts = []
    if fixed:
        parts.append(f"{len(fixed)} CVE corrigée(s)")
    if ignored:
        listed = ", ".join(sorted(ignored)[:5])
        parts.append(f"{len(ignored)} CVE ignorée(s) dans Cyberwatch (risque accepté) : {listed}")
    label = ", ".join(parts) or "CVE plus présentes"
    return Closure("Cyberwatch", "resolved", label, at=_now_iso(), observed=True, sources=len(records))


def varonis_ids(records: list[dict]) -> list[str]:
    """Identifiants des alertes Varonis d'origine ([] si l'une n'est pas identifiable : pas de conclusion)."""
    ids = [str(((r.get("alert") or {}).get("Alert.ID")) or "") for r in records]
    return [] if not ids or not all(ids) else list(dict.fromkeys(ids))


def varonis_closure(ids: list[str], found: dict[str, dict]) -> Closure | None:
    """found : alertes relues dans Varonis (identifiant → ligne). Toutes doivent être fermées."""
    if not ids or any(i not in found for i in ids):
        return None
    closures = [vr.closure_of(found[i]) for i in ids]
    if any(c is None for c in closures):
        return None
    status = "false_positive" if all(c[0] == "false_positive" for c in closures) else "resolved"
    labels = sorted({c[1] for c in closures})
    return Closure("Varonis", status, ", ".join(labels), at=_now_iso(), observed=True, sources=len(ids))


def gravityzone_ids(records: list[dict]) -> list[str]:
    """Incidents GravityZone d'origine ([] si l'alerte contient autre chose : quarantaine, événement Push…)."""
    ids = [str(r.get("incident_id") or "") for r in records]
    if not ids or not all(ids) or any(r.get("module") != "new-incident" for r in records):
        return []
    return list(dict.fromkeys(ids))


def gravityzone_closure(ids: list[str], statuses: dict[str, str]) -> Closure | None:
    if not ids or any(statuses.get(i) not in gz.CLOSED for i in ids):
        return None
    status = "false_positive" if all(statuses[i] == "false_positive" for i in ids) else "resolved"
    labels = sorted({gz.CLOSED[statuses[i]] for i in ids})
    return Closure("GravityZone", status, ", ".join(labels), at=_now_iso(), observed=True, sources=len(ids))


# ---------- Accès aux données ----------


def _parts(entity_key: str) -> dict[str, str]:
    out = {}
    for part in entity_key.split(" | "):
        name, sep, value = part.partition("=")
        if sep:
            out[name.strip()] = value.strip()
    return out


def _naive(value: datetime) -> datetime:
    return (value if value.tzinfo is None else value.astimezone(timezone.utc)).replace(tzinfo=None)


async def open_alerts(session: AsyncSession, module: str) -> list[Alert]:
    """Alertes ouvertes issues de ce seul outil."""
    rows = await session.scalars(
        select(Alert).where(
            Alert.status.in_(OPEN_STATUSES),
            Alert.modules.contains([module]),
            func.jsonb_array_length(Alert.modules) == 1,
        )
    )
    return list(rows.all())


async def source_rows(store, alert: Alert, module: str, actions: tuple[str, ...] = ()) -> list[dict] | None:
    """Alertes d'origine (événements de type alerte, ou de l'une des actions données) derrière une alerte du
    Mini-SOC, de la plus récente à la plus ancienne. None si la liste est incomplète ou introuvable : pas de clôture
    dans ce cas."""
    details = alert.details or {}
    entities = list((details.get("entities") or {}).keys()) if details.get("storm") else [alert.entity_key]
    params: dict[str, object] = {
        "module": module,
        "start": _naive(alert.first_seen) - timedelta(seconds=1),
        "end": _naive(alert.last_seen) + timedelta(seconds=1),
    }
    clauses = []
    for i, entity in enumerate(entities[:MAX_ENTITIES]):
        conditions = [(FIELDS[f], v) for f, v in _parts(entity).items() if f in FIELDS and f != "event.module"]
        if not conditions:
            continue
        for j, (_, value) in enumerate(conditions):
            params[f"e{i}_{j}"] = value
        clauses.append(
            "(" + " AND ".join(f"{column} = {{e{i}_{j}:String}}" for j, (column, _) in enumerate(conditions)) + ")"
        )
    if not clauses:
        return None
    kind = "kind = 'alert'"
    if actions:
        params["actions"] = list(actions)
        kind = "(kind = 'alert' OR action IN {actions:Array(String)})"
    rows = await store.query(
        "SELECT ts, reference, if(module = 'harfanglab', JSONExtractString(raw, 'id'), raw) AS source "
        f"FROM events WHERE module = {{module:String}} AND {kind} "
        "AND ts BETWEEN {start:DateTime64(3)} AND {end:DateTime64(3)} "
        f"AND ({' OR '.join(clauses)}) ORDER BY ts DESC LIMIT {MAX_SOURCE_EVENTS}",
        params,
    )
    if not rows or len(rows) >= MAX_SOURCE_EVENTS:
        return None
    return rows


def harfanglab_ids(rows: list[dict]) -> list[str]:
    """Identifiants HarfangLab, du plus récent au plus ancien (lien vers la console, sinon contenu brut)."""
    ids = []
    for row in rows:
        match = HL_REFERENCE.search(str(row.get("reference") or ""))
        alert_id = match.group(1) if match else str(row.get("source") or "")
        if not alert_id:
            return []  # une alerte d'origine non identifiable : on ne peut pas conclure
        ids.append(alert_id)
    return list(dict.fromkeys(ids))


async def close(session: AsyncSession, alert_id: int, last_seen: datetime, closure: Closure) -> bool:
    """Clôture tracée (historique, audit, details.source_closure), si l'alerte n'a pas bougé entre-temps."""
    alert = await session.get(Alert, alert_id, with_for_update=True, populate_existing=True)
    if alert is None or alert.status not in OPEN_STATUSES or alert.last_seen != last_seen:
        await session.rollback()
        return False
    actor = f"{closure.tool} (synchro)"
    previous = alert.status
    alert.status = closure.status
    alert.notify_pending = False
    alert.details = {**(alert.details or {}), "source_closure": {**asdict(closure), "synced_at": _now_iso()}}
    session.add(AlertHistory(alert_id=alert.id, actor=actor, action="status", detail=closure.status))
    session.add(AlertHistory(alert_id=alert.id, actor=actor, action="comment", detail=closure.text()))
    await audit.record(
        session,
        actor=actor,
        action="alert_source_closed",
        obj=f"alert:{alert.id}",
        detail={"previous_status": previous, **asdict(closure)},
    )
    await session.commit()
    return True


# ---------- Synchronisation par outil ----------


async def sync_harfanglab(session: AsyncSession, store, cfg: dict) -> int:
    alerts = await open_alerts(session, "harfanglab")
    sources: dict[int, tuple[list[str], datetime]] = {}
    for alert in alerts:  # 1. alertes d'origine, avant la liste des ouvertes (voir garde-fous)
        rows = await source_rows(store, alert, "harfanglab")
        ids = harfanglab_ids(rows) if rows else []
        if ids:
            sources[alert.id] = (ids, alert.last_seen)
    await session.commit()  # aucune écriture : fin de la transaction de lecture
    if not sources:
        return 0
    previous = {a.id: (a.details or {}).get("tool_state") or {} for a in alerts}
    closed = lookups = 0
    async with hl.make_client(cfg) as client:
        still_open = await hl.open_alert_ids(client)  # 2. liste complète, sinon exception
        for alert_id, (ids, last_seen) in sources.items():
            open_ids = [i for i in ids if i in still_open]
            if open_ids:  # encore à traiter dans l'outil : on note seulement son état (lecture seule)
                state = tool_state(open_ids, still_open, len(ids))
                if state["status"] == previous.get(alert_id, {}).get("status"):
                    continue
                if state["status"] == "investigating" and lookups < MAX_STATE_LOOKUPS:
                    lookups += 1
                    investigating = next(i for i in open_ids if still_open[i] == "investigating")
                    state.update(status_change(await hl.alert_status(client, investigating), "investigating"))
                await set_tool_state(session, alert_id, state, announce=bool(previous.get(alert_id)))
                continue
            closure = harfanglab_closure(await hl.alert_status(client, ids[0]), len(ids))  # 3. vérification
            if closure and await close(session, alert_id, last_seen, closure):
                closed += 1
    return closed


MAX_STATE_LOOKUPS = 50  # lectures détaillées (auteur, date) par passage


def tool_state(open_ids: list[str], statuses: dict[str, str], total: int) -> dict:
    """État HarfangLab d'une alerte encore ouverte dans l'outil : « en investigation » dès qu'une de ses alertes
    d'origine l'est, sinon « nouvelle »."""
    status = "investigating" if any(statuses.get(i) == "investigating" for i in open_ids) else "new"
    return {
        "tool": "HarfangLab",
        "status": status,
        "label": HL_STATUS_FR.get(status, status),
        "by": "",
        "at": "",
        "open": len(open_ids),
        "total": total,
    }


def status_change(detail: dict | None, status: str) -> dict:
    """Auteur et date du dernier passage au statut donné (historique HarfangLab)."""
    if not detail:
        return {}
    change = next((h for h in reversed(detail.get("status_history") or []) if h.get("to_status") == status), {})
    return {"by": str(change.get("username") or ""), "at": str(change.get("timestamp") or "")}


async def set_tool_state(session: AsyncSession, alert_id: int, state: dict, announce: bool) -> None:
    alert = await session.get(Alert, alert_id, with_for_update=True, populate_existing=True)
    if alert is None or alert.status not in OPEN_STATUSES:
        await session.rollback()
        return
    alert.details = {**(alert.details or {}), "tool_state": {**state, "checked_at": _now_iso()}}
    if announce:  # changement d'état dans l'outil : tracé dans l'historique de l'alerte
        who = f" par {state['by']}" if state.get("by") else ""
        session.add(
            AlertHistory(
                alert_id=alert.id,
                actor=f"{state['tool']} (lecture)",
                action="comment",
                detail=f"Dans {state['tool']} : {state['label']}{who}.",
            )
        )
    await session.commit()


async def sync_ninjaone(session: AsyncSession, store, redis: aioredis.Redis) -> int:
    now = time.time()
    active_raw = json.loads(await redis.get(ninja.ACTIVE_KEY) or "null")
    active = set(active_raw["keys"]) if active_raw and now - float(active_raw["at"]) <= ACTIVE_MAX_AGE else None
    posture_at = float(await redis.get(ninja.POSTURE_AT_KEY) or 0)
    posture = None
    if now - posture_at <= POSTURE_MAX_AGE:
        posture = {k: json.loads(v) for k, v in (await redis.hgetall(ninja.POSTURE_KEY)).items()}
    if active is None and posture is None:
        return 0
    candidates = []
    for alert in await open_alerts(session, "ninjaone"):
        rows = await source_rows(store, alert, "ninjaone", NINJA_POSTURE_ACTIONS)
        try:
            records = [json.loads(r["source"]) for r in rows or []]
        except ValueError:
            continue  # contenu d'origine illisible : on ne conclut pas
        closure = ninjaone_closure(records, active, posture)
        if closure:
            candidates.append((alert.id, alert.last_seen, closure))
    await session.commit()
    closed = 0
    for alert_id, last_seen, closure in candidates:
        if await close(session, alert_id, last_seen, closure):
            closed += 1
    return closed


async def sync_cyberwatch(session: AsyncSession, store, redis: aioredis.Redis) -> int:
    if time.time() - float(await redis.get(cw.STATE_AT_KEY) or 0) > CYBERWATCH_MAX_AGE:
        return 0
    states = cw.load_states(await redis.hgetall(cw.STATE_KEY))
    candidates = []
    for alert in await open_alerts(session, "cyberwatch"):
        kind = CYBERWATCH_RULE_KINDS.get(alert.rule_id)
        if not kind:
            continue
        rows = await source_rows(store, alert, "cyberwatch", (kind,))
        try:
            records = [json.loads(r["source"]) for r in rows or []]
        except ValueError:
            continue
        closure = cyberwatch_closure(records, kind, states)
        if closure:
            candidates.append((alert.id, alert.last_seen, closure))
    await session.commit()
    closed = 0
    for alert_id, last_seen, closure in candidates:
        if await close(session, alert_id, last_seen, closure):
            closed += 1
    return closed


async def _records(store, alert: Alert, module: str) -> list[dict] | None:
    rows = await source_rows(store, alert, module)
    try:
        return [json.loads(r["source"]) for r in rows] if rows else None
    except ValueError:
        return None


async def sync_varonis(session: AsyncSession, store, cfg: dict) -> int:
    alerts = await open_alerts(session, "varonis")
    sources = {}
    for alert in alerts:
        records = await _records(store, alert, "varonis")
        # Alertes lues par l'API seulement (une alerte reçue en syslog n'a pas d'identifiant Varonis exploitable)
        ids = varonis_ids(records) if records and all(r.get("type") == "alert" for r in records) else []
        if ids:
            sources[alert.id] = (ids, alert.last_seen)
    await session.commit()
    if not sources:
        return 0
    previous = {a.id: (a.details or {}).get("tool_state") or {} for a in alerts}
    closed = 0
    async with vr.make_http(cfg) as http:
        api = vr.VaronisClient(cfg, http)
        wanted = sorted({i for ids, _ in sources.values() for i in ids})
        found: dict[str, dict] = {}
        for start in range(0, len(wanted), 100):
            for row in await api.alerts_by_ids(wanted[start : start + 100]):
                found[str(row.get("Alert.ID"))] = row
    for alert_id, (ids, last_seen) in sources.items():
        closure = varonis_closure(ids, found)
        if closure:
            if await close(session, alert_id, last_seen, closure):
                closed += 1
            continue
        statuses = {str(found[i].get("Alert.Status.Name") or "").strip().lower() for i in ids if i in found}
        status = "under investigation" if "under investigation" in statuses else "new"
        if statuses and status != previous.get(alert_id, {}).get("status"):
            state = {"tool": "Varonis", "status": status, "label": vr.STATUS_FR.get(status, status), "by": "",
                     "at": "", "open": len(ids), "total": len(ids)}
            await set_tool_state(session, alert_id, state, announce=bool(previous.get(alert_id)))
    return closed


async def sync_gravityzone(session: AsyncSession, store, cfg: dict) -> int:
    alerts = await open_alerts(session, "bitdefender")
    sources = {}
    for alert in alerts:
        records = await _records(store, alert, "bitdefender")
        ids = gravityzone_ids(records) if records else []
        if ids:
            sources[alert.id] = (ids, alert.last_seen)
    await session.commit()
    if not sources:
        return 0
    previous = {a.id: (a.details or {}).get("tool_state") or {} for a in alerts}
    async with httpx.AsyncClient(timeout=60) as http:
        api = gz.GravityZoneClient(cfg, http)
        wanted = sorted({i for ids, _ in sources.values() for i in ids})
        statuses = {str(i.get("incidentId")): str(i.get("status") or "") for i in await api.incidents_by_ids(wanted)}
    closed = 0
    for alert_id, (ids, last_seen) in sources.items():
        closure = gravityzone_closure(ids, statuses)
        if closure:
            if await close(session, alert_id, last_seen, closure):
                closed += 1
            continue
        status = "in_progress" if any(statuses.get(i) == "in_progress" for i in ids) else "open"
        if any(i in statuses for i in ids) and status != previous.get(alert_id, {}).get("status"):
            state = {"tool": "GravityZone", "status": status, "label": gz.STATUS_FR[status], "by": "", "at": "",
                     "open": len(ids), "total": len(ids)}
            await set_tool_state(session, alert_id, state, announce=bool(previous.get(alert_id)))
    return closed


class SourceStatusSync:
    """Toutes les 5 minutes : clôture dans le Mini-SOC de ce qui a été traité dans l'outil d'origine."""

    def __init__(self, sessions: async_sessionmaker, redis: aioredis.Redis, store) -> None:
        self.sessions = sessions
        self.redis = redis
        self.store = store

    async def run(self) -> None:
        while True:
            await self.once()
            await asyncio.sleep(SYNC_SECONDS)

    async def once(self) -> dict[str, int]:
        result: dict[str, int] = {}
        async with self.sessions() as session:
            cfg = await settings_store.load(session)
            if hl.configured(cfg) and cfg.get("harfanglab_sync_status", True):
                try:
                    result["harfanglab"] = await sync_harfanglab(session, self.store, cfg)
                except Exception as exc:  # noqa: BLE001
                    await session.rollback()
                    log.error("Synchronisation HarfangLab interrompue, rien n'est clôturé : %s", exc)
            if (
                ninja.configured(cfg)
                and cfg.get("src_ninjaone_enabled", False)
                and cfg.get("ninjaone_sync_status", True)
            ):
                try:
                    result["ninjaone"] = await sync_ninjaone(session, self.store, self.redis)
                except Exception as exc:  # noqa: BLE001
                    await session.rollback()
                    log.error("Synchronisation NinjaOne interrompue : %s", exc)
            for tool, ready, run in (
                ("varonis", vr.configured(cfg) and cfg.get("varonis_sync_status", True), sync_varonis),
                ("gravityzone", gz.configured(cfg) and cfg.get("bitdefender_sync_status", True), sync_gravityzone),
            ):
                if ready:
                    try:
                        result[tool] = await run(session, self.store, cfg)
                    except Exception as exc:  # noqa: BLE001
                        await session.rollback()
                        log.error("Synchronisation %s interrompue, rien n'est clôturé : %s", tool, exc)
            if (
                cw.configured(cfg)
                and cfg.get("src_cyberwatch_enabled", False)
                and cfg.get("cyberwatch_sync_status", True)
            ):
                try:
                    result["cyberwatch"] = await sync_cyberwatch(session, self.store, self.redis)
                except Exception as exc:  # noqa: BLE001
                    await session.rollback()
                    log.error("Synchronisation Cyberwatch interrompue : %s", exc)
        for tool, count in result.items():
            if count:
                log.info("%s : %d alerte(s) clôturée(s) d'après l'outil", tool, count)
        return result
