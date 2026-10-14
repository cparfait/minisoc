"""Cyberwatch (gestion des vulnérabilités) : CVE présentes sur chaque actif, en lecture seule.

API v3 de Cyberwatch (https://docs.cyberwatch.com/help/fr/API_documentation/) : authentification Basic avec l'ID et
le secret d'une clé d'API (Mon profil › Clés d'API), pagination `page` / `per_page` (en-tête `X-Total`). Le
connecteur n'utilise que des lectures (GET) :
- /api/v3/ping : test de connexion ;
- /api/v3/vulnerabilities/servers : liste des actifs et compteurs (CVE, CVE prioritaires, redémarrage requis…) ;
- /api/v3/vulnerabilities/servers/{id} : CVE de l'actif (prioritaire, ignorée, corrigée, score, EPSS), relue
  seulement quand l'actif a été réanalysé ou que ses compteurs ont changé.

Contrairement à NinjaOne, Cyberwatch donne les numéros de CVE par actif : ils sont croisés avec le catalogue CISA KEV
(vulnérabilités activement exploitées). Toutes les 30 minutes, seuls les changements produisent des événements :
- nouvelle faille KEV présente sur un actif (UC-48) ;
- nouvelles vulnérabilités jugées prioritaires par Cyberwatch, sur les serveurs (UC-49 ; sur un parc réel, des
  centaines par serveur et une vague à chaque « Patch Tuesday » : les postes restent dans la synthèse) ;
- système d'exploitation arrivé en fin de support (UC-50).
Le premier relevé est un état des lieux sans alerte (des dizaines de failles connues, pas des nouveautés) : page Veille,
classement « Machines à corriger en premier » et recherche par CVE. Les CVE que la DSI a triées comme ignorées ou
acceptées dans Cyberwatch (`triage_status`) ne comptent plus comme présentes.
"""

from __future__ import annotations

import asyncio
import json
import logging
import ssl
import time
from datetime import datetime, timezone

import httpx
import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import async_sessionmaker

from minisoc import bus
from minisoc.settings_store import store as settings_store
from minisoc.threat_feeds import KEV_KEY

log = logging.getLogger(__name__)

MODULE = "cyberwatch"
STATE_KEY = "minisoc:cyberwatch:assets"  # hash identifiant d'actif -> état (JSON)
STATE_AT_KEY = "minisoc:cyberwatch:state_at"  # horodatage du dernier relevé complet
SUMMARY_KEY = "minisoc:cyberwatch:summary"  # synthèse pour la page Veille
POLL_SECONDS = 1800
CHECK_SECONDS = 60  # configuration relue chaque minute : un raccordement est pris en compte aussitôt
PER_PAGE = 500
MAX_PAGES = 100  # 50 000 actifs
DETAILS_PER_PASS = 400  # au-delà, la suite au passage suivant (ménage l'instance)
TOP_CVES = 10
MAX_PATCHES = 40  # correctifs conservés par actif (les plus utiles d'abord)


class CyberwatchError(RuntimeError):
    pass


def base_url(cfg: dict) -> str:
    return str(cfg.get("cyberwatch_url") or "").strip().rstrip("/")


def configured(cfg: dict) -> bool:
    return bool(base_url(cfg) and cfg.get("cyberwatch_access_key") and cfg.get("cyberwatch_secret_key"))


def tls(cfg: dict) -> ssl.SSLContext | bool:
    if not cfg.get("cyberwatch_verify_tls", True):
        return False
    return ssl.create_default_context(cadata=cfg.get("cyberwatch_ca_cert") or None)


def make_client(cfg: dict) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=base_url(cfg),
        auth=(str(cfg["cyberwatch_access_key"]), str(cfg["cyberwatch_secret_key"])),
        headers={"Accept": "application/json; charset=utf-8"},
        verify=tls(cfg),
        timeout=60,
    )


def console_url(cfg: dict, asset_id) -> str:
    """Fiche de l'actif dans l'interface Cyberwatch."""
    return f"{base_url(cfg)}/servers/{int(asset_id)}" if asset_id and base_url(cfg) else ""


async def get(client: httpx.AsyncClient, path: str, params: dict | None = None) -> httpx.Response:
    response = await client.get(path, params=params or {})
    if response.status_code == 401:
        raise CyberwatchError("clé d'API Cyberwatch refusée (ID ou secret de la clé)")
    if response.status_code == 403:
        raise CyberwatchError("droits insuffisants pour la clé d'API Cyberwatch")
    response.raise_for_status()
    return response


async def pages(client: httpx.AsyncClient, path: str) -> list[dict]:
    """Toutes les pages d'une liste ; erreur si la liste n'a pas pu être lue en entier (rien n'est conclu)."""
    rows: list[dict] = []
    for page in range(1, MAX_PAGES + 1):
        response = await get(client, path, {"page": page, "per_page": PER_PAGE})
        batch = response.json() or []
        rows += batch
        total = response.headers.get("x-total")
        if not batch or len(batch) < PER_PAGE or (total and len(rows) >= int(total)):
            return rows
    raise CyberwatchError(f"{path} : plus de {MAX_PAGES * PER_PAGE} éléments, lecture interrompue")


# ---------- État d'un actif ----------


def _os(item: dict) -> dict:
    return item.get("os") if isinstance(item.get("os"), dict) else {}


def _date(value) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def is_server(item: dict) -> bool:
    name = str(_os(item).get("name") or "").lower()
    if "windows" in name:
        return "server" in name
    return str(item.get("category") or "") in ("server", "hypervisor", "network_device", "network_target_or_website")


def _addresses(item: dict) -> list[str]:
    out = []
    for a in item.get("addresses") or []:
        value = a.get("value") or a.get("address") if isinstance(a, dict) else a
        if value:
            out.append(str(value))
    return out


def asset_state(cfg: dict, item: dict, now: datetime) -> dict:
    """Résumé d'un actif d'après la liste (sans ses CVE)."""
    os = _os(item)
    eol = _date(os.get("eol"))
    return {
        "id": str(item.get("id")),
        "name": str(item.get("hostname") or item.get("id")),
        "server": is_server(item),
        "category": str(item.get("category") or ""),
        "os": str(os.get("name") or ""),
        "eol": eol.date().isoformat() if eol else "",
        "eol_passed": bool(eol and eol < now),
        "ip": (_addresses(item) or [""])[0],
        "status": str(item.get("status") or ""),
        "cve_count": int(item.get("cve_announcements_count") or 0),
        "prioritized_count": int(item.get("prioritized_cve_announcements_count") or 0),
        "reboot_required": bool(item.get("reboot_required")),
        "last_communication": str(item.get("last_communication") or ""),
        "analyzed_at": str(item.get("analyzed_at") or ""),
        "groups": [str(g.get("name")) for g in item.get("groups") or [] if isinstance(g, dict) and g.get("name")],
        "console": console_url(cfg, item.get("id")),
    }


def triaged_out(cve: dict) -> bool:
    """CVE écartée par la DSI dans Cyberwatch : ignorée (anciennes versions) ou triée comme ignorée, risque accepté,
    faux positif, non concernée (versions récentes : `triage_status`, « untriaged » par défaut)."""
    if cve.get("ignored"):
        return True
    status = str(cve.get("triage_status") or "").lower()
    return any(word in status for word in ("ignor", "accept", "false", "not_"))


def active_cves(detail: dict) -> tuple[dict[str, list], list[str]]:
    """CVE présentes (ni corrigées ni écartées) : code -> [score, epss, prioritaire] ; et CVE écartées. Le détail
    d'un actif contient aussi l'historique des CVE corrigées (`active` faux, `fixed_at` renseigné)."""
    active, ignored = {}, []
    for cve in detail.get("cve_announcements") or []:
        code = str(cve.get("cve_code") or "").upper()
        if not code:
            continue
        if cve.get("fixed_at") or cve.get("active") is False:
            continue
        if triaged_out(cve):
            ignored.append(code)
            continue
        score = cve.get("score")
        epss = cve.get("epss")
        active[code] = [
            float(score) if isinstance(score, (int, float)) else None,
            float(epss) if isinstance(epss, (int, float)) else None,
            1 if cve.get("prioritized") else 0,
        ]
    return active, sorted(ignored)


def _package(side) -> tuple[str, str]:
    """Nom lisible et version d'un paquet, d'une application ou d'une KB (côté installé ou corrigé)."""
    side = side if isinstance(side, dict) else {}
    name = side.get("title") or " ".join(str(x) for x in (side.get("vendor"), side.get("product")) if x)
    version = str(side.get("version") or "").replace("^", "").rstrip(".")
    return str(name or ""), version


def pending_updates(detail: dict, active: dict) -> list[dict]:
    """Correctifs proposés par Cyberwatch : produit (paquet, application, KB), version installée → version qui corrige,
    et CVE présentes qu'il corrige. Les correctifs ignorés dans Cyberwatch sont écartés."""
    out = []
    for update in detail.get("updates") or []:
        if not isinstance(update, dict) or update.get("ignored"):
            continue
        name, current = _package(update.get("current"))
        target_name, target = _package(update.get("target"))
        codes = {
            str(c.get("cve_code") if isinstance(c, dict) else c or "").upper()
            for c in update.get("cve_announcements") or []
        }
        out.append({
            "product": name or target_name or "?",
            "from": current,
            "to": target,
            "patchable": bool(update.get("patchable")),
            "cves": sorted(codes & set(active)),
        })
    return out


def patches(state: dict, kev: set[str]) -> list[dict]:
    """Correctifs classés : failles KEV corrigées, puis prioritaires, puis score, puis nombre de CVE."""
    cves = state.get("cves") or {}
    out = []
    for update in state.get("updates") or []:
        codes = [c for c in update.get("cves") or [] if c in cves]
        scores = [cves[c][0] for c in codes if cves[c][0] is not None]
        out.append({
            "product": update["product"],
            "from": update["from"],
            "to": update["to"],
            "patchable": update["patchable"],
            "cves": len(codes),
            "kev": [c for c in codes if c in kev],
            "prioritized": sum(1 for c in codes if cves[c][2]),
            "max_score": max(scores) if scores else None,
        })
    out.sort(key=lambda p: (-len(p["kev"]), -p["prioritized"], -(p["max_score"] or 0), -p["cves"], p["product"]))
    return out[:MAX_PATCHES]


def needs_detail(state: dict, before: dict | None) -> bool:
    if not state["cve_count"] and not (before or {}).get("cves"):
        return False
    if not before or "cves" not in before or "updates" not in before:
        return True
    return any(state[k] != before.get(k) for k in ("analyzed_at", "cve_count", "prioritized_count"))


def enrich(state: dict, kev: set[str]) -> dict:
    """Failles KEV, prioritaires et les plus graves, d'après les CVE présentes."""
    cves = state.get("cves") or {}
    state["kev"] = sorted(c for c in cves if c in kev)
    state["prioritized"] = sorted(c for c, v in cves.items() if v[2])
    top = sorted(cves.items(), key=lambda cv: (cv[0] not in kev, -(cv[1][0] or 0), -(cv[1][1] or 0)))[:TOP_CVES]
    state["top"] = [{"cve": c, "score": v[0], "epss": v[1], "kev": c in kev, "prioritized": bool(v[2])} for c, v in top]
    state["patches"] = patches(state, kev)
    return state


def changes(now: dict, before: dict | None) -> list[dict]:
    """Événements de changement d'état. Premier relevé de l'actif (before None) : état des lieux, aucun événement."""
    if before is None:
        return []
    out = []
    new_kev = sorted(set(now["kev"]) - set(before.get("kev") or []))
    if new_kev:
        out.append({"kind": "kev_vulnerabilities", "cves": new_kev})
    new_prio = sorted(set(now["prioritized"]) - set(before.get("prioritized") or []) - set(now["kev"]))
    if new_prio and now["server"]:
        out.append({"kind": "prioritized_vulnerabilities", "cves": new_prio})
    if now["eol_passed"] and not before.get("eol_passed"):
        out.append({"kind": "os_end_of_life", "cves": []})
    return out


def _public(state: dict) -> dict:
    """État publié dans un événement (sans la liste complète des CVE ni des correctifs bruts)."""
    return {k: v for k, v in state.items() if k not in ("cves", "updates")}


class CyberwatchConnector:
    def __init__(self, sessions: async_sessionmaker, redis: aioredis.Redis) -> None:
        self.sessions = sessions
        self.redis = redis

    async def run(self) -> None:
        last, signature = 0.0, None
        while True:
            async with self.sessions() as session:
                cfg = await settings_store.load(session)
            current = (base_url(cfg), cfg.get("cyberwatch_access_key"), cfg.get("cyberwatch_secret_key"))
            due = current != signature or time.monotonic() - last >= POLL_SECONDS
            if configured(cfg) and cfg.get("src_cyberwatch_enabled", False) and due:
                last, signature = time.monotonic(), current
                try:
                    async with make_client(cfg) as client:
                        count = await self.poll(client, cfg)
                    await bus.heartbeat(self.redis, MODULE)
                    log.info("Cyberwatch : relevé terminé, %d événement(s)", count)
                except CyberwatchError as exc:
                    log.error("Cyberwatch : %s", exc)
                except Exception as exc:  # noqa: BLE001
                    log.error("Cyberwatch : interrogation en échec : %s", exc)
            await asyncio.sleep(CHECK_SECONDS)

    async def poll(self, client: httpx.AsyncClient, cfg: dict) -> int:
        now = datetime.now(timezone.utc)
        items = await pages(client, "/api/v3/vulnerabilities/servers")
        kev = set(await self.redis.hkeys(KEV_KEY))
        previous = {}
        for key, value in (await self.redis.hgetall(STATE_KEY)).items():
            try:
                previous[key] = json.loads(value)
            except ValueError:
                continue
        current, events, details = {}, [], 0
        for item in items:
            if item.get("id") is None:
                continue
            state = asset_state(cfg, item, now)
            before = previous.get(state["id"])
            if needs_detail(state, before) and details < DETAILS_PER_PASS:
                detail = (await get(client, f"/api/v3/vulnerabilities/servers/{state['id']}")).json() or {}
                state["cves"], state["ignored"] = active_cves(detail)
                state["updates"] = pending_updates(detail, state["cves"])
                details += 1
                await asyncio.sleep(0.05)
            elif before and "cves" in before and not needs_detail(state, before):
                state["cves"], state["ignored"] = before["cves"], before.get("ignored", [])
                state["updates"] = before.get("updates", [])
            elif not state["cve_count"]:
                state["cves"], state["ignored"], state["updates"] = {}, [], []
            else:  # détail à relire au prochain passage : on garde l'état précédent, sans conclure
                if before:
                    current[state["id"]] = before
                continue
            enrich(state, kev)
            current[state["id"]] = state
            for change in changes(state, before):
                events.append(
                    json.dumps({"type": "posture", **change, "asset_id": state["id"], "asset": _public(state)},
                               ensure_ascii=False)
                )
        pipe = self.redis.pipeline(transaction=True)
        pipe.delete(STATE_KEY)
        if current:
            pipe.hset(STATE_KEY, mapping={k: json.dumps(v, ensure_ascii=False) for k, v in current.items()})
        pipe.set(SUMMARY_KEY, json.dumps(summary(list(current.values())), ensure_ascii=False))
        pipe.set(STATE_AT_KEY, time.time())
        await pipe.execute()
        return await bus.publish(self.redis, MODULE, events)


def summary(states: list[dict]) -> dict:
    exposed = sorted(
        (s for s in states if s.get("kev") or s.get("prioritized") or s.get("eol_passed")),
        key=lambda s: (-len(s.get("kev") or []), -len(s.get("prioritized") or []), not s["server"], s["name"].lower()),
    )
    kev_codes = {c for s in states for c in s.get("kev") or []}
    return {
        "at": time.time(),
        "assets": len(states),
        "servers": sum(1 for s in states if s["server"]),
        "with_kev": sum(1 for s in states if s.get("kev")),
        "kev_cves": len(kev_codes),
        "prioritized": sum(len(s.get("prioritized") or []) for s in states),
        "with_prioritized": sum(1 for s in states if s.get("prioritized")),
        "eol": sum(1 for s in states if s.get("eol_passed")),
        "reboot_required": sum(1 for s in states if s.get("reboot_required")),
        "exposed": [_public(s) for s in exposed[:30]],
    }


def load_states(raw: dict[str, str]) -> dict[str, dict]:
    out = {}
    for key, value in raw.items():
        try:
            out[key] = json.loads(value)
        except ValueError:
            continue
    return out


async def test(cfg: dict) -> tuple[bool, str]:
    """Ping puis lecture d'une page d'actifs (lecture seule) : bouton « Tester »."""
    if not configured(cfg):
        return False, "Adresse, ID ou secret de la clé d'API manquant"
    try:
        async with make_client(cfg) as client:
            await get(client, "/api/v3/ping")
            response = await get(client, "/api/v3/vulnerabilities/servers", {"page": 1, "per_page": 1})
    except CyberwatchError as exc:
        return False, str(exc)
    except httpx.HTTPStatusError as exc:
        return False, f"Cyberwatch : HTTP {exc.response.status_code}"
    except httpx.HTTPError as exc:
        return False, f"Cyberwatch injoignable ({type(exc).__name__}) : {base_url(cfg)}"
    total = response.headers.get("x-total")
    count = f"{total} actif(s)" if total else "liste des actifs lisible"
    return True, f"Connexion réussie à {base_url(cfg)} : {count}"


def hosts_patches(states: dict[str, dict], names: list[str], limit: int = 10) -> dict[str, dict]:
    """Machine (nom tel que cité par l'alerte) → correctifs en attente et état, d'après le dernier relevé."""
    by_key = {str(s.get("name") or "").strip().lower().split(".")[0]: s for s in states.values()}
    out = {}
    for name in names:
        state = by_key.get(name.strip().lower().split(".")[0])
        if not state:
            continue
        found = state.get("patches") or []
        out[name] = {
            "os": state.get("os", ""),
            "console": state.get("console", ""),
            "reboot_required": bool(state.get("reboot_required")),
            "cve_count": state.get("cve_count", 0),
            "prioritized_count": state.get("prioritized_count", 0),
            "kev": state.get("kev") or [],
            "analyzed_at": state.get("analyzed_at", ""),
            "patches": found[:limit],
            "patches_total": len(state.get("updates") or found),
            "known": "updates" in state,  # faux tant que le détail n'a pas été relu depuis l'ajout des correctifs
        }
    return out
