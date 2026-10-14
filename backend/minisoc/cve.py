"""Recherche par CVE : quelles machines sont touchées, et que sait-on de la faille ?

Sources croisées (lecture seule) :
- Cyberwatch, en direct (/api/v3/vulnerabilities/cve_announcements/{cve}) : fiche de la CVE et actifs concernés,
  vulnérables ou corrigés (avec les dates) ; à défaut (instance injoignable), le dernier relevé du connecteur ;
- catalogue CISA KEV et publications du CERT-FR (veille) ;
- détections citant la CVE (EDR, IPS…) dans les événements, et alertes du Mini-SOC ;
- inventaire des actifs (criticité, propriétaire, service).

NinjaOne ne donne pas les CVE par poste (seulement des nombres par gravité) : il n'est pas une source de cette
recherche tant qu'une correspondance CVE → correctif Windows (KB) n'est pas en place.
"""

from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime, timedelta, timezone

import httpx

from minisoc.assets import CRITICALITY_POINTS, AssetIndex, host_key
from minisoc.connectors import cyberwatch as cw

CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
DETECTION_DAYS = 90
LEVEL = {"level_critical": "critique", "level_high": "haute", "level_medium": "moyenne", "level_low": "basse",
         "level_info": "information", "level_unknown": "inconnue"}


def normalize(code: str) -> str:
    code = (code or "").strip().upper().replace("_", "-")
    if not CVE_RE.match(code):
        raise ValueError("Format attendu : CVE-AAAA-NNNN (ex. CVE-2024-3400)")
    return code


def _criticality(index: AssetIndex | None, name: str) -> dict:
    info = index.host(name) if index else None
    if not info:
        return {"criticality": None, "owner": "", "service": ""}
    return {"criticality": info.criticality, "owner": info.owner, "service": info.service}


def from_states(states: dict[str, dict], code: str) -> list[dict]:
    """Machines touchées d'après le dernier relevé Cyberwatch (CVE présentes ou écartées ; pas l'historique)."""
    out = []
    for state in states.values():
        present = (state.get("cves") or {}).get(code)
        ignored = code in (state.get("ignored") or [])
        if present is None and not ignored:
            continue
        out.append({
            "name": state.get("name", ""),
            "asset_id": state.get("id"),
            "server": bool(state.get("server")),
            "os": state.get("os", ""),
            "ip": state.get("ip", ""),
            "status": "vulnerable" if present is not None else "ignored",
            "prioritized": bool(present and present[2]),
            "environmental_score": None,
            "detected_at": "",
            "fixed_at": "",
            "console": state.get("console", ""),
        })
    return out


def from_live(cfg: dict, servers: list[dict]) -> list[dict]:
    out = []
    for s in servers:
        os = s.get("os") if isinstance(s.get("os"), dict) else {}
        if s.get("fixed_at") or s.get("active") is False:
            status = "fixed"
        elif cw.triaged_out(s):
            status = "ignored"
        else:
            status = "vulnerable"
        out.append({
            "name": str(s.get("hostname") or s.get("id")),
            "asset_id": str(s.get("id")),
            "server": cw.is_server({"os": os, "category": s.get("category") or "server"}),
            "os": str(os.get("name") or ""),
            "ip": "",
            "status": status,
            "triage": str(s.get("triage_status") or ""),
            "prioritized": bool(s.get("prioritized")),
            "environmental_score": s.get("environmental_score"),
            "detected_at": str(s.get("detected_at") or ""),
            "fixed_at": str(s.get("fixed_at") or ""),
            "comment": str(s.get("comment") or ""),
            "console": cw.console_url(cfg, s.get("id")),
        })
    return out


def cyberwatch_info(data: dict) -> dict:
    announcements = [
        {"code": a.get("sa_code"), "link": a.get("link")}
        for a in data.get("security_announcements") or []
        if "anssi" in str(a.get("type") or "").lower() or str(a.get("sa_code") or "").startswith("CERTFR")
    ]
    return {
        "description": str(data.get("content") or data.get("summary") or "")[:2000],
        "score": data.get("score"),
        "level": LEVEL.get(str(data.get("level") or ""), ""),
        "epss": data.get("epss"),
        "published": str(data.get("published") or ""),
        "exploitable": data.get("exploitable"),
        "exploit_code_maturity": str(data.get("exploit_code_maturity") or ""),
        "euvd_id": str(data.get("euvd_id") or ""),
        "catalogs": data.get("catalogs") or [],
        "technologies": [
            " ".join(filter(None, (t.get("vendor"), t.get("product"))))
            for t in data.get("technologies") or []
            if isinstance(t, dict)
        ][:10],
        "certfr": announcements[:10],
    }


async def cyberwatch_lookup(cfg: dict, states: dict[str, dict], code: str) -> dict:
    """Fiche et machines d'après Cyberwatch : en direct si possible, sinon le dernier relevé."""
    if not cw.configured(cfg) or not cfg.get("src_cyberwatch_enabled", False):
        return {"configured": False, "live": False, "info": None, "machines": []}
    try:
        async with cw.make_client(cfg) as client:
            response = await client.get(f"/api/v3/vulnerabilities/cve_announcements/{code}")
            if response.status_code == 404:
                return {"configured": True, "live": True, "known": False, "info": None, "machines": []}
            response.raise_for_status()
            data = response.json()
        return {"configured": True, "live": True, "known": True, "info": cyberwatch_info(data),
                "machines": from_live(cfg, data.get("servers") or [])}
    except (httpx.HTTPError, cw.CyberwatchError, ValueError) as exc:
        return {"configured": True, "live": False, "error": str(exc)[:200], "info": None,
                "machines": from_states(states, code)}


async def detections(store, code: str, days: int = DETECTION_DAYS) -> list[dict]:
    """Détections (EDR, IPS…) qui citent la CVE, par machine ou adresse visée."""
    rows = await store.query(
        "SELECT module, if(host_name != '', host_name, destination_ip) AS target, rule_name, count() AS n, "
        "min(ts) AS first, max(ts) AS last FROM events "
        "WHERE ts >= {since:DateTime64(3)} AND module != 'cyberwatch' "
        "AND positionCaseInsensitive(concat(rule_name, ' ', threat_name, ' ', intel, ' ', message), {code:String}) > 0 "
        "GROUP BY module, target, rule_name ORDER BY last DESC LIMIT 200",
        {"since": (datetime.now(timezone.utc) - timedelta(days=days)).replace(tzinfo=None), "code": code},
    )
    return [
        {
            "module": r["module"],
            "target": r["target"],
            "rule": r["rule_name"],
            "count": int(r["n"]),
            "first": r["first"].isoformat() if hasattr(r["first"], "isoformat") else str(r["first"]),
            "last": r["last"].isoformat() if hasattr(r["last"], "isoformat") else str(r["last"]),
        }
        for r in rows
    ]


def fleet(states: dict[str, dict], kev: set[str], limit: int = 100) -> list[dict]:
    """CVE les plus répandues sur le parc (dernier relevé Cyberwatch) : point de départ de la recherche."""
    machines: dict[str, list[str]] = defaultdict(list)
    servers: dict[str, int] = defaultdict(int)
    score: dict[str, float] = {}
    prioritized: dict[str, int] = defaultdict(int)
    for state in states.values():
        for code, (s, _epss, prio) in (state.get("cves") or {}).items():
            machines[code].append(state.get("name", ""))
            servers[code] += int(bool(state.get("server")))
            prioritized[code] += int(bool(prio))
            if s is not None:
                score[code] = max(score.get(code, 0.0), s)
    rows = [
        {
            "cve": code,
            "machines": len(names),
            "servers": servers[code],
            "prioritized": prioritized[code],
            "score": score.get(code),
            "kev": code in kev,
            "sample": sorted(names, key=str.lower)[:5],
        }
        for code, names in machines.items()
    ]
    rows.sort(key=lambda r: (not r["kev"], -r["prioritized"], -r["machines"], -(r["score"] or 0), r["cve"]))
    return rows[:limit]


def merge_inventory(machines: list[dict], index: AssetIndex | None) -> list[dict]:
    """Ajoute la criticité de l'inventaire ; machines vulnérables et critiques d'abord."""
    order = {"vulnerable": 0, "ignored": 1, "fixed": 2}
    for m in machines:
        m.update(_criticality(index, m["name"]))
        m["key"] = host_key(m["name"])
    machines.sort(
        key=lambda m: (
            order.get(m["status"], 3),
            -CRITICALITY_POINTS.get(m["criticality"] or "normal", 0),
            not m["server"],
            m["name"].lower(),
        )
    )
    return machines


def kev_entry(raw: str | None) -> dict | None:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return None
