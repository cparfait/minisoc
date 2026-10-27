"""Croisement des inventaires NinjaOne, Bitdefender GravityZone, HarfangLab et de l'annuaire AD (ménage des outils).

Les techniciens laissent parfois des machines dans les outils : retirées du parc mais restées dans une console,
supprimées de l'AD, inscrites deux fois. Chaque heure, la vérification de couverture (minisoc/coverage.py) lit déjà
les quatre sources ; ce module les rapproche par nom court de machine (base_host_key) et range le résultat dans Redis
pour la page Veille › Croisement des inventaires. Lecture seule : rien n'est supprimé dans les outils.

Constats (champ `issues` de chaque machine) :
- hors_ad : présente dans un outil, absente de l'AD (annuaire lu) ;
- ad_desactive / ad_inactive : compte ordinateur désactivé ou sans ouverture de session depuis 90 jours, encore dans un outil ;
- absent_ninjaone / absent_bitdefender / absent_harfanglab : connue de l'AD ou d'un autre outil, absente de celui-ci.
  Bitdefender (antivirus, et EDR hors AD) est attendu partout, HarfangLab (EDR) sur les machines de l'AD ;
  Bitdefender et HarfangLab ne sont attendus que sur Windows et macOS ;
- inactif_ninjaone / inactif_harfanglab : sans contact depuis plus de 30 jours (machine disparue, agent oublié) ;
- doublon_<outil> : plusieurs fiches pour la même machine dans cet outil.

Une source non lue (non configurée, en erreur) n'est pas un constat : ses colonnes restent vides et aucune absence
n'est déduite d'elle.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from minisoc.identity import base_host_key, is_ip

KEY = "minisoc:inventory:cross"
SOURCES = ("ninjaone", "bitdefender", "harfanglab", "ad")
STALE = timedelta(days=30)  # outil : plus de contact
AD_STALE = timedelta(days=90)  # annuaire : plus d'ouverture de session
EXPECTED_NINJA = ("WINDOWS_WORKSTATION", "WINDOWS_SERVER", "MAC", "MAC_SERVER")
EXPECTED_OS = ("windows", "macos", "mac", "darwin")


def _date(value) -> datetime | None:
    if not value:
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(float(value), tz=timezone.utc) if value > 0 else None
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def _expected(os_name: str) -> bool | None:
    """Windows ou macOS (équipé d'un antivirus et d'un EDR) ; None : système inconnu."""
    text = (os_name or "").lower()
    if not text:
        return None
    return any(word in text for word in EXPECTED_OS)


def _row(rows: dict[str, dict], name: str) -> dict:
    key = base_host_key(name)
    return rows.setdefault(key, {
        "key": key, "name": name.split(".")[0] if not is_ip(key) else name,
        "ninjaone": None, "bitdefender": None, "harfanglab": None, "ad": None,
        "doublons": {}, "expected": [], "server": False,
    })


def _put(row: dict, source: str, info: dict, expected: bool | None) -> None:
    """Fiche d'un outil ; une seconde fiche pour la même machine est un doublon (la plus récente est gardée)."""
    old = row[source]
    if old is not None:
        row["doublons"][source] = row["doublons"].get(source, 1) + 1
        if (info.get("last_seen") or "") < (old.get("last_seen") or ""):
            info = old
        if old.get("managed") == "géré":  # GravityZone : la fiche gérée prime sur la fiche découverte
            info = {**info, "managed": "géré", "group": old.get("group") or info.get("group")}
    row[source] = info
    if expected is not None:
        row["expected"].append(expected)


def build(raw: dict[str, list[dict] | None], groups: dict[str, str] | None, now: datetime) -> dict:
    """Croisement à partir des relevés bruts des consoles (None : source non lue)."""
    rows: dict[str, dict] = {}
    for device in raw.get("ninjaone") or []:
        if not device.get("name"):
            continue
        seen = _date(device.get("last_contact"))
        cls = str(device.get("class") or "")
        row = _row(rows, device["name"])
        row["server"] = row["server"] or "SERVER" in cls
        _put(row, "ninjaone", {"last_seen": seen.isoformat() if seen else None, "detail": cls.lower().replace("_", " ")},
             cls in EXPECTED_NINJA if cls else None)
    for endpoint in raw.get("bitdefender") or []:
        name = str(endpoint.get("name") or endpoint.get("fqdn") or "").strip()
        if not name:
            continue
        managed = bool(endpoint.get("isManaged")) and endpoint.get("managedWithBest") is not False
        group_id = str(endpoint.get("groupId") or "")
        row = _row(rows, name)
        os_name = str(endpoint.get("operatingSystemVersion") or "")
        row["server"] = row["server"] or "server" in os_name.lower()
        _put(row, "bitdefender", {
            "last_seen": None, "managed": "géré" if managed else "non géré",
            "group": (groups or {}).get(group_id) or (f"groupe {group_id}" if group_id else ""), "detail": os_name,
        }, _expected(os_name))
    for agent in raw.get("harfanglab") or []:
        name = str(agent.get("hostname") or "").strip()
        if not name:
            continue
        seen = _date(agent.get("lastseen"))
        os_name = str(agent.get("ostype") or "")
        row = _row(rows, name)
        row["server"] = row["server"] or "server" in str(agent.get("osproducttype") or agent.get("osversion") or "").lower()
        _put(row, "harfanglab", {"last_seen": seen.isoformat() if seen else None, "detail": os_name}, _expected(os_name))
    for computer in raw.get("ad") or []:
        row = _row(rows, computer["name"])
        os_name = str(computer.get("os") or "")
        row["server"] = row["server"] or "server" in os_name.lower()
        _put(row, "ad", {"last_seen": computer.get("last_logon"), "enabled": computer.get("enabled", True),
                         "detail": os_name, "service": computer.get("service") or ""}, _expected(os_name))

    read = {s: raw.get(s) is not None for s in SOURCES}
    out = []
    for row in rows.values():
        expected = not row["expected"] or any(row["expected"])  # un système inconnu est présumé équipable
        issues = _issues(row, read, expected, now)
        if not issues:
            continue
        out.append({
            "name": row["name"], "server": row["server"],
            **{s: row[s] is not None for s in SOURCES},
            "bitdefender_group": (row["bitdefender"] or {}).get("group", ""),
            "bitdefender_state": (row["bitdefender"] or {}).get("managed", ""),
            "ninjaone_seen": (row["ninjaone"] or {}).get("last_seen"),
            "harfanglab_seen": (row["harfanglab"] or {}).get("last_seen"),
            "ad_seen": (row["ad"] or {}).get("last_seen"),
            "ad_service": (row["ad"] or {}).get("service", ""),
            "os": next((row[s]["detail"] for s in ("ad", "harfanglab", "bitdefender", "ninjaone") if row[s] and row[s]["detail"]), ""),
            "doublons": row["doublons"], "issues": issues,
        })
    out.sort(key=lambda r: (-len(r["issues"]), r["name"].lower()))
    counts: dict[str, int] = {}
    for item in out:
        for code in item["issues"]:
            counts[code] = counts.get(code, 0) + 1
    return {
        "at": now.isoformat(),
        "machines": len(rows),
        "sources": {s: {"read": read[s], "count": len(raw.get(s) or [])} for s in SOURCES},
        "summary": counts,
        "rows": out,
    }


def _issues(row: dict, read: dict[str, bool], expected: bool, now: datetime) -> list[str]:
    issues: list[str] = []
    in_tool = any(row[s] is not None for s in ("ninjaone", "bitdefender", "harfanglab"))
    ad = row["ad"]
    if read["ad"]:
        if ad is None and in_tool:
            issues.append("hors_ad")
        elif ad is not None and in_tool:
            seen = _date(ad.get("last_seen"))
            if not ad.get("enabled", True):
                issues.append("ad_desactive")
            elif seen and now - seen > AD_STALE:
                issues.append("ad_inactive")
    # Absence : la machine est connue par ailleurs (AD actif ou autre outil)
    known = {s for s in SOURCES if row[s] is not None}
    ad_seen = _date((ad or {}).get("last_seen"))
    ad_active = ad is not None and ad.get("enabled", True) and not (ad_seen and now - ad_seen > AD_STALE)
    for source, needs_expected in (("ninjaone", False), ("bitdefender", True), ("harfanglab", True)):
        if not read[source] or row[source] is not None or (needs_expected and not expected):
            continue
        # HarfangLab n'est attendu que sur les machines de l'AD (annuaire non lu : aucune conclusion). Bitdefender,
        # antivirus de tout le parc, est attendu partout (et seul EDR hors AD).
        if source == "harfanglab" and (not read["ad"] or ad is None):
            continue
        if ad_active or known - {"ad", source}:
            issues.append(f"absent_{source}")
    for source in ("ninjaone", "harfanglab"):
        seen = _date((row[source] or {}).get("last_seen"))
        if row[source] is not None and (seen is None or now - seen > STALE):
            issues.append(f"inactif_{source}")
    issues += [f"doublon_{s}" for s in SOURCES if row["doublons"].get(s)]
    return issues
