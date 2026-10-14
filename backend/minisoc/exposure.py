"""Exposition réelle : quelles machines corriger en premier cette semaine ?

Croise, par machine : vulnérabilités et correctifs (NinjaOne), CVE présentes dont les failles activement exploitées
et le système en fin de support (Cyberwatch), état de l'antivirus et menaces actives, alertes de menace ouvertes,
failles activement exploitées citées par les alertes (catalogue CISA KEV), exposition à Internet et criticité
(inventaire). Chaque point est expliqué et accompagné de l'action à mener.
"""

from __future__ import annotations

import json

from minisoc.assets import CRITICALITY_LABEL, host_key
from minisoc.detections import alert_detections
from minisoc.models import Alert, Asset

CRITICALITY_FACTOR = {"vital": 1.5, "high": 1.25, "normal": 1.0, "low": 0.75}


def _host_alerts(alerts: list[Alert]) -> dict[str, list[Alert]]:
    out: dict[str, list[Alert]] = {}
    for alert in alerts:
        names = {h for _, _, h, _ in alert_detections(alert) if h}
        sample = (alert.details or {}).get("sample") or {}
        if sample.get("host.name"):
            names.add(str(sample["host.name"]))
        for name in names:
            out.setdefault(host_key(name), []).append(alert)
    return out


def score_host(
    name: str, posture: dict | None, asset: Asset | None, alerts: list[Alert], cyber: dict | None = None
) -> dict:
    reasons, actions = [], []

    def add(points: float, label: str, action: str = "") -> None:
        reasons.append({"label": label, "points": round(points)})
        if action and action not in actions:
            actions.append(action)

    if posture:
        if posture.get("critical"):
            add(
                min(40, 10 * posture["critical"]),
                f"{posture['critical']} vulnérabilité(s) critique(s)",
                "Appliquer les correctifs critiques",
            )
        if posture.get("high"):
            add(
                min(10, 2 * posture["high"]),
                f"{posture['high']} vulnérabilité(s) élevée(s)",
                "Appliquer les correctifs",
            )
        if posture.get("failed"):
            add(5, f"{posture['failed']} correctif(s) en échec", "Corriger l'installation des correctifs en échec")
        if posture.get("pending", 0) >= 10:
            add(
                5, f"{posture['pending']} correctif(s) en attente", "Redémarrer / installer les mises à jour en attente"
            )
        antivirus = posture.get("antivirus")
        if antivirus == "inactive":
            add(25, "antivirus inactif", "Réactiver la protection antivirus")
        elif antivirus == "outdated":
            add(10, "définitions antivirus obsolètes", "Mettre à jour l'antivirus")
        if posture.get("threats"):
            add(30, f"{posture['threats']} menace(s) active(s) selon l'antivirus", "Traiter les menaces actives")
        if posture.get("offline"):
            reasons.append({"label": "hors ligne au dernier relevé", "points": 0})
    if cyber:
        present = list(cyber.get("kev") or [])
        if present:
            add(
                min(40, 20 + 5 * (len(present) - 1)),
                f"{len(present)} faille(s) activement exploitée(s) présente(s) : {', '.join(present[:3])}",
                "Corriger en urgence les failles KEV présentes (Cyberwatch)",
            )
        prioritized = [c for c in cyber.get("prioritized") or [] if c not in present]
        if prioritized:
            add(
                min(15, 3 * len(prioritized)),
                f"{len(prioritized)} vulnérabilité(s) prioritaire(s) selon Cyberwatch",
                "Appliquer les correctifs prioritaires",
            )
        if cyber.get("eol_passed"):
            add(
                10,
                f"système en fin de support : {cyber.get('os') or '?'}",
                "Mettre à niveau le système d'exploitation",
            )
        if cyber.get("reboot_required"):
            add(2, "redémarrage requis pour appliquer des correctifs", "Redémarrer la machine")
    threat_alerts = [
        a
        for a in alerts
        if a.status in ("new", "in_progress", "waiting") and ((a.details or {}).get("category") or "threat") == "threat"
    ]
    if threat_alerts:
        worst = max(a.severity for a in threat_alerts)
        add(
            {4: 20, 3: 12, 2: 6}.get(worst, 2),
            f"{len(threat_alerts)} alerte(s) de menace ouverte(s)",
            "Traiter les alertes ouvertes de la machine",
        )
    kev = sorted(
        {
            i[4:]
            for a in alerts
            for i in str(((a.details or {}).get("sample") or {}).get("threat.intel") or "").split(",")
            if i.startswith("kev:")
        }
    )
    kev = [c for c in kev if c not in set((cyber or {}).get("kev") or [])]  # déjà comptées comme présentes
    if kev:
        add(
            25,
            f"faille activement exploitée citée : {', '.join(kev[:3])}",
            "Corriger en urgence les failles KEV citées",
        )
    base = sum(r["points"] for r in reasons)
    factor = 1.0
    if asset and asset.internet_exposed:
        factor *= 1.5
        reasons.append({"label": "exposée à Internet (×1,5)", "points": 0})
    criticality = asset.criticality if asset else "normal"
    if criticality != "normal":
        factor *= CRITICALITY_FACTOR[criticality]
        reasons.append(
            {"label": f"criticité {CRITICALITY_LABEL[criticality]} (×{CRITICALITY_FACTOR[criticality]})", "points": 0}
        )
    return {
        "name": asset.display_name if asset else (cyber or posture or {}).get("name") or name,
        "score": round(base * factor),
        "criticality": criticality,
        "internet_exposed": bool(asset and asset.internet_exposed),
        "owner": asset.owner if asset else "",
        "service": asset.service if asset else "",
        "reasons": sorted(reasons, key=lambda r: -r["points"]),
        "actions": actions,
        "has_posture": posture is not None or cyber is not None,
        "console": (cyber or {}).get("console") or "",
    }


def ranking(
    postures: dict[str, dict],
    assets: list[Asset],
    alerts: list[Alert],
    limit: int = 50,
    cyber: dict[str, dict] | None = None,
) -> list[dict]:
    """postures : dernier relevé NinjaOne ; cyber : dernier relevé Cyberwatch (identifiant d'actif → état)."""
    by_host = _host_alerts(alerts)
    host_assets = {a.name: a for a in assets if a.kind == "host"}
    posture_by_key = {host_key(p.get("name", "")): p for p in postures.values() if p.get("name")}
    cyber_by_key = {host_key(c.get("name", "")): c for c in (cyber or {}).values() if c.get("name")}
    names = (
        set(posture_by_key)
        | set(by_host)
        | set(cyber_by_key)
        | {k for k, a in host_assets.items() if a.internet_exposed}
    )
    rows = [
        score_host(n, posture_by_key.get(n), host_assets.get(n), by_host.get(n, []), cyber_by_key.get(n))
        for n in names
    ]
    rows = [r for r in rows if r["score"] > 0]
    rows.sort(key=lambda r: (-r["score"], r["name"].lower()))
    return rows[:limit]


def load_postures(raw: dict[str, str]) -> dict[str, dict]:
    out = {}
    for key, value in raw.items():
        try:
            out[key] = json.loads(value)
        except ValueError:
            continue
    return out
