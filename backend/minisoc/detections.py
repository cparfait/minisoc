"""Détections des outils : fiches (catégorie, sévérité recalibrée), regroupement par détection et priorité.

- Une **fiche** (`DetectionProfile`) qualifie une détection d'outil (ex. « Recommended driver block list » de
  HarfangLab) : menace, hygiène du parc ou information, avec une sévérité éventuellement recalibrée. Elle
  s'applique aux nouvelles alertes (worker) et, à la demande, aux alertes ouvertes, avec une trace dans leur
  historique. La sévérité d'origine reste dans `details.tool_severity`.
- La vue **par détection** regroupe les alertes ouvertes par (outil, détection), avec leurs machines.
- La **priorité** (0-100) ordonne la file de traitement ; chaque point est expliqué.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from minisoc.models import OPEN_STATUSES, Alert, AlertHistory, DetectionProfile

CATEGORY_LABEL = {"threat": "menace", "hygiene": "hygiène du parc", "info": "information"}
SEVERITY_LABEL = {0: "info", 1: "faible", 2: "moyenne", 3: "haute", 4: "critique"}
SERVER_NAME = re.compile(r"^(srv|svr|serveur|dc|ad|fs|sql|web|app|mail|exch)[-_0-9]", re.I)
SUGGESTIONS_FILE = Path(__file__).with_name("detection_suggestions.yaml")
WIDESPREAD = 20  # machines : au-delà, la détection relève du parc plus que de l'attaque ciblée


def detection_key(module: str, detection: str) -> tuple[str, str]:
    return (module or "").strip().lower(), (detection or "").strip().lower()


def entity_parts(entity_key: str) -> dict[str, str]:
    out = {}
    for part in (entity_key or "").split(" | "):
        name, sep, value = part.partition("=")
        if sep:
            out[name.strip()] = value.strip()
    return out


def alert_detections(alert: Alert) -> list[tuple[str, str, str, int]]:
    """(outil, détection, machine, occurrences) couverts par l'alerte : son entité, ou les entités d'un
    regroupement (anti-tempête)."""
    details = alert.details or {}
    if details.get("storm"):
        items = [(k, int(v or 0)) for k, v in (details.get("entities") or {}).items()]
    else:
        items = [(alert.entity_key, alert.count)]
    default_module = (alert.modules or [""])[0]
    out = []
    for key, count in items:
        parts = entity_parts(key)
        if parts.get("rule.name"):
            module = parts.get("event.module") or default_module
            out.append((module, parts["rule.name"], parts.get("host.name", ""), count))
    return out


# ---------- Corroboration : une machine signalée par plusieurs outils ----------

# Outils de détection : deux outils indépendants qui signalent la même machine sont une piste bien plus sûre
DETECTION_TOOLS = {"harfanglab": "HarfangLab", "bitdefender": "Bitdefender", "vectra": "Vectra",
                   "varonis": "Varonis", "sophos_xgs": "pare-feu Sophos", "crowdsec": "CrowdSec",
                   "windows": "journaux Windows", "m365": "Microsoft 365", "dns": "DNS"}
CORROBORATION_POINTS = 10  # par outil supplémentaire
CORROBORATION_MAX = 20


def alert_hosts(alert: Alert) -> set[str]:
    """Machines citées par l'alerte (entité, entités regroupées, événement déclencheur), en clé unifiée."""
    from minisoc.identity import host_key

    details = alert.details or {}
    names = {parts.get("host.name", "") for parts in [entity_parts(alert.entity_key)]}
    names |= {entity_parts(k).get("host.name", "") for k in (details.get("entities") or {})}
    names.add(str((details.get("sample") or {}).get("host.name") or ""))
    return {host_key(n) for n in names if n and n not in ("-", "?")} - {""}


def tools_by_host(alerts: list[Alert]) -> dict[str, set[str]]:
    """Outils de détection ayant signalé chaque machine (alertes de menace seulement)."""
    out: dict[str, set[str]] = {}
    for alert in alerts:
        if ((alert.details or {}).get("category") or "threat") != "threat":
            continue
        tools = {m for m in alert.modules or [] if m in DETECTION_TOOLS}
        if not tools:
            continue
        for host in alert_hosts(alert):
            out.setdefault(host, set()).update(tools)
    return out


def corroboration(tools: set[str]) -> tuple[int, str]:
    """(points, libellé) quand au moins deux outils distincts ont signalé la machine."""
    if len(tools) < 2:
        return 0, ""
    labels = ", ".join(sorted(DETECTION_TOOLS.get(t, t) for t in tools))
    return min(CORROBORATION_MAX, CORROBORATION_POINTS * (len(tools) - 1)), labels


# ---------- Fiches ----------


class ProfileCache:
    """Fiches en mémoire (worker), rechargées périodiquement."""

    def __init__(self, sessions: async_sessionmaker | None = None) -> None:
        self.sessions = sessions
        self.items: dict[tuple[str, str], DetectionProfile] = {}

    async def refresh(self) -> None:
        async with self.sessions() as session:
            rows = (await session.scalars(select(DetectionProfile))).all()
        self.items = {detection_key(p.module, p.detection): p for p in rows}

    def get(self, module: str, detection: str) -> DetectionProfile | None:
        return self.items.get(detection_key(module, detection))


def recalibrate(profile: DetectionProfile | None, tool_severity: int) -> tuple[int, dict]:
    """Sévérité à retenir et détails à ajouter à l'alerte pour une détection de l'outil."""
    if profile is None:
        return tool_severity, {}
    details = {"category": profile.category, "tool_severity": tool_severity}
    return (tool_severity if profile.severity is None else profile.severity), details


def apply_to_alert(session: AsyncSession, alert: Alert, profile: DetectionProfile | None, actor: str) -> bool:
    """Applique la fiche (ou son retrait : None) à une alerte ouverte, avec une trace. True si l'alerte change."""
    details = dict(alert.details or {})
    tool_severity = int(details.get("tool_severity", alert.severity))
    severity = tool_severity if profile is None or profile.severity is None else profile.severity
    category = profile.category if profile else None
    if severity == alert.severity and category == details.get("category"):
        return False
    previous = alert.severity
    if profile is None:
        details.pop("category", None)
        details.pop("tool_severity", None)
    else:
        details.update(category=category, tool_severity=tool_severity)
    alert.details = details
    alert.severity = severity
    text = f"Fiche de la détection : catégorie « {CATEGORY_LABEL.get(category or 'threat')} »"
    if severity != previous:
        text += f", sévérité {SEVERITY_LABEL[previous]} → {SEVERITY_LABEL[severity]}"
        if severity < previous:
            alert.notify_pending = False  # une alerte déclassée n'est plus à notifier
    session.add(AlertHistory(alert_id=alert.id, actor=actor, action="comment", detail=text))
    return True


async def apply_to_open_alerts(session: AsyncSession, module: str, detection: str,
                               profile: DetectionProfile | None, actor: str) -> int:
    """Alertes ouvertes de cette seule détection (les regroupements multi-détections ne sont pas modifiés)."""
    wanted = detection_key(module, detection)
    alerts = (await session.scalars(select(Alert).where(Alert.status.in_(OPEN_STATUSES)))).all()
    changed = 0
    for alert in alerts:
        found = {detection_key(m, d) for m, d, _, _ in alert_detections(alert)}
        if found == {wanted} and apply_to_alert(session, alert, profile, actor):
            changed += 1
    return changed


def load_suggestions() -> dict[tuple[str, str], dict]:
    if not SUGGESTIONS_FILE.exists():
        return {}
    items = yaml.safe_load(SUGGESTIONS_FILE.read_text(encoding="utf-8")) or []
    return {detection_key(i["module"], i["detection"]): i for i in items}


# ---------- Regroupement par détection ----------


@dataclass
class Topic:
    module: str
    detection: str
    alerts: set[int] = field(default_factory=set)
    occurrences: int = 0
    hosts: dict[str, int] = field(default_factory=dict)
    severity: int = 0
    tool_severity: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None


def topics(alerts: list[Alert]) -> dict[tuple[str, str], Topic]:
    out: dict[tuple[str, str], Topic] = {}
    for alert in alerts:
        details = alert.details or {}
        for module, detection, host, count in alert_detections(alert):
            topic = out.setdefault(detection_key(module, detection), Topic(module, detection))
            topic.alerts.add(alert.id)
            topic.occurrences += count
            if host:
                topic.hosts[host] = topic.hosts.get(host, 0) + count
            severity = alert.severity or 0
            topic.severity = max(topic.severity, severity)
            topic.tool_severity = max(topic.tool_severity, int(details.get("tool_severity", severity)))
            topic.first_seen = min(filter(None, [topic.first_seen, alert.first_seen]), default=None)
            topic.last_seen = max(filter(None, [topic.last_seen, alert.last_seen]), default=None)
    return out


def spread(alerts: list[Alert]) -> dict[tuple[str, str], int]:
    """Nombre de machines par détection, sur les alertes ouvertes (rareté pour la priorité)."""
    return {k: len(t.hosts) for k, t in topics(alerts).items()}


# ---------- Priorité ----------

_SEVERITY_POINTS = {0: 5, 1: 15, 2: 35, 3: 55, 4: 70}


def priority(alert: Alert, machines: dict[tuple[str, str], int], hosts: list[str],
             now: datetime | None = None, extra: list[dict] | None = None,
             tools: dict[str, set[str]] | None = None) -> tuple[int, list[dict]]:
    """Score de 0 à 100 et ses raisons ({label, points}), du plus au moins important. `extra` : raisons venues
    de l'inventaire (criticité de la machine ou du compte) ; `tools` : outils ayant signalé chaque machine sur les
    alertes ouvertes (tools_by_host)."""
    now = now or datetime.now(timezone.utc)
    details = alert.details or {}
    reasons = [{"label": f"sévérité {SEVERITY_LABEL.get(alert.severity, '?')}",
                "points": _SEVERITY_POINTS.get(alert.severity, 0)}, *(extra or [])]
    servers = [h for h in hosts if SERVER_NAME.match(h)]
    if servers:
        reasons.append({"label": f"serveur touché ({servers[0]})", "points": 15})
    roles = str((details.get("sample") or {}).get("user.roles") or "")
    if "admin" in roles:
        reasons.append({"label": "compte à privilèges", "points": 10})
    elif "service" in roles:
        reasons.append({"label": "compte de service", "points": 5})
    category = details.get("category")
    if category == "hygiene":
        reasons.append({"label": "hygiène du parc (pas une attaque en cours)", "points": -30})
    elif category == "info":
        reasons.append({"label": "information", "points": -45})
    spreads = [machines.get(detection_key(m, d), 0) for m, d, _, _ in alert_detections(alert)]
    if spreads and max(spreads) >= WIDESPREAD:
        reasons.append({"label": f"détection répandue ({max(spreads)} machines) : sujet de parc", "points": -15})
    elif spreads and max(spreads) == 1:
        reasons.append({"label": "détection vue sur une seule machine", "points": 10})
    last = alert.last_seen if alert.last_seen.tzinfo else alert.last_seen.replace(tzinfo=timezone.utc)
    if now - last <= timedelta(hours=24):
        reasons.append({"label": "activité dans les dernières 24 h", "points": 10})
    elif now - last > timedelta(days=7):
        reasons.append({"label": "aucune activité depuis plus de 7 jours", "points": -10})
    if len(alert.modules or []) > 1:
        reasons.append({"label": f"confirmée par {len(alert.modules)} outils", "points": 10})
    if tools and category in (None, "threat"):
        from minisoc.identity import host_key

        best = max(((h, tools.get(host_key(h), set())) for h in hosts), key=lambda ht: len(ht[1]), default=None)
        points, labels = corroboration(best[1]) if best else (0, "")
        if points:
            reasons.append({"label": f"{best[0]} signalée par {len(best[1])} outils ({labels})", "points": points})
    score = max(0, min(100, sum(r["points"] for r in reasons)))
    reasons.sort(key=lambda r: -abs(r["points"]))
    return score, reasons

