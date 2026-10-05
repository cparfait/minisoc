"""Alertes de l'EDR HarfangLab récupérées par l'API REST (`/api/data/alert/alert/Alert/`)."""

from __future__ import annotations

from datetime import datetime

from minisoc.ecs import Event
from minisoc.parsers.common import compact_json, first, parse_ts

MODULE = "harfanglab"

_LEVELS = {"informational": 0, "info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
# Statuts HarfangLab encore à traiter : les autres (faux positif, clôturée) sont gardés comme simples événements
OPEN_STATUSES = {"", "new", "investigating"}
# Champs redondants ou volumineux, retirés seulement si l'alerte dépasse la taille de stockage
BULKY = (
    "process.sigma_rule_content",  # copie de rule_content
    "process.agent",  # copie de agent
    "process.stacktrace",  # stacktrace_minimal conservée
    "process.signature_info.root_info",
    "process.pe_info.authentihashes",
    "details_powershell.hashes",  # details_powershell.sha256 conservée
)
STATUS_FR = {"new": "nouvelle", "investigating": "en investigation", "probable_false_positive": "faux positif probable",
             "false_positive": "faux positif", "closed": "clôturée"}


def parse_harfanglab(alert: dict, received: datetime, console_url: str = "") -> Event:
    level = first(alert, "level", "severity").lower()
    rule = first(alert, "rule_name", "rule.name", "alert_subtype", default="Alerte HarfangLab")
    alert_id = first(alert, "id")
    reference = f"{console_url.rstrip('/')}/security-event/{alert_id}/summary" if console_url and alert_id else ""
    status = first(alert, "status").lower()
    message = first(alert, "msg", "message", default=rule)
    if status not in OPEN_STATUSES:
        message = f"[{STATUS_FR.get(status, status)} dans HarfangLab] {message}"

    return Event(
        ts=parse_ts(first(alert, "alert_time", "@timestamp", "detection_date"), received),
        module=MODULE,
        kind="alert" if status in OPEN_STATUSES else "event",
        category="malware" if "malware" in first(alert, "alert_type", "type").lower() else "intrusion_detection",
        action=first(alert, "alert_type", "type", default="edr_alert").lower(),
        outcome="",
        severity=_LEVELS.get(level, 2),
        source_ip=first(alert, "source_address.ip", "network.source.ip"),
        destination_ip=first(alert, "destination_address.ip", "network.destination.ip"),
        # Compte du processus seulement : le nom de domaine (agent.domainname) n'est pas un compte
        user_name=first(alert, "process.username"),
        host_name=first(alert, "agent.hostname", "hostname"),
        host_ip=first(alert, "agent.ipaddress", "agent.ip"),
        rule_name=rule,
        threat_name=first(alert, "rule_name", "msg"),
        file_path=first(alert, "process.image_name", "image_name", "process.current_directory"),
        observer="HarfangLab",
        reference=reference,
        message=message,
        raw=compact_json(alert, drop=BULKY),
    )
