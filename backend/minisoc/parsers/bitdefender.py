"""Événements du service Push de Bitdefender GravityZone (méthode JSON-RPC `addEvents`).

Chaque événement porte un champ `module` (av, hd, avc, ransomware-mitigation, new-incident, fw, aph,
network-monitor, modules…). Les noms de champs varient selon le module et la version de l'API :
l'analyse est tolérante, l'événement complet reste dans `raw`.
"""

from __future__ import annotations

import json
from datetime import datetime

from minisoc.ecs import Event
from minisoc.parsers.common import first, parse_ts

MODULE = "bitdefender"

# Statuts finaux considérés comme une menace neutralisée
NEUTRALIZED = {
    "deleted",
    "blocked",
    "quarantined",
    "cleaned",
    "disinfected",
    "moved to quarantine",
    "access denied",
    "killed",
    "restored",
}

# module Bitdefender -> (catégorie ECS, kind, sévérité si neutralisé, sévérité sinon)
_MODULES: dict[str, tuple[str, str, int, int]] = {
    "av": ("malware", "alert", 2, 4),
    "hd": ("malware", "alert", 2, 4),
    "avc": ("malware", "alert", 2, 4),
    "network-sandboxing": ("malware", "alert", 2, 4),
    "exchange-malware": ("malware", "alert", 1, 3),
    "ransomware-mitigation": ("malware", "alert", 4, 4),
    "new-incident": ("intrusion_detection", "alert", 3, 3),
    "network-monitor": ("intrusion_detection", "alert", 3, 3),
    "aph": ("web", "alert", 1, 2),
    "fw": ("network", "event", 0, 0),
    "uc": ("web", "event", 0, 0),
    "dp": ("file", "event", 1, 1),
    "modules": ("configuration", "event", 0, 0),
    "sva": ("configuration", "event", 0, 0),
    "registration": ("configuration", "event", 0, 0),
    "task-status": ("configuration", "event", 0, 0),
}


def parse_bitdefender(event: dict, received: datetime, console_url: str = "") -> Event:
    bd_module = str(event.get("module", "unknown")).lower()
    category, kind, sev_ok, sev_bad = _MODULES.get(bd_module, ("other", "event", 0, 0))
    status = first(event, "final_status", "status", "action_taken").lower()
    neutralized = status in NEUTRALIZED
    if bd_module == "ransomware-mitigation":
        action = "ransomware_detected"
    elif category == "malware":
        action = "malware_detected"
    else:
        action = bd_module.replace("-", "_")

    outcome = ""
    if category == "malware" and status:
        outcome = "success" if neutralized else "failure"  # succès = menace neutralisée

    return Event(
        ts=parse_ts(first(event, "timestamp", "detection_time", "date", "created"), received),
        module=MODULE,
        kind=kind,
        category=category,
        action=action,
        outcome=outcome,
        severity=sev_ok if neutralized or not status else sev_bad,
        source_ip=first(event, "source_ip", "attacker_ip", "attack_source", "sourceIp"),
        destination_ip=first(event, "destination_ip", "computer_ip", "endpoint_ip"),
        user_name=first(event, "user.name", "username", "user_name", "computer_user"),
        host_name=first(event, "computer_name", "endpoint_name", "computerName", "hostname"),
        host_ip=first(event, "computer_ip", "endpoint_ip", "computerIp"),
        rule_name=first(event, "malware_type", "attack_type", "incident_type", "detection_name", default=bd_module),
        threat_name=first(event, "malware_name", "threat_name", "attack_type", "detection_name"),
        file_path=first(event, "file_path", "filePath", "path"),
        observer="GravityZone",
        reference=console_url,
        message=_message(bd_module, event, status),
        raw=json.dumps(event, ensure_ascii=False, default=str),
    )


def _message(bd_module: str, event: dict, status: str) -> str:
    threat = first(event, "malware_name", "threat_name", "attack_type", "detection_name", default=bd_module)
    host = first(event, "computer_name", "endpoint_name", default="poste inconnu")
    suffix = f" (statut : {status})" if status else ""
    return f"Bitdefender {bd_module} : {threat} sur {host}{suffix}"
