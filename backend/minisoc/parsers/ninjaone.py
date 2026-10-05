"""NinjaOne : alertes du parc et changements d'état de sécurité des postes (voir connectors/ninjaone.py)."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone

from minisoc.ecs import Event

MODULE = "ninjaone"
ALERT_SEVERITY = {"CRITICAL": 4, "MAJOR": 3, "MODERATE": 2, "MINOR": 1, "NONE": 0}
_PERIOD = re.compile(r"\s+(?:de|from)\s+\d{4}-\d{2}-\d{2}T\S+(?:\s+(?:à|to)\s+\d{4}-\d{2}-\d{2}T\S+)?")


def _ts(value, received: datetime) -> datetime:
    """Horodatage NinjaOne : secondes Unix, parfois millisecondes."""
    try:
        number = float(value)
    except (TypeError, ValueError):
        return received
    if number > 1e12:
        number /= 1000
    return datetime.fromtimestamp(number, tz=timezone.utc) if number > 0 else received


def parse_ninjaone(record: dict, received: datetime) -> Event:
    raw = json.dumps(record, ensure_ascii=False, default=str)
    if record.get("type") == "alert":
        alert = record.get("alert") or {}
        device = alert.get("device") or {}
        text = re.sub(
            r"\s+",
            " ",
            str(
                alert.get("message")
                or alert.get("subject")
                or alert.get("conditionName")
                or alert.get("sourceType")
                or "alerte"
            ),
        ).strip()
        text = _PERIOD.sub("", text)[:300]
        severity = ALERT_SEVERITY.get(str(alert.get("severity") or "").upper(), 1)
        return Event(
            ts=_ts(alert.get("createTime"), received),
            module=MODULE,
            kind="alert" if severity >= 2 else "event",
            category="host",
            action="ninjaone_alert",
            severity=severity,
            host_name=str(device.get("systemName") or alert.get("deviceId") or ""),
            rule_name=str(alert.get("conditionName") or alert.get("sourceType") or "Alerte NinjaOne")[:200],
            message=text,
            observer="NinjaOne",
            reference=record.get("console") or "",
            raw=raw,
        )

    d = record.get("device") or {}
    kind = record.get("kind") or "posture"
    server = str(d.get("class") or "").endswith(("SERVER", "VM_HOST", "VMM_HOST"))
    base = dict(
        ts=received,
        module=MODULE,
        host_name=d.get("name") or "",
        host_ip=d.get("ip") or "",
        observer="NinjaOne",
        reference=record.get("console") or "",
        raw=raw,
    )
    if kind == "antivirus_inactive":
        return Event(
            **base,
            category="host",
            action="antivirus_disabled",
            severity=3,
            threat_name=d.get("products") or "",
            message=f"Aucun antivirus actif sur {d.get('name')} ({d.get('products') or 'produit inconnu'})",
        )
    if kind == "antivirus_outdated":
        return Event(
            **base,
            category="host",
            action="antivirus_outdated",
            severity=2,
            threat_name=d.get("products") or "",
            message=f"Définitions antivirus obsolètes sur {d.get('name')} ({d.get('products') or '?'})",
        )
    if kind == "active_threat":
        return Event(
            **base,
            category="malware",
            action="active_threat",
            outcome="failure",
            severity=4,
            threat_name=f"{d.get('threats')} menace(s) active(s) signalée(s) par l'antivirus",
            message=f"{d.get('threats')} menace(s) active(s) sur {d.get('name')} selon NinjaOne",
        )
    if kind == "critical_vulnerabilities":
        return Event(
            **base,
            category="vulnerability",
            action="critical_vulnerabilities",
            severity=3 if server else 2,
            rule_name=f"{d.get('critical')} critique(s), {d.get('high')} élevée(s)",
            threat_name=f"{d.get('pending')} correctif(s) Windows en attente",
            message=f"{d.get('name')} : {d.get('critical')} vulnérabilité(s) critique(s) non corrigée(s) "
            f"(avant : {record.get('previous', 0)}), {d.get('high')} élevée(s), "
            f"{d.get('pending')} correctif(s) en attente",
        )
    if kind == "patches_failed":
        return Event(
            **base,
            category="vulnerability",
            action="patches_failed",
            severity=1,
            message=f"{d.get('name')} : {d.get('failed')} correctif(s) Windows en échec",
        )
    return Event(**base, category="host", action=kind, message=f"NinjaOne : {kind} sur {d.get('name')}")
