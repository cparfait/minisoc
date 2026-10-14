"""Varonis SaaS : alertes lues par l'API (voir connectors/varonis.py). Les alertes reçues en syslog CEF (Varonis
installé sur site) passent par parsers/cef.py."""

from __future__ import annotations

import json
from datetime import datetime

from minisoc.ecs import Event
from minisoc.parsers.cef import RANSOMWARE
from minisoc.parsers.common import parse_ts

MODULE = "varonis"
SEVERITY = {"high": 3, "medium": 2, "low": 1, "informational": 0}


def _first(value) -> str:
    """Champs multiples Varonis (« a, b ») : la première valeur."""
    return str(value or "").split(",")[0].strip()


def _account(value) -> str:
    name = _first(value)
    return name.rsplit("\\", 1)[-1].split("@")[0] if name else ""


def _delay(seconds) -> str:
    if not isinstance(seconds, int) or seconds < 60:
        return ""
    minutes = seconds // 60
    return f" ; alerte reçue {minutes // 60} h {minutes % 60:02d} après l'activité" if minutes >= 60 else \
        f" ; alerte reçue {minutes} min après l'activité"


def parse_varonis(record: dict, received: datetime) -> Event:
    a = record.get("alert") or {}
    rule = str(a.get("Alert.Rule.Name") or "Alerte Varonis")[:200]
    category = str(a.get("Alert.Rule.Category.Name") or "")
    severity = SEVERITY.get(str(a.get("Alert.Rule.Severity.Name") or "").strip().lower(), 1)
    user = _account(a.get("Alert.User.SamAccountName") or a.get("Alert.User.Name"))
    device = _first(a.get("Alert.Device.HostName"))
    filer = _first(a.get("Alert.Filer.Name"))
    platform = str(a.get("Alert.Filer.Platform.Name") or "")
    asset = _first(a.get("Alert.Asset.Path"))
    action = "varonis_alert"
    if RANSOMWARE.search(f"{rule} {category}"):
        action, severity = "ransomware_detected", 4
    where = asset or filer or platform
    intel = []
    if str(a.get("Alert.Device.IsMaliciousExternalIP") or "").lower() in ("true", "yes", "1"):
        intel.append("varonis:ip-malveillante")
    if str(a.get("Alert.Location.BlacklistedLocation") or "").lower() in ("true", "yes", "1"):
        intel.append("varonis:pays-interdit")
    details = [f"{a.get('Alert.EventsCount') or '?'} événement(s)"]
    if str(a.get("Alert.Data.IsSensitive") or "").lower() in ("true", "yes", "1"):
        details.append("données sensibles")
    if a.get("Alert.Location.CountryName"):
        details.append(f"depuis {a['Alert.Location.CountryName']}")
    return Event(
        ts=parse_ts(a.get("Alert.TimeUTC"), received),
        module=MODULE,
        kind="alert",
        category="iam" if "directory" in platform.lower() else "file",
        action=action,
        severity=severity,
        user_name=user,
        host_name=device or filer,
        rule_name=rule,
        threat_name=category,
        file_path=asset[:1024],
        intel=",".join(intel),
        observer="Varonis",
        reference=str(record.get("console") or ""),
        message=f"Varonis : {rule}{f' — {user}' if user else ''}{f' sur {where}' if where else ''} "
        f"({', '.join(details)}){_delay(record.get('delay_seconds'))}",
        raw=json.dumps(record, ensure_ascii=False, default=str),
    )
