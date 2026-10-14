"""Journaux syslog du Sophos Firewall (SFOS / XGS), format clé=valeur.

Deux formats, tous deux reconnus :
- « Standard syslog protocol » (ex-« Central Reporting Format », recommandé par Sophos) : timestamp ISO 8601 avec
  fuseau, `severity`, `client_used` (client d'authentification), `malware` (ATP), `src_country` en code à 3 lettres ;
- « Device standard format (legacy) », bientôt abandonné par Sophos : `date`/`time` en heure locale, `priority`,
  `auth_client`, `threatname`.
Les noms de champs varient aussi selon la version de SFOS : l'analyse est tolérante et le message brut est gardé.
"""

from __future__ import annotations

import re
from datetime import datetime

from minisoc.ecs import Event
from minisoc.parsers.common import first, parse_kv, parse_ts

MODULE = "sophos_xgs"

# (motif dans log_component / auth_client, service normalisé) – le premier motif trouvé l'emporte
_SERVICES = (
    ("ssl vpn", "ssl_vpn"),
    ("sslvpn", "ssl_vpn"),
    ("ipsec", "ipsec"),
    ("sophos connect", "ipsec"),
    ("l2tp", "l2tp"),
    ("vpn portal", "user_portal"),
    ("vpnportal", "user_portal"),
    ("user portal", "user_portal"),
    ("userportal", "user_portal"),
    ("my account", "user_portal"),
    ("captive portal", "captive_portal"),
    ("webadmin", "admin_console"),
    ("gui", "admin_console"),
    ("ssh", "admin_console"),
    ("admin", "admin_console"),
)

_PRIORITY = {
    "emergency": 4,
    "alert": 4,
    "critical": 4,
    "error": 3,
    "warning": 2,
    "notice": 1,
    "information": 0,
    "informational": 0,
    "debug": 0,
}

_FAILURE = {"failed", "failure", "denied", "deny", "drop", "dropped", "blocked", "reject", "rejected"}
_SUCCESS = {"successful", "success", "allowed", "allow", "accepted", "passed"}


def looks_like_sophos(text: str) -> bool:
    return "log_component=" in text or ("device_name=" in text and "log_type=" in text)


def parse_sophos(text: str, received: datetime, peer: str = "") -> Event:
    kv = parse_kv(text)
    log_type = kv.get("log_type", "")
    component = kv.get("log_component", "")
    subtype = kv.get("log_subtype", "")
    status = kv.get("status", "")
    descr = f"{log_type} {component} {subtype}".lower()

    category, kind, severity = _classify(descr, kv)
    if category != "authentication" and _admin_login(subtype, kv):
        category = "authentication"  # connexion à l'administration (GUI, SSH, CLI) : log_subtype « Admin »
    service = ""
    if category == "authentication":
        hint = f"{component} {first(kv, 'client_used', 'auth_client')}".lower()
        service = next((svc for pattern, svc in _SERVICES if pattern in hint), "other")

    outcome = _outcome(status) or _outcome(subtype) or _outcome(kv.get("fw_rule_action", ""))
    reason = auth_failure_reason(f"{kv.get('reason', '')} {kv.get('message', '')}") if outcome == "failure" else ""

    return Event(
        # `date`/`time` sont en heure locale sans fuseau fiable : sans `timestamp`, on garde l'heure de réception
        ts=parse_ts(kv.get("timestamp"), received),
        module=MODULE,
        kind=kind,
        category=category,
        action=(subtype or component or log_type).lower().replace(" ", "_"),
        outcome=outcome,
        reason=reason if category == "authentication" else "",
        severity=severity,
        source_ip=first(kv, "src_ip", "srcip", "src"),
        source_port=first(kv, "src_port", "srcport", default="0"),
        destination_ip=first(kv, "dst_ip", "dstip", "dst"),
        destination_port=first(kv, "dst_port", "dstport", default="0"),
        user_name=first(kv, "user_name", "username", "user"),
        host_name=first(kv, "src_host", "hostname"),
        network_service=service,
        rule_name=first(kv, "signature_msg", "threatname", "malware", "fw_rule_name", "fw_rule_id"),
        threat_name=first(kv, "threatname", "malware", "virus", "signature_msg"),
        observer=first(kv, "device_name", "device_id", default=peer),
        message=first(kv, "message", "reason", default=f"{log_type} {component} {subtype} {status}".strip()),
        raw=text,
    )


_LOGIN = ("login", "log in", "logged in", "logged out", "authenticat")


def _admin_login(subtype: str, kv: dict[str, str]) -> bool:
    """Connexion (ou échec) à la console d'administration : sous-type « Admin » et message de connexion. Les autres
    événements « Admin » (modifications de configuration) restent de la configuration."""
    if subtype.lower() != "admin":
        return False
    text = f"{kv.get('message', '')} {kv.get('reason', '')}".lower()
    return any(word in text for word in _LOGIN)


def _classify(descr: str, kv: dict[str, str]) -> tuple[str, str, int]:
    """Retourne (catégorie ECS, kind, sévérité)."""
    priority = _PRIORITY.get((kv.get("priority") or kv.get("severity") or "").lower(), 0)
    words = set(re.findall(r"[a-z]+", descr))
    if "authentication" in words or "auth" in words:
        return "authentication", "event", priority
    if "atp" in words or "advanced threat" in descr:
        return "intrusion_detection", "alert", max(priority, 3)
    if "idp" in words or "ips" in words or "intrusion" in descr:
        return "intrusion_detection", "alert", max(priority, 2)
    if "anti-virus" in descr or "antivirus" in descr or "malware" in descr or "sandstorm" in descr:
        return "malware", "alert", max(priority, 3)
    if "firewall" in descr:
        return "network", "event", priority
    if "content filtering" in descr or "web" in descr:
        return "web", "event", priority
    if "system" in descr or "event" in descr:
        return "configuration", "event", priority
    return "other", "event", priority


# Motif d'échec d'authentification normalisé. Les libellés exacts varient selon la version de SFOS et le
# mécanisme (local, AD, RADIUS) : à compléter avec les journaux réels.
_REASONS = (
    ("unknown_user", ("does not exist", "not exist", "user not found", "unknown user", "no such user",
                      "invalid user")),
    ("password_expired", ("expired", "must change", "change password")),
    ("account_locked", ("locked", "lockout")),
    ("outside_hours", ("access time", "time policy")),  # hors de la plage horaire autorisée par le pare-feu
    ("account_disabled", ("disabled", "inactive", "not allowed", "not authorized")),
    ("mfa_failed", ("otp", "token", "mfa", "two-factor")),
    ("invalid_credentials", ("wrong credentials", "invalid credentials", "wrong password", "incorrect password",
                             "authentication failed", "bad password", "failed to login")),
)


def auth_failure_reason(text: str) -> str:
    text = text.lower()
    for reason, patterns in _REASONS:
        if any(p in text for p in patterns):
            return reason
    return "other"


def _outcome(value: str) -> str:
    value = value.lower().strip()
    if value in _FAILURE:
        return "failure"
    if value in _SUCCESS:
        return "success"
    return ""
