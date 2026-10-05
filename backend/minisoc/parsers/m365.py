"""Journal d'audit unifié Microsoft 365 (API Office 365 Management Activity) : connexions Entra ID, rôles
d'administration, consentements d'applications, règles de transfert de messagerie.

Disponible sans licence Entra ID P1 (contrairement à l'API Graph des connexions) ; délai de 30 min à quelques
heures. Les codes d'erreur Entra (AADSTS) distinguent un vrai échec d'une simple étape d'authentification : une
demande de MFA ou de « rester connecté » apparaît comme « UserLoginFailed » sans en être un.
"""

from __future__ import annotations

import json
import re
from datetime import datetime

from minisoc.ecs import Event
from minisoc.parsers.common import parse_ts

MODULE = "m365"

# Code AADSTS → motif normalisé (comme pour le VPN et l'AD)
ERROR_REASONS = {
    "50126": "invalid_credentials",
    "50034": "unknown_user",
    "50053": "account_locked",
    "50057": "account_disabled",
    "50055": "password_expired",
    "50144": "password_expired",
    "53003": "blocked_by_policy",  # accès conditionnel
    "530032": "blocked_by_policy",
    "500121": "mfa_failed",  # MFA refusée ou non réalisée (fatigue MFA)
    "50131": "blocked_by_policy",
    "7000218": "invalid_credentials",
}
# Étapes normales d'une connexion (MFA demandée, « rester connecté ? », jeton à renouveler) : pas des échecs
INTERRUPTS = {"50074", "50076", "50079", "50072", "50158", "50140", "50058", "16000", "16001", "50199", "81010",
              "81012", "50133", "50173", "70044", "50097", "50125", "65001", "700082", "50089", "50132", "50127"}
FORWARD_PARAMETERS = {"forwardto", "redirectto", "forwardasattachmentto", "forwardingsmtpaddress",
                      "forwardingaddress"}
_IP_PORT = re.compile(r"^\[?([0-9a-fA-F:.]+?)\]?(?::\d+)?$")


def _ip(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    if value.count(":") > 1 and not value.startswith("["):  # IPv6 sans port
        return value.removeprefix("::ffff:")
    match = _IP_PORT.match(value)
    return (match.group(1) if match else value).removeprefix("::ffff:")


def _props(items) -> dict[str, str]:
    out = {}
    for item in items or []:
        if isinstance(item, dict) and item.get("Name"):
            out[str(item["Name"])] = str(item.get("Value", ""))
    return out


def interesting(record: dict) -> bool:
    """Tri à la réception (le journal Exchange est volumineux) : connexions, rôles, consentements, transferts."""
    operation = str(record.get("Operation", ""))
    if operation in ("UserLoggedIn", "UserLoginFailed", "Add member to role.", "Consent to application.",
                     "Add service principal credentials.", "Add app role assignment grant to user.",
                     "Reset user password.",
                     "Disable Strong Authentication."):
        return True
    if operation in ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules", "Set-Mailbox"):
        params = {k.lower(): v for k, v in _props(record.get("Parameters")).items()}
        params.update({k.lower(): v for k, v in _props(record.get("OperationProperties")).items()})
        return any(params.get(p) for p in FORWARD_PARAMETERS) or "forward" in json.dumps(record).lower()
    return False


def parse_m365(record: dict, received: datetime) -> Event:
    operation = str(record.get("Operation", ""))
    user = str(record.get("UserId") or "").lower()
    base = dict(
        ts=parse_ts(record.get("CreationTime"), received),
        module=MODULE,
        observer=str(record.get("Workload") or "Microsoft 365"),
        user_name=user,
        source_ip=_ip(str(record.get("ClientIP") or record.get("ActorIpAddress") or "")),
        rule_name=operation,
        raw=json.dumps(record, ensure_ascii=False, default=str),
    )
    if operation in ("UserLoggedIn", "UserLoginFailed"):
        props = _props(record.get("ExtendedProperties"))
        device = _props(record.get("DeviceProperties"))
        error = str(record.get("ErrorNumber") or "").strip()
        agent = props.get("UserAgent", "")
        client = " · ".join(filter(None, [device.get("OS"), device.get("BrowserType"), device.get("DisplayName")]))
        if operation == "UserLoggedIn":
            action, outcome, reason = "logon", "success", ""
        elif error in INTERRUPTS:
            action, outcome, reason = "logon_interrupted", "", ""
        else:
            action, outcome, reason = "logon_failed", "failure", ERROR_REASONS.get(error, "other")
        label = {"logon": "Connexion réussie", "logon_failed": "Échec de connexion",
                 "logon_interrupted": "Connexion en cours (MFA ou étape intermédiaire)"}[action]
        return Event(**base, category="authentication", action=action, outcome=outcome, reason=reason,
                     network_service="entra_id", threat_name=f"AADSTS{error}" if error else "",
                     host_name=device.get("DisplayName", "")[:128],
                     message=f"{label} de {user}" + (f" ({client})" if client else "")
                             + (f" · {agent[:200]}" if agent and not client else ""))
    if operation == "Add member to role.":
        target = _target(record)
        role = _modified(record, "Role.DisplayName") or "rôle d'administration"
        return Event(**{**base, "rule_name": role, "user_name": target or user}, category="iam",
                     action="role_member_added", threat_name=f"par {user}", severity=2,
                     message=f"{target or '?'} ajouté au rôle Entra « {role} » par {user}")
    if operation in ("Consent to application.", "Add app role assignment grant to user.",
                     "Add service principal credentials."):
        target = _target(record)
        return Event(**{**base, "rule_name": target or operation}, category="iam", action="app_consent",
                     threat_name=operation, severity=2,
                     message=f"{operation} {target} par {user}".strip())
    if operation == "Reset user password.":
        target = _target(record)
        return Event(**{**base, "user_name": target or user}, category="iam", action="password_reset",
                     threat_name=f"par {user}", severity=1, message=f"Mot de passe de {target} réinitialisé par {user}")
    if operation == "Disable Strong Authentication.":
        target = _target(record)
        return Event(**{**base, "user_name": target or user}, category="iam", action="mfa_disabled",
                     threat_name=f"par {user}", severity=2, message=f"MFA désactivée pour {target} par {user}")
    # Règles de boîte aux lettres et transfert
    params = {k.lower(): v for k, v in _props(record.get("Parameters")).items()}
    params.update({k.lower(): v for k, v in _props(record.get("OperationProperties")).items()})
    destination = next((params[p] for p in FORWARD_PARAMETERS if params.get(p)), "")
    mailbox = str(record.get("ObjectId") or user)
    return Event(**{**base, "rule_name": params.get("name", operation)}, category="email",
                 action="mail_forwarding_rule", threat_name=destination[:256], severity=2,
                 message=f"{operation} sur {mailbox} : transfert vers {destination or '?'}")


def _target(record: dict) -> str:
    for target in record.get("Target") or []:
        if isinstance(target, dict) and target.get("Type") == 5:  # UPN
            return str(target.get("ID", "")).lower()
    return str(record.get("ObjectId") or "").lower()


def _modified(record: dict, name: str) -> str:
    for prop in record.get("ModifiedProperties") or []:
        if isinstance(prop, dict) and prop.get("Name") == name:
            return str(prop.get("NewValue", "")).strip('"[] ')
    return ""
