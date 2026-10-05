"""Journaux d'événements Windows / Active Directory envoyés en JSON par NXLog (ou équivalent) via syslog.

Champs NXLog utilisés : EventID, Hostname, Channel, EventTime, TargetUserName, SubjectUserName, IpAddress,
LogonType, Status, SubStatus, FailureCode, MemberName, Message. Voir deploy/nxlog/nxlog.conf.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import PureWindowsPath

from minisoc.ecs import Event
from minisoc.parsers.common import first, parse_ts

MODULE = "windows"

# Codes NTSTATUS / Kerberos des échecs d'ouverture de session → motif normalisé (comme pour le VPN)
STATUS_REASONS = {
    "0xc000006a": "invalid_credentials",
    "0xc0000064": "unknown_user",
    "0xc0000234": "account_locked",
    "0xc0000072": "account_disabled",
    "0xc0000071": "password_expired",
    "0xc0000193": "account_expired",
    "0xc0000224": "must_change_password",
    "0xc000006f": "logon_hours",
    "0xc0000070": "workstation",
    "0x18": "invalid_credentials",  # Kerberos : pré-authentification incorrecte
    "0x6": "unknown_user",
    "0x12": "account_disabled",
    "0x17": "password_expired",
}
LOGON_TYPES = {"2": "interactive", "3": "network", "7": "unlock", "8": "network_cleartext", "10": "rdp",
               "11": "cached"}
GROUP_ADD = {"4728": "global", "4732": "local", "4756": "universal"}
GROUP_REMOVE = {"4729": "global", "4733": "local", "4757": "universal"}
# Gestion des comptes : action normalisée (cible = TargetUserName, auteur = SubjectUserName)
ACCOUNT_CHANGES = {
    "4720": "user_created", "4726": "user_deleted", "4722": "account_enabled", "4725": "account_disabled",
    "4723": "password_changed", "4724": "password_reset", "4767": "account_unlocked",
}
DELETE_ACCESS = 0x10000  # 4663 : droit « DELETE » exercé = fichier supprimé ou renommé (déplacé)
# FSRM (filtre de fichiers « rançongiciel ») : message « l'utilisateur X a tenté d'enregistrer <chemin> sur <lecteur> »
FSRM_USER = re.compile(r"(?:user|utilisateur)\s+(\S+)\s+(?:attempted|a tenté)", re.IGNORECASE)
FSRM_PATH = re.compile(r"(?:save|enregistrer)\s+(.+?)\s+(?:on|sur)\s+[A-Za-z]:", re.IGNORECASE)
# Chiffrement des tickets Kerberos (4769) : RC4/DES = faible, cible du « kerberoasting »
TICKET_ENCRYPTION = {"0x17": "rc4", "0x18": "rc4", "0x1": "des", "0x3": "des", "0x11": "aes", "0x12": "aes"}


def looks_like_windows(body: str) -> dict | None:
    start = body.find("{")
    if start < 0 or '"EventID"' not in body:
        return None
    try:
        data = json.loads(body[start:])
    except ValueError:
        return None
    return data if isinstance(data, dict) and "EventID" in data else None


def _ip(value: str) -> str:
    value = (value or "").strip()
    return "" if value == "-" else value.removeprefix("::ffff:")


def _user(value: str) -> str:
    value = (value or "").strip()
    return "" if value == "-" else value


def parse_windows(data: dict, received: datetime, peer: str = "") -> Event:
    event_id = str(data.get("EventID", ""))
    host = first(data, "Hostname", "Computer", default=peer)
    base = dict(
        ts=parse_ts(first(data, "EventTime", "TimeCreated"), received),
        module=MODULE,
        host_name=host,
        observer=host,
        message=first(data, "Message", default=f"Événement Windows {event_id}")[:1000],
        raw=json.dumps(data, ensure_ascii=False, default=str),
        rule_name=f"Windows {event_id}",
    )
    target = _user(first(data, "TargetUserName"))
    # Poste d'où vient la tentative (4625 : WorkstationName, 4776 : Workstation) ; à défaut, le contrôleur
    workstation = _user(first(data, "WorkstationName", "Workstation")).lstrip("\\")
    subject = _user(first(data, "SubjectUserName"))
    source_ip = _ip(first(data, "IpAddress", "ClientAddress"))

    if event_id in ("4624", "4625", "4771", "4776"):
        failed = event_id != "4624"
        status = first(data, "SubStatus", "Status", "FailureCode", "ErrorCode").lower()
        if status in ("0x0", "0x00000000"):
            status = first(data, "Status").lower()
        logon_type = first(data, "LogonType")
        service = {"4771": "kerberos", "4776": "ntlm"}.get(event_id, LOGON_TYPES.get(logon_type, "windows"))
        return Event(**{**base, "host_name": workstation or host}, category="authentication",
                     action="logon_failed" if failed else "logon",
                     outcome="failure" if failed else "success",
                     reason=STATUS_REASONS.get(status, "other") if failed else "",
                     user_name=target, source_ip=source_ip, network_service=service)
    if event_id == "4740":
        # Verrouillage : TargetDomainName contient le poste d'où viennent les échecs
        return Event(**{**base, "host_name": first(data, "TargetDomainName", default=host)}, category="iam",
                     action="account_locked", user_name=target, severity=1)
    if event_id in GROUP_ADD:
        member = first(data, "MemberName", "MemberSid")
        member_cn = member.split(",")[0].removeprefix("CN=") if member.startswith("CN=") else member
        description = f"{member_cn} ajouté au groupe {target} ({GROUP_ADD[event_id]}) par {subject}"
        return Event(**{**base, "rule_name": target, "message": description}, category="iam",
                     action="group_member_added", user_name=member_cn, threat_name=f"ajouté par {subject}",
                     severity=1)
    if event_id in GROUP_REMOVE:
        member = first(data, "MemberName", "MemberSid")
        member_cn = member.split(",")[0].removeprefix("CN=") if member.startswith("CN=") else member
        description = f"{member_cn} retiré du groupe {target} ({GROUP_REMOVE[event_id]}) par {subject}"
        return Event(**{**base, "rule_name": target, "message": description}, category="iam",
                     action="group_member_removed", user_name=member_cn, threat_name=f"retiré par {subject}")
    if event_id in ACCOUNT_CHANGES:
        action = ACCOUNT_CHANGES[event_id]
        by_self = event_id == "4723" or subject.lower() == target.lower()
        return Event(**base, category="iam", action=action, user_name=target,
                     threat_name="" if by_self else f"par {subject}", severity=0 if event_id == "4723" else 1)
    if event_id == "4769":
        # Ticket de service Kerberos : demandeur (« compte@DOMAINE ») et service visé ; NXLog ne transmet que RC4/DES
        status = first(data, "Status").lower()
        failed = status not in ("", "0x0")
        encryption = TICKET_ENCRYPTION.get(first(data, "TicketEncryptionType").lower(), "autre")
        service = first(data, "ServiceName")
        return Event(**{**base, "rule_name": service, "message": f"Ticket Kerberos {encryption.upper()} demandé pour "
                        f"{service} par {target}"}, category="authentication", action="service_ticket",
                     outcome="failure" if failed else "success", user_name=target.split("@")[0],
                     source_ip=source_ip, network_service="kerberos_tgs", threat_name=encryption)
    if event_id == "4663":
        # Audit du système de fichiers (serveurs de fichiers) : seul le droit DELETE est transmis par NXLog
        try:
            mask = int(first(data, "AccessMask") or "0", 16)
        except ValueError:
            mask = 0
        path = first(data, "ObjectName")
        if mask & DELETE_ACCESS and first(data, "ObjectType", default="File") == "File":
            process = first(data, "ProcessName")
            return Event(**{**base, "rule_name": PureWindowsPath(path).suffix.lower(),
                            "message": f"Fichier supprimé ou renommé par {subject} : {path}"},
                         category="file", action="file_delete", user_name=subject, file_path=path,
                         threat_name=PureWindowsPath(process).name if process else "")
    if event_id == "8215":
        message = first(data, "Message")
        user = FSRM_USER.search(message)
        path = FSRM_PATH.search(message)
        user_name = _user(user.group(1)).rsplit("\\", 1)[-1] if user else _user(first(data, "UserName"))
        return Event(**{**base, "rule_name": "FSRM : extension de rançongiciel"}, kind="alert", category="file",
                     action="ransomware_file_blocked", user_name=user_name,
                     file_path=path.group(1) if path else "", severity=4)
    if event_id == "4794":
        return Event(**base, category="configuration", action="dsrm_password_set", user_name=subject, severity=3)
    if event_id in ("1102", "104"):
        return Event(**base, category="configuration", action="log_cleared", user_name=subject, severity=3,
                     kind="alert")
    if event_id == "4719":
        return Event(**base, category="configuration", action="audit_policy_changed", user_name=subject, severity=2)
    if event_id == "7045":
        return Event(**{**base, "rule_name": first(data, "ServiceName", default="service")}, category="configuration",
                     action="service_installed", file_path=first(data, "ImagePath"), user_name=subject, severity=1)
    return Event(**base, category="host", action=f"event_{event_id}", user_name=target or subject,
                 source_ip=source_ip)
