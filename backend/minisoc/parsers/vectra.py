"""Vectra AI : événements lus par l'API v3 (voir connectors/vectra.py). Les messages reçus en syslog CEF passent par
parsers/cef.py ; les deux produisent les mêmes champs (module « vectra »), pour les mêmes règles (NATIVE, UC-19)."""

from __future__ import annotations

import json
from datetime import datetime

from minisoc.ecs import Event
from minisoc.parsers.common import parse_ts

MODULE = "vectra"
# Gravité des entités dans la console Vectra (score d'urgence) → sévérité Mini-SOC
ENTITY_SEVERITY = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _int(value) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return -1


def _account(uid: str) -> str:
    """« O365:prenom.nom@mairie.fr », « kerberos:j.dupont@MAIRIE.LOCAL » → identifiant du compte."""
    name = str(uid or "").split(":", 1)[-1]
    return name.split("@")[0] if name else ""


def _first_ip(value) -> str:
    if isinstance(value, list):
        value = value[0] if value else ""
    return str(value or "").split(",")[0].strip()


def parse_vectra(record: dict, received: datetime) -> Event:
    e = record.get("event") or {}
    if record.get("type") == "detection":
        return _detection(e, received, record)
    return _scoring(e, received, record)


def _detection(e: dict, received: datetime, record: dict) -> Event:
    """Détection, à sa création et à chaque mise à jour : sévérité selon les quadrants de la console Vectra
    (critique : menace et certitude ≥ 50 ; haute : menace ≥ 50 ; moyenne : certitude ≥ 50 ; faible sinon)."""
    name = str(e.get("d_type_vname") or e.get("detection_type") or "Détection Vectra")[:200]
    account = str(e.get("type") or "").lower() == "account"
    entity = str(e.get("entity_name") or "")
    threat, certainty = _int(e.get("threat")), _int(e.get("certainty"))
    severity = 2
    scores = ""
    if threat >= 0 and certainty >= 0:
        high_threat, high_certainty = threat >= 50, certainty >= 50
        severity = 4 if high_threat and high_certainty else 3 if high_threat else 2 if high_certainty else 1
        scores = f" (menace {threat}, certitude {certainty})"
    detail = e.get("detail") if isinstance(e.get("detail"), dict) else {}
    dst_hosts = detail.get("dst_hosts") if isinstance(detail.get("dst_hosts"), dict) else {}
    mitre = ", ".join(str(t) for t in e.get("mitre") or [])
    return Event(
        ts=parse_ts(e.get("event_timestamp"), received),
        module=MODULE,
        kind="alert",
        category="intrusion_detection",
        action=name.lower(),
        severity=severity,
        destination_ip=_first_ip(detail.get("dst_ips") or dst_hosts.get("ip")),
        user_name=_account(e.get("entity_uid") or entity) if account else "",
        host_name="" if account else entity,
        rule_name=name,
        threat_name=str(e.get("category") or "").replace("_", " ").upper(),
        observer="Vectra",
        reference=str(e.get("detection_href") or e.get("url") or ""),
        message=f"Vectra : {name} sur {'le compte ' if account else ''}{entity or '?'}{scores}"
        f"{f' ; MITRE {mitre}' if mitre else ''}",
        raw=json.dumps(record, ensure_ascii=False, default=str),
    )


def _scoring(e: dict, received: datetime, record: dict) -> Event:
    """Changement de score d'un hôte ou d'un compte (règle UC-19 : entité critique)."""
    account = record.get("type") == "account_scoring" or str(e.get("type") or "").lower() == "account"
    name = str(e.get("name") or "")
    level = str(e.get("severity") or "").strip().lower()
    severity = ENTITY_SEVERITY.get(level, 1)
    urgency = e.get("urgency_score")
    detections = ", ".join(str(d) for d in e.get("active_detection_types") or [])
    details = [f"gravité {e.get('severity') or '?'}"]
    if urgency is not None:
        details.append(f"urgence {urgency}")
    if e.get("is_prioritized"):
        details.append("prioritaire")
    return Event(
        ts=parse_ts(e.get("event_timestamp"), received),
        module=MODULE,
        kind="alert",
        category="intrusion_detection",
        action="account_scoring" if account else "host_scoring",
        severity=severity,
        user_name=_account(name) if account else "",
        host_name="" if account else name,
        rule_name="Account Score Change" if account else "Host Score Change",
        threat_name="ACCOUNT SCORING" if account else "HOST SCORING",
        observer="Vectra",
        reference=str(e.get("url") or ""),
        message=f"Vectra : score {'du compte' if account else 'de l’hôte'} {name or '?'} ({', '.join(details)})"
        f"{f' ; détections actives : {detections}' if detections else ''}",
        raw=json.dumps(record, ensure_ascii=False, default=str),
    )
