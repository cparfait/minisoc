"""OGO Security (WAF) : journal et état des sites lus par l'API v2 (voir connectors/ogo.py).

Journal : chaque événement a un type (SECURITY, MONITORING, ACTIVITY), un sous-type et une sévérité OGO de 1 à 3.
- attaque en cours (pic de bannissements, afflux de trafic, limitation de débit) → alerte (règle UC-17) ;
- certificat en erreur ou bientôt expiré, DNS ne pointant plus vers OGO → alerte (NATIVE) ;
- changement sensible (site supprimé, utilisateur invité ou promu, paramètres de protection) → règle UC-60 ;
- le reste (IP nouvellement bannie, erreurs 4xx/5xx, configuration courante) → événement consultable.
État des sites : protection contournée (passthrough), mode audit (détecte sans bloquer), site hors ligne ou DNS en
erreur → alerte (UC-60) ; retour à la normale → événement.
"""

from __future__ import annotations

import json
import re
from datetime import datetime

from minisoc.ecs import Event
from minisoc.parsers.common import compact_json, parse_ts

MODULE = "ogo"
DASHBOARD = "https://dashboard.ogosecurity.com"
LABELS = {
    "newIpBlocked": "Nouvelle IP bannie", "highBannedVolume": "Volume élevé de requêtes bannies",
    "traficSpike": "Pic de trafic", "increasedBandwidth": "Hausse de la bande passante",
    "increasedResponseTime": "Hausse du temps de réponse", "siteRateLimit": "Limitation de débit atteinte",
    "4XX": "Erreurs 4xx", "5XX": "Erreurs 5xx", "increased4xxRate": "Hausse des erreurs 4xx",
    "increased5xxRate": "Hausse des erreurs 5xx", "increasedOriginError": "Erreurs du serveur d'origine",
    "siteCreated": "Site créé", "siteConfigChange": "Configuration du site modifiée",
    "siteStatusChange": "Statut du site modifié", "siteTagsChange": "Étiquettes du site modifiées",
    "siteShareChange": "Partage du site modifié", "siteDeleted": "Site supprimé", "sitePurgeCache": "Cache purgé",
    "certificateError": "Erreur de certificat", "certificateUploaded": "Certificat déposé",
    "certificateGenerated": "Certificat généré", "certificateActivated": "Certificat activé",
    "customerCertificateExpiresSoon": "Certificat bientôt expiré", "invalidDnsConfig": "DNS ne pointant pas vers OGO",
    "userInvited": "Utilisateur invité", "userRoleChange": "Rôle d'utilisateur modifié",
    "userRemoved": "Utilisateur retiré", "brainParametersChange": "Paramètres de protection modifiés",
    "blacklistedIpsChange": "Liste d'IP bloquées modifiée",
}
ATTACKS = {"highBannedVolume", "traficSpike", "siteRateLimit", "increasedBandwidth"}
EXPOSURE = {"certificateError", "customerCertificateExpiresSoon", "invalidDnsConfig"}
SENSITIVE = {"siteDeleted", "userInvited", "userRoleChange", "userRemoved", "brainParametersChange"}
CATEGORY = {"SECURITY": "intrusion_detection", "MONITORING": "network", "ACTIVITY": "configuration"}
SITE_STATUS = {"CREATED": "créé", "DNS_ERROR": "DNS en erreur", "ONLINE": "en ligne", "LE_CERT": "en ligne",
               "CUST_CERT": "en ligne", "OFFLINE": "hors ligne"}


def action_name(subtype: str) -> str:
    """« highBannedVolume » → « high_banned_volume », « tlsOptions.create » → « tls_options.create »."""
    return re.sub(r"(?<=[a-z])(?=[A-Z])", "_", subtype).lower()


def _find(data, *keys: str) -> str:
    """Première valeur d'une des clés, à n'importe quelle profondeur (contenu de l'événement non documenté)."""
    if isinstance(data, dict):
        for key in keys:
            value = data.get(key)
            if isinstance(value, list):
                value = value[0] if value else None
            if isinstance(value, dict):
                value = value.get("email") or value.get("ip") or value.get("name")
            if value not in (None, ""):
                return str(value)
        for value in data.values():
            found = _find(value, *keys)
            if found:
                return found
    elif isinstance(data, list):
        for value in data:
            found = _find(value, *keys)
            if found:
                return found
    return ""


def parse_ogo(record: dict, received: datetime) -> Event:
    if record.get("type") == "site":
        return _site(record, received)
    return _journal(record, received)


def _journal(record: dict, received: datetime) -> Event:
    e = record.get("event") or {}
    subtype = str(e.get("subtype") or "")
    kind_ = str(e.get("type") or "").upper()
    label = LABELS.get(subtype) or str(e.get("subtypeLabel") or subtype or "Événement OGO")
    try:
        level = min(3, max(1, int(e.get("severity") or 1)))  # sévérité OGO : 1 (faible) à 3 (forte)
    except (TypeError, ValueError):
        level = 1
    detail = e.get("event") if isinstance(e.get("event"), (dict, list)) else {}
    site = str(e.get("site") or "")
    ip = _find(detail, "ip", "clientIp", "clientIP", "ips")
    user = _find(detail, "user", "email", "userEmail", "author", "owner", "by") if kind_ == "ACTIVITY" else ""
    if subtype in ATTACKS:
        kind, severity = "alert", max(2, level)
    elif subtype in EXPOSURE:
        kind, severity = "alert", 2
    elif subtype in SENSITIVE:
        kind, severity = "event", 2
    else:
        kind, severity = "event", 1 if kind_ != "ACTIVITY" else 0
    where = f" sur {site}" if site else ""
    return Event(
        ts=parse_ts(e.get("date"), received),
        module=MODULE,
        kind=kind,
        category=CATEGORY.get(kind_, "other"),
        action=action_name(subtype) or "journal",
        severity=severity,
        source_ip=ip if subtype == "newIpBlocked" or kind_ == "SECURITY" else "",
        user_name=user.split("@")[0] if user else "",
        host_name=site,
        rule_name=label,
        threat_name=kind_,
        observer="OGO",
        reference=DASHBOARD,
        message=f"OGO : {label}{where}{f' ({ip})' if ip else ''}{f' par {user}' if user else ''}"
        f"{' [expérimental]' if e.get('experimental') else ''}",
        raw=compact_json(record),
    )


def _site(record: dict, received: datetime) -> Event:
    """Site nouveau ou modifié : la pire situation donne l'action et la sévérité."""
    state = record.get("state") or {}
    previous = record.get("previous") or {}
    site = str(record.get("site") or "")
    status = str(state.get("status") or "")
    if state.get("passthroughMode"):
        action, severity, text = "site_passthrough", 3, "protection contournée (passthrough) : trafic non filtré"
    elif state.get("auditMode"):
        action, severity, text = "site_audit_mode", 2, "mode audit : attaques détectées mais plus bloquées"
    elif status in ("OFFLINE", "DNS_ERROR"):
        action, severity, text = "site_unreachable", 2, (
            f"site {SITE_STATUS[status]} (DNS ou serveur d'origine : le trafic peut contourner OGO)")
    else:
        action, severity = "site_state", 0
        text = f"site {SITE_STATUS.get(status, status.lower() or 'connu')}" + (
            ", protection rétablie" if previous.get("passthroughMode") or previous.get("auditMode") else "")
    return Event(
        ts=received,
        module=MODULE,
        kind="alert" if severity else "event",
        category="configuration",
        action=action,
        severity=severity,
        host_name=site,
        rule_name={"site_passthrough": "Protection WAF contournée", "site_audit_mode": "WAF en mode audit",
                   "site_unreachable": "Site injoignable par OGO"}.get(action, "État du site"),
        threat_name="SITE",
        observer="OGO",
        reference=DASHBOARD,
        message=f"OGO : {site or '?'} — {text}" + (f" ; cluster {state['cluster']}" if state.get("cluster") else ""),
        raw=json.dumps(record, ensure_ascii=False, default=str),
    )
