"""Paramètres modifiables depuis l'interface (annuaire AD, messagerie, IA).

Ordre de priorité : valeur en base (saisie dans l'interface) > variable d'environnement > valeur par défaut.
Les secrets sont chiffrés en base (AES-256-GCM) et ne sont jamais renvoyés au navigateur.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc.ai.catalog import BUILTIN as AI_BUILTIN
from minisoc.ai.catalog import CUSTOM_ID as AI_CUSTOM_ID
from minisoc.config import Settings, get_settings
from minisoc.crypto import CryptoError, decrypt, encrypt
from minisoc.models import Setting


@dataclass(frozen=True)
class Field:
    group: str
    kind: str  # str | int | bool | list | pem | choice
    default: Any = ""
    secret: bool = False
    env: str = ""  # attribut de Settings utilisé en repli
    choices: tuple[str, ...] = ()


DEFAULT_USER_FILTER = "(&(objectCategory=person)(objectClass=user)(sAMAccountName={username}))"

FIELDS: dict[str, Field] = {
    # Annuaire Active Directory (LDAPS)
    "ldap_enabled": Field("ldap", "bool", False),
    "ldap_url": Field("ldap", "str", ""),  # ldaps://dc01.domaine.local:636
    "ldap_ca_cert": Field("ldap", "pem", ""),  # autorité de certification de l'AD (PEM)
    "ldap_bind_dn": Field("ldap", "str", ""),  # compte de service en lecture seule
    "ldap_bind_password": Field("ldap", "str", "", secret=True),
    "ldap_base_dn": Field("ldap", "str", ""),
    "ldap_user_filter": Field("ldap", "str", DEFAULT_USER_FILTER),
    "ldap_group_admin": Field("ldap", "str", ""),  # DN des groupes AD donnant chaque rôle
    "ldap_group_analyst": Field("ldap", "str", ""),
    "ldap_group_viewer": Field("ldap", "str", ""),
    "ldap_timeout": Field("ldap", "int", 8),
    # Messagerie (SMTP)
    "smtp_host": Field("smtp", "str", "", env="smtp_host"),
    "smtp_port": Field("smtp", "int", 587, env="smtp_port"),
    "smtp_security": Field("smtp", "choice", "starttls", choices=("starttls", "ssl", "none")),
    "smtp_user": Field("smtp", "str", "", env="smtp_user"),
    "smtp_password": Field("smtp", "str", "", secret=True, env="smtp_password"),
    "smtp_from": Field("smtp", "str", "", env="smtp_from"),
    "smtp_to": Field("smtp", "list", [], env="smtp_to"),
    "smtp_ca_cert": Field("smtp", "pem", ""),
    # Intégrations (catalogue) : activation des sources et fonctions
    "src_sophos_xgs_enabled": Field("integrations", "bool", False),
    "src_bitdefender_enabled": Field("integrations", "bool", False),
    "src_harfanglab_enabled": Field("integrations", "bool", False),
    "src_m365_enabled": Field("integrations", "bool", False),
    "src_ninjaone_enabled": Field("integrations", "bool", False),
    "src_cyberwatch_enabled": Field("integrations", "bool", False),
    "src_crowdsec_enabled": Field("integrations", "bool", False),
    "src_windows_enabled": Field("integrations", "bool", False),
    "src_dns_enabled": Field("integrations", "bool", False),
    "src_vectra_enabled": Field("integrations", "bool", False),
    "src_varonis_enabled": Field("integrations", "bool", False),
    "src_ogo_enabled": Field("integrations", "bool", False),
    "src_wordpress_enabled": Field("integrations", "bool", False),
    "src_syslog_enabled": Field("integrations", "bool", False),
    "geoip_enabled": Field("integrations", "bool", False),
    "bitdefender_token": Field("connectors", "str", "", secret=True, env="bitdefender_token"),
    "bitdefender_allowed_ips": Field("connectors", "list", [], env="bitdefender_allowed_ips"),
    "bitdefender_console_url": Field("connectors", "str", "https://cloudgz.gravityzone.bitdefender.com",
                                     env="bitdefender_console_url"),
    # Connecteurs d'API (interrogés par le worker ; modifiables sans redémarrage)
    "harfanglab_url": Field("connectors", "str", "", env="harfanglab_url"),
    "harfanglab_token": Field("connectors", "str", "", secret=True, env="harfanglab_token"),
    "harfanglab_verify_tls": Field("connectors", "bool", True, env="harfanglab_verify_tls"),
    # Clôture dans le Mini-SOC de ce qui est traité dans l'outil (minisoc/source_sync.py)
    "harfanglab_sync_status": Field("connectors", "bool", True),
    "ninjaone_sync_status": Field("connectors", "bool", True),
    "cyberwatch_sync_status": Field("connectors", "bool", True),
    "varonis_sync_status": Field("connectors", "bool", True),
    "bitdefender_sync_status": Field("connectors", "bool", True),
    # Export vers un SIEM ou un SOC externe (minisoc/export.py)
    "export_enabled": Field("connectors", "bool", False),
    "export_host": Field("connectors", "str", ""),
    "export_port": Field("connectors", "int", 6514),
    "export_protocol": Field("connectors", "choice", "tls", choices=("tls", "tcp", "udp")),
    "export_tls_verify": Field("connectors", "bool", True),
    "export_format": Field("connectors", "choice", "json", choices=("json", "cef")),
    "export_scope": Field("connectors", "choice", "alerts", choices=("alerts", "both")),
    "export_min_severity": Field("connectors", "choice", "low",
                                 choices=("info", "low", "medium", "high", "critical")),
    "export_hostname": Field("connectors", "str", "minisoc"),
    # Archives scellées des événements (minisoc/archives.py)
    "archive_enabled": Field("retention", "bool", True),
    # Suivi des alertes (minisoc/followup.py) : échéances par sévérité, prise en charge (heures) et traitement (jours)
    "sla_ack_critical": Field("followup", "int", 1),
    "sla_ack_high": Field("followup", "int", 4),
    "sla_ack_medium": Field("followup", "int", 24),
    "sla_ack_low": Field("followup", "int", 72),
    "sla_resolve_critical": Field("followup", "int", 1),
    "sla_resolve_high": Field("followup", "int", 3),
    "sla_resolve_medium": Field("followup", "int", 7),
    "sla_resolve_low": Field("followup", "int", 30),
    "assign_notify": Field("followup", "bool", True),  # e-mail à la personne à qui une alerte est assignée
    # Écran mural (commun à tous les écrans) : écrans qui défilent et leur ordre, durée, alertes affichées aussitôt
    "wall_pages": Field("wall", "list", ["alertes", "vpn", "auth", "vuln", "sources"]),
    "wall_rotation": Field("wall", "int", 20),  # secondes par écran, 0 = pas de défilement
    "wall_flash_min_severity": Field("wall", "choice", "high", choices=("medium", "high", "critical")),
    "wall_sound_default": Field("wall", "bool", False),  # son discret, modifiable sur chaque écran
    "harfanglab_history_days": Field("connectors", "int", 0),  # profondeur de relecture (jours, 0 = tout l'historique)
    # NinjaOne (parc) : application « Services API », portée monitoring (lecture seule)
    "ninjaone_instance": Field("connectors", "str", "eu"),  # eu, us, ca, oc ou nom d'hôte
    "ninjaone_client_id": Field("connectors", "str", ""),
    "ninjaone_client_secret": Field("connectors", "str", "", secret=True),
    # Varonis SaaS : clé d'API au rôle « Threat Detection Integrator » (recherche d'alertes)
    "varonis_url": Field("connectors", "str", ""),  # https://<tenant>.varonis.io
    "varonis_api_key": Field("connectors", "str", "", secret=True),
    # GravityZone : clé d'API de lecture (Incidents, Quarantaine), distincte de la clé d'isolation
    "bitdefender_read_api_key": Field("connectors", "str", "", secret=True),
    "bitdefender_history_days": Field("connectors", "int", 365),  # relu au raccordement (jours, 0 = tout)
    # Cyberwatch (vulnérabilités) : clé d'API en lecture seule, authentification Basic
    "cyberwatch_url": Field("connectors", "str", ""),  # https://cyberwatch.mairie.local
    "cyberwatch_access_key": Field("connectors", "str", ""),
    "cyberwatch_secret_key": Field("connectors", "str", "", secret=True),
    "cyberwatch_verify_tls": Field("connectors", "bool", True),
    "cyberwatch_ca_cert": Field("connectors", "pem", ""),
    # MaxMind GeoLite2 (compte gratuit) : bases de géolocalisation téléchargées par le worker (geoip_update.py)
    "maxmind_account_id": Field("connectors", "str", ""),
    "maxmind_license_key": Field("connectors", "str", "", secret=True),
    # Vectra AI : client d'API OAuth2 en lecture seule (détections et scores d'entités, API v3.4)
    "vectra_url": Field("connectors", "str", ""),  # https://brain.mairie.local ou https://<id>.portal.vectra.ai
    "vectra_client_id": Field("connectors", "str", ""),
    "vectra_client_secret": Field("connectors", "str", "", secret=True),
    "vectra_verify_tls": Field("connectors", "bool", True),
    "vectra_ca_cert": Field("connectors", "pem", ""),
    # OGO Security (WAF) : compte en lecture seule (rôle Viewer) ; en-tête X-Ogo-Auth = e-mail + empreinte de la clé
    "ogo_api_url": Field("connectors", "str", "https://api.ogosecurity.com"),
    "ogo_email": Field("connectors", "str", ""),
    "ogo_api_key": Field("connectors", "str", "", secret=True),
    "ogo_organization": Field("connectors", "str", ""),  # vide : la seule organisation du compte
    # WordPress : sites inventoriés chaque jour ([{url, user, password}] chiffré), failles connues par WPScan
    "wordpress_sites": Field("connectors", "str", "[]", secret=True),
    "wordpress_wpscan_token": Field("connectors", "str", "", secret=True),
    "wordpress_wpscan_daily": Field("connectors", "int", 25),  # quota quotidien (offre gratuite : 25)
    "wordpress_verify_tls": Field("connectors", "bool", True),
    # Microsoft 365 / Entra ID : inscription d'application (ActivityFeed.Read), journal d'audit unifié
    "m365_tenant_id": Field("connectors", "str", ""),
    "m365_client_id": Field("connectors", "str", ""),
    "m365_client_secret": Field("connectors", "str", "", secret=True),
    "m365_exchange": Field("connectors", "bool", True),  # règles de transfert de messagerie (Audit.Exchange)
    "crowdsec_url": Field("connectors", "str", ""),  # API locale (LAPI), ex. http://crowdsec:8080
    "crowdsec_api_key": Field("connectors", "str", "", secret=True),  # clé de bouncer (lecture seule)
    "crowdsec_community": Field("connectors", "bool", True),  # inclure la liste communautaire (enrichissement)
    # Réponse : blocage d'IP sur le Sophos XGS (API XML)
    "response_enabled": Field("response", "bool", False),
    "xgs_url": Field("response", "str", ""),  # https://xgs.mairie.local:4444
    "xgs_user": Field("response", "str", ""),
    "xgs_password": Field("response", "str", "", secret=True),
    "xgs_verify_tls": Field("response", "bool", True),
    "xgs_ca_cert": Field("response", "pem", ""),
    "xgs_block_group": Field("response", "str", "MiniSOC-Blocages"),
    "block_default_hours": Field("response", "int", 24),
    # Isolation de poste par l'EDR (F-27) : jetons distincts des jetons de lecture
    "isolation_enabled": Field("response", "bool", False),
    "harfanglab_isolation_token": Field("response", "str", "", secret=True),
    "bitdefender_api_url": Field("response", "str", "https://cloudgz.gravityzone.bitdefender.com/api"),
    "bitdefender_api_key": Field("response", "str", "", secret=True),
    "never_block": Field("response", "list", ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]),
    # Détection
    "home_countries": Field("detection", "list", ["FR"]),  # pays habituels des connexions (codes ISO)
    # DNS interne (Active Directory) : noms des adresses internes affichés à côté des adresses (résolution inverse)
    "dns_server": Field("detection", "str", ""),
    "threat_feeds_enabled": Field("detection", "bool", False),  # veille CISA KEV et CERT-FR (accès Internet)
    # Comptes sensibles (minisoc/accounts.py) : motifs de noms en plus de la liste lue dans l'AD
    "accounts_ad_sync": Field("detection", "bool", True),  # admins (adminCount=1) et comptes de service lus dans l'AD
    "accounts_admin_patterns": Field("detection", "list", ["administrateur", "administrator", "adm-*", "adm_*",
                                                           "admin-*", "admin_*"]),
    "accounts_service_patterns": Field("detection", "list", ["svc*", "sa-*", "sa_*", "srv-*", "srv_*"]),
    # Score de risque et chaînes d'attaque (minisoc/risk.py)
    "risk_threshold": Field("detection", "int", 60),
    "chain_auto_incident": Field("detection", "bool", True),
    # Espace des disques de la VM (minisoc/hostdisk.py) : alerte UC-63 au-delà de cette occupation (%)
    "disk_alert_percent": Field("detection", "int", 85),
    # Leurres (minisoc/decoys.py) : toute activité touchant ces éléments est malveillante
    "decoy_accounts": Field("detection", "list", []),
    "decoy_paths": Field("detection", "list", []),
    "decoy_hosts": Field("detection", "list", []),
    "decoy_tokens": Field("detection", "list", []),
    # DNS : domaines de confiance exclus des règles tunnel / DGA (éditeurs, antivirus, CDN, résolution inverse)
    "dns_trusted_domains": Field("detection", "list", [
        "microsoft.com", "windows.com", "windowsupdate.com", "office.com", "office365.com", "office.net",
        "live.com", "msftncsi.com", "azure.com", "azureedge.net", "trafficmanager.net", "akamai.net",
        "akamaiedge.net", "akadns.net", "cloudfront.net", "amazonaws.com", "googleapis.com", "gstatic.com",
        "google.com", "apple.com", "icloud.com", "sophos.com", "sophosxl.net", "bitdefender.com", "bitdefender.net",
        "hurukai.io", "ninjarmm.com", "in-addr.arpa", "ip6.arpa",
    ]),
    # Conservation des données (RGPD) : appliquée chaque nuit par le worker
    "events_retention_days": Field("retention", "int", 365),  # journaux (90 j consultables par défaut, puis archive)
    "alerts_retention_days": Field("retention", "int", 1095),  # alertes clôturées
    # Notifications : Teams, mobile (ntfy), escalade, résumé quotidien
    "teams_webhook_url": Field("notify", "str", "", secret=True, env="teams_webhook_url"),
    "ntfy_url": Field("notify", "str", "", env="ntfy_url"),
    "ntfy_topic": Field("notify", "str", "", env="ntfy_topic"),
    "ntfy_token": Field("notify", "str", "", secret=True, env="ntfy_token"),
    # Routage : canaux par sévérité (email, teams, ntfy) et sévérités notifiées seulement aux heures ouvrées
    "route_critical": Field("notify", "list", ["ntfy", "teams", "email"]),
    "route_high": Field("notify", "list", ["teams", "email"]),
    "route_medium": Field("notify", "list", ["email"]),
    "route_low": Field("notify", "list", []),
    "business_hours_only": Field("notify", "list", ["medium"]),
    "business_hours_start": Field("notify", "int", 8),
    "business_hours_end": Field("notify", "int", 18),
    "business_days": Field("notify", "list", ["1", "2", "3", "4", "5"]),  # 1 = lundi … 7 = dimanche
    "escalation_enabled": Field("notify", "bool", True),
    "escalation_minutes": Field("notify", "int", 30),
    "escalation_min_severity": Field("notify", "choice", "critical", choices=("high", "critical")),
    "escalation_to": Field("notify", "list", []),  # second contact (e-mails)
    "escalation_ntfy_topic": Field("notify", "str", ""),  # sujet ntfy du second contact
    "digest_enabled": Field("notify", "bool", True),
    "digest_hour": Field("notify", "int", 8),
    "digest_to": Field("notify", "list", []),  # vide = destinataires des alertes
    "report_monthly_enabled": Field("notify", "bool", True),  # rapport mensuel le 1er (comme le résumé)
    # Assistant IA
    "ai_enabled": Field("ai", "bool", False),
    "ai_provider": Field("ai", "str", "anthropic"),  # fournisseur intégré (ai/catalog.py) ou « custom-xxxxxxxx »
    "ai_model": Field("ai", "str", ""),
    "ai_api_key": Field("ai", "str", "", secret=True),  # ancien champ unique (repli de la clé du fournisseur actif)
    "ai_provider_keys": Field("ai", "str", "{}", secret=True),  # {fournisseur: clé} (JSON chiffré)
    "ai_custom_providers": Field("ai", "str", "[]"),  # [{id, name, base_url}] compatibles OpenAI
    "ai_base_url": Field("ai", "str", ""),  # adresse du serveur Ollama : http://serveur-ia:11434
    "ai_effort": Field("ai", "choice", "medium", choices=("low", "medium", "high")),
    "ai_max_tokens": Field("ai", "int", 16000),
    "ai_pseudonymize": Field("ai", "bool", True),
    "ai_org_networks": Field("ai", "list", []),  # IP publiques de la collectivité, pseudonymisées (IP_ORG_n)
    "ai_internal_domains": Field("ai", "list", []),  # domaines internes en plus de ceux de l'annuaire
}

GROUPS = sorted({f.group for f in FIELDS.values()})
WALL_PAGES = ("alertes", "vpn", "auth", "vuln", "sources")
_CACHE_SECONDS = 30
CHANNELS = ("email", "teams", "ntfy")


class SettingsError(ValueError):
    pass


def _parse(field: Field, raw: str) -> Any:
    if field.kind == "int":
        return int(raw) if raw not in ("", None) else field.default
    if field.kind == "bool":
        return str(raw).lower() in ("1", "true", "oui", "on")
    if field.kind == "list":
        return [item.strip() for item in str(raw).replace(";", ",").split(",") if item.strip()]
    return raw


def _serialize(field: Field, value: Any) -> str:
    if field.kind == "list":
        items = value if isinstance(value, list) else str(value).replace(";", ",").split(",")
        return ",".join(str(i).strip() for i in items if str(i).strip())
    if field.kind == "bool":
        return "true" if value else "false"
    return "" if value is None else str(value)


def validate(key: str, value: Any) -> Any:
    field = FIELDS.get(key)
    if field is None:
        raise SettingsError(f"paramètre inconnu : {key}")
    if field.kind == "int":
        try:
            value = int(value)
        except (TypeError, ValueError):
            raise SettingsError(f"{key} : nombre entier attendu") from None
        if not 0 <= value <= 65535:
            raise SettingsError(f"{key} : valeur hors limites")
    elif field.kind == "choice" and value not in field.choices:
        raise SettingsError(f"{key} : valeur attendue parmi {', '.join(field.choices)}")
    elif field.kind == "pem" and value:
        value = str(value).strip()
        _check_pem(key, value)
    elif field.kind in ("str",) and value is not None and len(str(value)) > (
            20000 if key in ("ai_provider_keys", "ai_custom_providers") else 2000):
        raise SettingsError(f"{key} : valeur trop longue")
    if key == "ldap_url" and value:
        if not str(value).lower().startswith("ldaps://"):
            raise SettingsError("ldap_url : seul LDAPS est accepté (ldaps://serveur:636) ; le LDAP en clair est refusé")
    if key == "ogo_api_url" and value and not str(value).lower().startswith("https://"):
        raise SettingsError("ogo_api_url : adresse https:// attendue")
    if key in ("harfanglab_url", "crowdsec_url", "vectra_url") and value and not str(value).lower().startswith(("http://", "https://")):
        raise SettingsError(f"{key} : adresse http(s):// attendue")
    if key == "ai_base_url" and value and not str(value).lower().startswith(("http://", "https://")):
        raise SettingsError("ai_base_url : adresse http(s):// attendue")
    if key == "ai_provider" and value not in AI_BUILTIN and not AI_CUSTOM_ID.match(str(value)):
        raise SettingsError("ai_provider : fournisseur inconnu")
    if key == "ai_custom_providers":
        _check_custom_providers(value)
    if key == "home_countries":
        items = value if isinstance(value, list) else str(value).replace(";", ",").split(",")
        if any(not re.fullmatch(r"[A-Za-z]{2}", str(c).strip()) for c in items if str(c).strip()):
            raise SettingsError("home_countries : codes pays ISO à 2 lettres (ex. FR, BE)")
    if key in ("never_block", "ai_org_networks"):
        import ipaddress
        for net in value if isinstance(value, list) else str(value).replace(";", ",").split(","):
            if str(net).strip():
                try:
                    ipaddress.ip_network(str(net).strip(), strict=False)
                except ValueError:
                    raise SettingsError(f"{key} : réseau invalide {net}") from None
    if key == "ai_internal_domains":
        items = value if isinstance(value, list) else str(value).replace(";", ",").split(",")
        for domain in (str(d).strip().strip(".") for d in items):
            if domain and not re.fullmatch(r"[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+", domain):
                raise SettingsError(f"ai_internal_domains : domaine invalide {domain} (ex. mairie.local)")
    if key == "wordpress_wpscan_daily" and not 1 <= int(value) <= 100000:
        raise SettingsError("wordpress_wpscan_daily : entre 1 et 100000 requêtes par jour")
    if key == "wordpress_sites":
        try:
            items = json.loads(value or "[]")
        except ValueError:
            raise SettingsError("wordpress_sites : JSON invalide") from None
        if not isinstance(items, list) or not all(isinstance(i, dict) and i.get("url") for i in items):
            raise SettingsError("wordpress_sites : liste de sites {url, user, password} attendue")
    if key == "xgs_block_group" and value and not re.fullmatch(r"[\w .-]{1,50}", str(value)):
        raise SettingsError("xgs_block_group : 50 caractères maximum (lettres, chiffres, espace, . _ -)")
    if key == "block_default_hours" and not 1 <= int(value) <= 24 * 90:
        raise SettingsError("block_default_hours : entre 1 et 2160 heures")
    if key == "events_retention_days" and not 30 <= int(value) <= 3650:
        raise SettingsError("events_retention_days : entre 30 et 3650 jours")
    if key == "alerts_retention_days" and not 365 <= int(value) <= 3650:
        raise SettingsError("alerts_retention_days : entre 365 et 3650 jours (1 an minimum)")
    if key.startswith("route_"):
        items = value if isinstance(value, list) else str(value).replace(";", ",").split(",")
        unknown = [c for c in (str(i).strip() for i in items) if c and c not in CHANNELS]
        if unknown:
            raise SettingsError(f"{key} : canal inconnu {', '.join(unknown)} (attendus : {', '.join(CHANNELS)})")
    if key == "business_hours_only":
        items = value if isinstance(value, list) else str(value).replace(";", ",").split(",")
        if any(str(i).strip() not in ("critical", "high", "medium", "low") for i in items if str(i).strip()):
            raise SettingsError("business_hours_only : sévérités parmi critical, high, medium, low")
    if key in ("business_hours_start", "business_hours_end") and not 0 <= int(value) <= 24:
        raise SettingsError(f"{key} : heure entre 0 et 24")
    if key == "business_days":
        items = value if isinstance(value, list) else str(value).replace(";", ",").split(",")
        if any(str(i).strip() not in "1234567" or len(str(i).strip()) != 1 for i in items if str(i).strip()):
            raise SettingsError("business_days : jours de 1 (lundi) à 7 (dimanche)")
    if key.startswith("sla_") and not 1 <= int(value) <= 8760:
        raise SettingsError(f"{key} : entre 1 et 8760")
    if key == "dns_server" and value:
        import ipaddress

        try:
            ipaddress.ip_address(str(value).strip())
        except ValueError:
            raise SettingsError("dns_server : adresse IP du serveur DNS interne attendue (ex. 192.168.2.9)") from None
    if key == "wall_pages":
        raw = value if isinstance(value, list) else str(value).split(",")
        items = [str(i).strip() for i in raw if str(i).strip()]
        unknown = [i for i in items if i not in WALL_PAGES]
        if unknown or "alertes" not in items:
            raise SettingsError(f"wall_pages : écrans parmi {', '.join(WALL_PAGES)}, « alertes » obligatoire")
    if key == "wall_rotation" and not 0 <= int(value) <= 600:
        raise SettingsError("wall_rotation : entre 0 (pas de défilement) et 600 secondes")
    if key == "disk_alert_percent" and not 50 <= int(value) <= 98:
        raise SettingsError("disk_alert_percent : entre 50 et 98 %")
    if key == "risk_threshold" and not 20 <= int(value) <= 1000:
        raise SettingsError("risk_threshold : entre 20 et 1000 points")
    if key == "bitdefender_history_days" and not 0 <= int(value) <= 3650:
        raise SettingsError("bitdefender_history_days : entre 0 (tout l'historique) et 3650 jours")
    if key == "harfanglab_history_days" and not 0 <= int(value) <= 3650:
        raise SettingsError("harfanglab_history_days : entre 0 (tout l'historique) et 3650 jours")
    if key == "digest_hour" and not 0 <= int(value) <= 23:
        raise SettingsError("digest_hour : heure entre 0 et 23")
    if key == "escalation_minutes" and not 5 <= int(value) <= 1440:
        raise SettingsError("escalation_minutes : entre 5 et 1440")
    if key in ("ntfy_url", "teams_webhook_url") and value and not str(value).lower().startswith("https://"):
        if not (key == "ntfy_url" and str(value).lower().startswith("http://")):
            raise SettingsError(f"{key} : adresse https:// attendue")
    if key == "ai_max_tokens" and not 256 <= int(value) <= 64000:
        raise SettingsError("ai_max_tokens : entre 256 et 64000")
    if key == "ldap_user_filter" and value and "{username}" not in str(value):
        raise SettingsError("ldap_user_filter doit contenir {username}")
    return value


def _check_custom_providers(value: Any) -> None:
    import json

    try:
        items = json.loads(value) if isinstance(value, str) else value
    except ValueError:
        raise SettingsError("ai_custom_providers : JSON invalide") from None
    if not isinstance(items, list) or len(items) > 20:
        raise SettingsError("ai_custom_providers : liste de 20 fournisseurs au plus")
    for item in items:
        if not isinstance(item, dict) or not AI_CUSTOM_ID.match(str(item.get("id", ""))):
            raise SettingsError("ai_custom_providers : identifiant invalide")
        if not str(item.get("base_url", "")).lower().startswith(("http://", "https://")):
            raise SettingsError("ai_custom_providers : adresse http(s):// attendue")


def _check_pem(key: str, value: str) -> None:
    from cryptography import x509

    try:
        certs = x509.load_pem_x509_certificates(value.encode())
    except ValueError:
        raise SettingsError(f"{key} : certificat PEM invalide") from None
    if not certs:
        raise SettingsError(f"{key} : aucun certificat trouvé")


class SettingsStore:
    """Lecture avec cache court (le worker relit les paramètres sans redémarrer)."""

    def __init__(self, env: Settings | None = None) -> None:
        self.env = env or get_settings()
        self._cache: dict[str, Any] = {}
        self._loaded_at = 0.0

    async def load(self, session: AsyncSession, *, force: bool = False) -> dict[str, Any]:
        if not force and self._cache and time.monotonic() - self._loaded_at < _CACHE_SECONDS:
            return self._cache
        rows = {s.key: s for s in (await session.scalars(select(Setting))).all()}
        values: dict[str, Any] = {}
        for key, field in FIELDS.items():
            row = rows.get(key)
            if row is not None:
                raw = row.value
                if row.is_secret and raw:
                    try:
                        raw = decrypt(raw)
                    except (CryptoError, ValueError):
                        raise SettingsError(
                            f"{key} : déchiffrement impossible (MINISOC_MASTER_KEY a-t-elle changé ?)"
                        ) from None
                values[key] = _parse(field, raw)
            elif field.env and getattr(self.env, field.env, None) not in (None, "", []):
                values[key] = getattr(self.env, field.env)
            else:
                values[key] = field.default
        if rows.get("smtp_security") is None and not self.env.smtp_starttls and values["smtp_port"] != 465:
            values["smtp_security"] = "none"
        self._cache, self._loaded_at = values, time.monotonic()
        return values

    def invalidate(self) -> None:
        self._loaded_at = 0.0

    async def public(self, session: AsyncSession, group: str) -> dict[str, Any]:
        """Valeurs d'un groupe pour l'interface : un secret n'est jamais renvoyé, seulement s'il est défini."""
        return await self.public_keys(session, [k for k, f in FIELDS.items() if f.group == group])

    async def public_keys(self, session: AsyncSession, keys: list[str]) -> dict[str, Any]:
        values = await self.load(session, force=True)
        return {k: ({"set": bool(values[k])} if FIELDS[k].secret else values[k]) for k in keys if k in FIELDS}

    async def update(self, session: AsyncSession, group: str, changes: dict[str, Any], actor: str) -> list[str]:
        """Enregistre les champs d'un groupe et retourne les clés modifiées."""
        allowed = {k for k, f in FIELDS.items() if f.group == group}
        return await self.update_keys(session, allowed, changes, actor)

    async def update_keys(self, session: AsyncSession, allowed: set[str], changes: dict[str, Any],
                          actor: str) -> list[str]:
        """Enregistre les champs fournis (limités à `allowed`). Secret : chaîne vide = inchangé, None = effacer."""
        rows = {s.key: s for s in (await session.scalars(select(Setting))).all()}
        changed = []
        for key, value in changes.items():
            field = FIELDS.get(key)
            if field is None or key not in allowed:
                raise SettingsError(f"paramètre non modifiable ici : {key}")
            if field.secret and value == "":
                continue
            value = validate(key, "" if value is None else value) if value is not None else ""
            stored = _serialize(field, value)
            if field.secret and stored:
                stored = encrypt(stored)
            row = rows.get(key)
            if row is None:
                session.add(Setting(key=key, value=stored, is_secret=field.secret, updated_by=actor))
            elif row.value != stored:
                row.value, row.updated_by = stored, actor
            else:
                continue
            changed.append(key)
        self.invalidate()
        return changed


store = SettingsStore()
