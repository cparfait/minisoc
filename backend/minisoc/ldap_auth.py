"""Authentification Active Directory en LDAPS.

Principe :
  1. Connexion TLS au contrôleur de domaine, certificat toujours vérifié (pas de désactivation possible).
  2. Le compte de service (lecture seule) recherche l'utilisateur (filtre échappé, RFC 4515).
  3. Le mot de passe est vérifié par une connexion LDAP au nom de l'utilisateur (bind).
  4. Le rôle est déduit de l'appartenance aux groupes AD, y compris imbriqués (LDAP_MATCHING_RULE_IN_CHAIN).
     Aucun groupe correspondant = accès refusé.
Les fonctions sont bloquantes (ldap3) : les appeler via asyncio.to_thread.
"""

from __future__ import annotations

import re
import ssl
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlparse

from ldap3 import BASE, NONE, SUBTREE, Connection, Server, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.utils.conv import escape_filter_chars

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
IN_CHAIN = "1.2.840.113556.1.4.1941"
ROLE_ORDER = (("admin", "ldap_group_admin"), ("analyst", "ldap_group_analyst"), ("viewer", "ldap_group_viewer"))
UAC_DISABLED = 0x2

# Sous-codes Active Directory renvoyés dans le message d'erreur d'un bind refusé (« data 52e »)
AD_ERRORS = {
    "525": "unknown_user",
    "52e": "invalid_credentials",
    "530": "logon_hours",
    "531": "workstation",
    "532": "password_expired",
    "533": "disabled",
    "701": "account_expired",
    "773": "must_change_password",
    "775": "locked",
}
# Motifs qu'on peut afficher sans aider un attaquant : AD ne les renvoie que si le mot de passe est correct
DISCLOSABLE = {
    "password_expired": "Votre mot de passe a expiré : changez-le depuis un poste Windows, puis reconnectez-vous.",
    "must_change_password": "Vous devez changer votre mot de passe : faites-le depuis un poste Windows.",
    "logon_hours": "Connexion non autorisée à cette heure par la politique du domaine.",
}


class LdapConfigError(RuntimeError):
    """Configuration incomplète ou annuaire injoignable (problème d'administration, pas d'utilisateur)."""


class LdapAuthFailed(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason

    @property
    def user_message(self) -> str | None:
        return DISCLOSABLE.get(self.reason)


@dataclass
class LdapUser:
    username: str
    dn: str
    display_name: str = ""
    email: str = ""
    role: str = ""
    groups: list[str] = field(default_factory=list)


def _server(cfg: dict[str, Any]) -> Server:
    url = urlparse(cfg.get("ldap_url") or "")
    if url.scheme.lower() != "ldaps" or not url.hostname:
        raise LdapConfigError("URL LDAPS invalide (attendu : ldaps://dc01.domaine.local:636)")
    tls = Tls(
        validate=ssl.CERT_REQUIRED,
        version=ssl.PROTOCOL_TLS_CLIENT,
        ca_certs_data=cfg.get("ldap_ca_cert") or None,
    )
    return Server(url.hostname, port=url.port or 636, use_ssl=True, tls=tls, get_info=NONE,
                  connect_timeout=int(cfg.get("ldap_timeout") or 8))


def _connect(cfg: dict[str, Any], user: str, password: str) -> Connection:
    conn = Connection(_server(cfg), user=user, password=password, receive_timeout=int(cfg.get("ldap_timeout") or 8),
                      raise_exceptions=False, read_only=True)
    try:
        conn.open()
    except LDAPException as exc:
        raise LdapConfigError(_tls_hint(exc)) from exc
    return conn


def _tls_hint(exc: Exception) -> str:
    text = str(exc)
    if "certificate" in text.lower() or "hostname" in text.lower() or "CERTIFICATE_VERIFY_FAILED" in text:
        return ("Certificat du contrôleur de domaine refusé : renseigner l'autorité de certification de l'AD et "
                f"utiliser le nom DNS figurant dans le certificat (pas l'adresse IP). Détail : {text[:200]}")
    return f"Annuaire injoignable : {text[:200]}"


def _service_connection(cfg: dict[str, Any]) -> Connection:
    if not cfg.get("ldap_bind_dn") or not cfg.get("ldap_bind_password"):
        raise LdapConfigError("Compte de service AD non configuré")
    if not cfg.get("ldap_base_dn"):
        raise LdapConfigError("Base DN non configurée")
    conn = _connect(cfg, cfg["ldap_bind_dn"], cfg["ldap_bind_password"])
    if not conn.bind():
        raise LdapConfigError(f"Connexion du compte de service refusée ({_ad_reason(conn.result) or 'identifiants'})")
    return conn


def _ad_reason(result: dict | None) -> str:
    message = (result or {}).get("message", "") or ""
    match = re.search(r"data ([0-9a-f]{3})", message, re.IGNORECASE)
    return AD_ERRORS.get(match.group(1).lower(), "") if match else ""


def _find_user(conn: Connection, cfg: dict[str, Any], username: str) -> dict | None:
    flt = (cfg.get("ldap_user_filter") or "").replace("{username}", escape_filter_chars(username))
    conn.search(cfg["ldap_base_dn"], flt, SUBTREE, attributes=["sAMAccountName", "displayName", "mail",
                                                                 "userAccountControl"], size_limit=2)
    entries = [e for e in conn.response or [] if e.get("type") == "searchResEntry"]
    if len(entries) > 1:
        raise LdapConfigError("Plusieurs comptes correspondent : préciser le filtre utilisateur")
    return entries[0] if entries else None


def _member_of(conn: Connection, user_dn: str, group_dn: str) -> bool:
    """Appartenance directe ou imbriquée, évaluée par le contrôleur de domaine."""
    flt = f"(memberOf:{IN_CHAIN}:={escape_filter_chars(group_dn)})"
    conn.search(user_dn, flt, BASE, attributes=["distinguishedName"])
    return any(e.get("type") == "searchResEntry" for e in conn.response or [])


def resolve_role(conn: Connection, cfg: dict[str, Any], user_dn: str) -> tuple[str, list[str]]:
    configured = [(role, cfg.get(key)) for role, key in ROLE_ORDER if cfg.get(key)]
    if not configured:
        raise LdapConfigError("Aucun groupe AD associé à un rôle : accès refusé par défaut")
    matched = [group for _, group in configured if _member_of(conn, user_dn, group)]
    for role, group in configured:
        if group in matched:
            return role, matched
    return "", matched


def authenticate(cfg: dict[str, Any], username: str, password: str) -> LdapUser:
    """Lève LdapAuthFailed (refus imputable à l'utilisateur) ou LdapConfigError (problème d'annuaire)."""
    if not cfg.get("ldap_enabled"):
        raise LdapConfigError("Authentification AD désactivée")
    if not USERNAME_RE.match(username) or not password:
        raise LdapAuthFailed("invalid_credentials")  # aussi : un mot de passe vide ferait un bind anonyme
    service = _service_connection(cfg)
    try:
        entry = _find_user(service, cfg, username)
        if entry is None:
            raise LdapAuthFailed("unknown_user")
        attrs = entry.get("attributes", {})
        dn = entry["dn"]
        if int(attrs.get("userAccountControl") or 0) & UAC_DISABLED:
            raise LdapAuthFailed("disabled")

        user_conn = _connect(cfg, dn, password)
        try:
            if not user_conn.bind():
                raise LdapAuthFailed(_ad_reason(user_conn.result) or "invalid_credentials")
        finally:
            user_conn.unbind()

        role, groups = resolve_role(service, cfg, dn)
        if not role:
            raise LdapAuthFailed("no_group")
        return LdapUser(
            username=str(attrs.get("sAMAccountName") or username).lower(),
            dn=dn,
            display_name=str(attrs.get("displayName") or ""),
            email=str(attrs.get("mail") or ""),
            role=role,
            groups=groups,
        )
    finally:
        service.unbind()


def test_connection(cfg: dict[str, Any], username: str = "", password: str = "") -> list[dict]:
    """Diagnostic pas à pas pour la page Paramètres (aucune session n'est créée)."""
    steps: list[dict] = []

    def step(label: str, ok: bool, detail: str = "") -> bool:
        steps.append({"step": label, "ok": ok, "detail": detail})
        return ok

    try:
        service = _service_connection(cfg)
    except LdapConfigError as exc:
        step("Connexion LDAPS et compte de service", False, str(exc))
        return steps
    try:
        step("Connexion LDAPS (certificat vérifié) et compte de service", True, cfg.get("ldap_url", ""))
        found = service.search(cfg["ldap_base_dn"], "(objectClass=*)", BASE)
        if not step("Lecture de la base DN", bool(found), cfg["ldap_base_dn"]):
            return steps
        for role, key in ROLE_ORDER:
            group = cfg.get(key)
            if group:
                exists = service.search(group, "(objectClass=group)", BASE)
                step(f"Groupe du rôle « {role} »", bool(exists), group if exists else f"introuvable : {group}")
        if username:
            try:
                user = authenticate(cfg, username, password)
                step(f"Connexion de {username}", True, f"{user.dn} → rôle {user.role}")
            except LdapAuthFailed as exc:
                step(f"Connexion de {username}", False, f"refusée : {exc.reason}")
            except LdapConfigError as exc:
                step(f"Connexion de {username}", False, str(exc))
    finally:
        service.unbind()
    return steps


# --- Comptes sensibles (surveillance : minisoc/accounts.py) ------------------------------------------------------

ADMIN_FILTER = "(&(objectCategory=person)(objectClass=user)(adminCount=1))"
SERVICE_FILTER = ("(|(&(objectCategory=person)(objectClass=user)(servicePrincipalName=*))"
                  "(objectClass=msDS-GroupManagedServiceAccount)(objectClass=msDS-ManagedServiceAccount))")
ACCOUNT_ATTRIBUTES = ["sAMAccountName", "displayName", "userAccountControl", "lastLogonTimestamp", "pwdLastSet",
                      "servicePrincipalName", "description"]
UAC_DONT_EXPIRE_PASSWORD = 0x10000
UAC_TRUSTED_FOR_DELEGATION = 0x80000
MAX_ACCOUNTS = 5000


def _single(value: Any) -> Any:
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _filetime(value: Any) -> str | None:
    """Date AD (FILETIME : centaines de ns depuis 1601) ou datetime → ISO 8601 ; jamais = None."""
    value = _single(value)
    if value is None or value == "":
        return None
    if hasattr(value, "isoformat"):
        return None if value.year <= 1601 else value.isoformat()
    try:
        ticks = int(value)
    except (TypeError, ValueError):
        return None
    if ticks <= 0 or ticks >= 0x7FFFFFFFFFFFFFFF:
        return None
    return (datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=ticks // 10)).isoformat()


def _account(entry: dict) -> dict | None:
    attrs = entry.get("attributes") or {}
    name = str(_single(attrs.get("sAMAccountName")) or "").strip()
    if not name:
        return None
    try:
        uac = int(_single(attrs.get("userAccountControl")) or 0)
    except (TypeError, ValueError):
        uac = 0
    spn = attrs.get("servicePrincipalName") or []
    return {
        "name": name,
        "display_name": str(_single(attrs.get("displayName")) or ""),
        "description": str(_single(attrs.get("description")) or "")[:200],
        "disabled": bool(uac & UAC_DISABLED),
        "password_never_expires": bool(uac & UAC_DONT_EXPIRE_PASSWORD),
        "unconstrained_delegation": bool(uac & UAC_TRUSTED_FOR_DELEGATION),
        "spn_count": len(spn) if isinstance(spn, list) else 1,
        "last_logon": _filetime(attrs.get("lastLogonTimestamp")),
        "password_set": _filetime(attrs.get("pwdLastSet")),
    }


def sensitive_accounts(cfg: dict[str, Any]) -> dict[str, list[dict]]:
    """Comptes à privilèges (adminCount=1 : membres actuels ou anciens des groupes protégés) et comptes de service
    (SPN, comptes de service gérés), lus avec le compte de service en lecture seule. Bloquant : asyncio.to_thread."""
    conn = _service_connection(cfg)
    try:
        result: dict[str, list[dict]] = {}
        for kind, flt in (("admin", ADMIN_FILTER), ("service", SERVICE_FILTER)):
            entries = conn.extend.standard.paged_search(cfg["ldap_base_dn"], flt, SUBTREE,
                                                        attributes=ACCOUNT_ATTRIBUTES, paged_size=500, generator=True)
            accounts = []
            for entry in entries:
                if entry.get("type") != "searchResEntry":
                    continue
                account = _account(entry)
                if account:
                    accounts.append(account)
                if len(accounts) >= MAX_ACCOUNTS:
                    break
            result[kind] = accounts
        return result
    finally:
        conn.unbind()


USER_FILTER = "(&(objectCategory=person)(objectClass=user))"
USER_ATTRIBUTES = ["sAMAccountName", "userPrincipalName", "mail", "displayName", "proxyAddresses"]
MAX_USERS = 50000


def user_identities(cfg: dict[str, Any]) -> list[dict]:
    """Formes du nom de chaque compte (identifiant, UPN, adresses de messagerie, nom affiché) : table des alias
    (minisoc/identity.py). Lecture seule. Bloquant : asyncio.to_thread."""
    conn = _service_connection(cfg)
    try:
        out = []
        entries = conn.extend.standard.paged_search(cfg["ldap_base_dn"], USER_FILTER, SUBTREE,
                                                    attributes=USER_ATTRIBUTES, paged_size=500, generator=True)
        for entry in entries:
            if entry.get("type") != "searchResEntry":
                continue
            attrs = entry.get("attributes") or {}
            sam = str(_single(attrs.get("sAMAccountName")) or "").strip()
            if not sam:
                continue
            proxies = attrs.get("proxyAddresses") or []
            out.append({
                "sam": sam,
                "upn": str(_single(attrs.get("userPrincipalName")) or ""),
                "mail": str(_single(attrs.get("mail")) or ""),
                "display": str(_single(attrs.get("displayName")) or ""),
                "proxies": [str(x) for x in (proxies if isinstance(proxies, list) else [proxies])][:50],
            })
            if len(out) >= MAX_USERS:
                break
        return out
    finally:
        conn.unbind()


COMPUTER_FILTER = "(objectCategory=computer)"
COMPUTER_ATTRIBUTES = ["cn", "dNSHostName", "description", "operatingSystem", "distinguishedName", "managedBy"]
MAX_COMPUTERS = 10000


def _first_ou(dn: str) -> str:
    """« CN=PC-1,OU=Urbanisme,OU=Postes,DC=… » → « Urbanisme » (service de rattachement)."""
    for part in (dn or "").split(","):
        key, _, value = part.strip().partition("=")
        if key.upper() == "OU" and value:
            return value
    return ""


def computers(cfg: dict[str, Any]) -> list[dict]:
    """Ordinateurs de l'annuaire (inventaire) : nom, description, système, service (première OU). Lecture seule.
    Bloquant : asyncio.to_thread."""
    conn = _service_connection(cfg)
    try:
        out = []
        entries = conn.extend.standard.paged_search(cfg["ldap_base_dn"], COMPUTER_FILTER, SUBTREE,
                                                    attributes=COMPUTER_ATTRIBUTES, paged_size=500, generator=True)
        for entry in entries:
            if entry.get("type") != "searchResEntry":
                continue
            attrs = entry.get("attributes") or {}
            name = str(_single(attrs.get("cn")) or "").strip()
            if not name:
                continue
            managed = str(_single(attrs.get("managedBy")) or "")
            out.append({
                "name": name,
                "description": str(_single(attrs.get("description")) or "")[:500],
                "os": str(_single(attrs.get("operatingSystem")) or ""),
                "service": _first_ou(str(entry.get("dn") or _single(attrs.get("distinguishedName")) or "")),
                "owner": managed.split(",")[0].removeprefix("CN=") if managed else "",
            })
            if len(out) >= MAX_COMPUTERS:
                break
        return out
    finally:
        conn.unbind()
