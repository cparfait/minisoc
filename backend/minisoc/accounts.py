"""Comptes sensibles : administrateurs et comptes de service, à surveiller de plus près.

Deux sources, combinées :
- l'Active Directory, lu chaque heure avec le compte de service LDAPS (lecture seule) : comptes à privilèges
  (adminCount=1, posé par l'AD sur les membres, actuels ou passés, des groupes protégés comme Admins du domaine) et
  comptes de service (SPN déclaré, comptes de service gérés gMSA/MSA) ;
- des motifs de noms saisis dans Paramètres › Détection (ex. « adm-* », « svc* ») : utiles sans accès LDAPS, ou
  pour des conventions de nommage maison.

Chaque événement reçoit `user.roles` (« admin », « service » ou « admin,service ») : les règles UC-23 à UC-31 s'en
servent, et la page Comptes AD en fait la synthèse.
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from fnmatch import fnmatchcase

import redis.asyncio as aioredis

from minisoc.ldap_auth import LdapConfigError, sensitive_accounts

log = logging.getLogger(__name__)

KEYS = {"admin": "minisoc:accounts:admin", "service": "minisoc:accounts:service"}  # hash nom -> détails (JSON)
SYNC_KEY = "minisoc:accounts:sync"  # dernier passage : {"at", "admin", "service", "error"}
SYNC_SECONDS = 3600
ROLES = ("admin", "service")


def normalize(name: str) -> str:
    """« DOMAINE\\J.Dupont » ou « j.dupont@domaine.local » → « j.dupont » (comparaison sans casse)."""
    name = (name or "").strip().lower()
    if "\\" in name:
        name = name.rsplit("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name


def ad_configured(cfg: dict) -> bool:
    return all(cfg.get(k) for k in ("ldap_url", "ldap_bind_dn", "ldap_bind_password", "ldap_base_dn"))


class SensitiveAccounts:
    """Cache en mémoire (rafraîchi chaque minute) : rôle d'un compte sans latence dans le pipeline."""

    def __init__(self, redis: aioredis.Redis) -> None:
        self.redis = redis
        self.known: dict[str, set[str]] = {role: set() for role in ROLES}
        self.patterns: dict[str, list[str]] = {role: [] for role in ROLES}

    async def refresh(self, cfg: dict) -> None:
        for role in ROLES:
            self.known[role] = {normalize(n) for n in await self.redis.hkeys(KEYS[role])}
            self.patterns[role] = [normalize(p) for p in cfg.get(f"accounts_{role}_patterns") or [] if str(p).strip()]

    def roles(self, user_name: str) -> str:
        name = normalize(user_name)
        if not name:
            return ""
        found = []
        for role in ROLES:
            if name in self.known[role]:
                found.append(role)
            # Les comptes machine (« PC-01$ ») ne sont pas concernés par les motifs (« srv-* » viserait les serveurs)
            elif not name.endswith("$") and any(fnmatchcase(name, p) for p in self.patterns[role]):
                found.append(role)
        return ",".join(found)


async def sync_from_ad(redis: aioredis.Redis, cfg: dict) -> dict:
    """Lit les comptes sensibles dans l'AD et remplace la liste en Redis ; renvoie le compte rendu enregistré."""
    status: dict = {"at": datetime.now(timezone.utc).isoformat(), "admin": 0, "service": 0, "error": ""}
    try:
        found = await asyncio.to_thread(sensitive_accounts, cfg)
    except LdapConfigError as exc:
        status["error"] = str(exc)
    except Exception as exc:  # noqa: BLE001 - l'annuaire peut renvoyer des erreurs variées
        status["error"] = f"lecture de l'annuaire en échec : {str(exc)[:200]}"
    else:
        pipe = redis.pipeline(transaction=True)
        for role in ROLES:
            accounts = found.get(role, [])
            status[role] = len(accounts)
            pipe.delete(KEYS[role])
            if accounts:
                pipe.hset(KEYS[role], mapping={normalize(a["name"]): json.dumps(a, ensure_ascii=False)
                                               for a in accounts})
        await pipe.execute()
    await redis.set(SYNC_KEY, json.dumps(status, ensure_ascii=False))
    if status["error"]:
        log.error("comptes sensibles : %s", status["error"])
    else:
        log.info("comptes sensibles lus dans l'AD : %d administrateurs, %d comptes de service",
                 status["admin"], status["service"])
    return status


async def directory(redis: aioredis.Redis) -> dict[str, dict]:
    """Comptes sensibles connus de l'AD : nom normalisé -> détails et rôles."""
    accounts: dict[str, dict] = {}
    for role in ROLES:
        for name, raw in (await redis.hgetall(KEYS[role])).items():
            entry = accounts.setdefault(name, {**json.loads(raw), "roles": []})
            entry["roles"].append(role)
    return accounts


async def sync_status(redis: aioredis.Redis) -> dict | None:
    raw = await redis.get(SYNC_KEY)
    return json.loads(raw) if raw else None
