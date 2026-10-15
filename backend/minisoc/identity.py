"""Identités unifiées : un même compte, une même machine, quelle que soit la forme sous laquelle un outil les nomme.

Comptes : « MAIRIE\\JDupont », « jdupont@chatillon92.fr », « Jean.Dupont@chatillon92.fr » (identifiant Microsoft 365
ou adresse de messagerie différente de l'identifiant Windows), « Jean Dupont » (nom affiché) → « jdupont »
(sAMAccountName). La table des alias est lue dans l'AD chaque heure avec le compte de service LDAPS (lecture seule) :
UPN, adresse principale, adresses secondaires (proxyAddresses) et nom affiché quand il n'est porté que par un compte.

Machines : « PC-00605.mairie.local », « pc-00605 » → « pc-00605 » ; une machine connue seulement par son adresse
(« 192.168.2.38 », « IP-192.168.2.38 » chez Vectra) → son nom, d'après la dernière association adresse / nom
observée (agents HarfangLab et GravityZone, inventaire NinjaOne, événements portant les deux). Les adresses changent
(DHCP) : la table est reconstruite chaque heure à partir des 24 dernières heures.

Chaque événement reçoit `user.key` et `host.key` à l'enrichissement. Les règles planifiées (seuils, séquences,
nouveautés) regroupent sur ces clés ; le score de risque, les chaînes d'attaque, l'inventaire, les exceptions et le
rôle des comptes (administrateur, service) s'en servent aussi.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import time
from collections import Counter
from datetime import datetime, timezone

import redis.asyncio as aioredis

log = logging.getLogger(__name__)

USER_ALIASES_KEY = "minisoc:identity:users"  # alias normalisé -> sAMAccountName normalisé
HOST_ALIASES_KEY = "minisoc:identity:hosts"  # adresse IP -> nom court de la machine
STATUS_KEY = "minisoc:identity:status"  # {"users": {"at", "aliases", "error"}, "hosts": {"at", "addresses"}}
REFRESH_SECONDS = 60

_IP_HOST = re.compile(r"^(?:ip[-_])?(\d{1,3}(?:\.\d{1,3}){3})$", re.I)
_IP = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def normalize(name: str) -> str:
    """« DOMAINE\\J.Dupont » ou « j.dupont@domaine.local » → « j.dupont » (comparaison sans casse)."""
    name = (name or "").strip().lower()
    if "\\" in name:
        name = name.rsplit("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name


def base_host_key(name: str) -> str:
    """« PTB-00100.mairie.local » → « ptb-00100 » ; une machine connue par son adresse (« 192.168.2.38 »,
    « IP-192.168.2.38 » chez Vectra) garde l'adresse entière, sans être coupée au premier point."""
    value = (name or "").strip().lower()
    ip = _IP_HOST.match(value)
    if ip:
        return ip.group(1)
    return value.split(".")[0]


def is_ip(value: str) -> bool:
    return bool(_IP.match(value or ""))


class Identities:
    """Tables d'alias en mémoire, relues dans Redis au plus chaque minute (pipeline, API)."""

    def __init__(self) -> None:
        self.users: dict[str, str] = {}
        self.hosts: dict[str, str] = {}
        self.loaded = 0.0

    async def refresh(self, redis: aioredis.Redis) -> None:
        self.users = await redis.hgetall(USER_ALIASES_KEY)
        self.hosts = await redis.hgetall(HOST_ALIASES_KEY)
        self.loaded = time.monotonic()

    async def ensure(self, redis: aioredis.Redis) -> Identities:
        if time.monotonic() - self.loaded > REFRESH_SECONDS:
            try:
                await self.refresh(redis)
            except Exception as exc:  # noqa: BLE001 - sans Redis, les noms restent comparés tels quels
                log.warning("tables d'identités illisibles : %s", exc)
        return self

    def user(self, name: str) -> str:
        key = normalize(name)
        return self.users.get(key, key)

    def host(self, name: str) -> str:
        key = base_host_key(name)
        return self.hosts.get(key, key) if is_ip(key) else key


IDENTITIES = Identities()


def user_key(name: str) -> str:
    """Clé d'un compte : identifiant Windows (sAMAccountName) en minuscules, quelle que soit la forme reçue."""
    return IDENTITIES.user(name)


def host_key(name: str) -> str:
    """Clé d'une machine : nom court en minuscules ; une adresse IP connue est remplacée par le nom de la machine."""
    return IDENTITIES.host(name)


def same(field: str, a: object, b: object) -> bool:
    """Égalité de deux valeurs d'un champ, aux alias près pour les comptes et les machines."""
    a, b = str(a or ""), str(b or "")
    if a == b:
        return True
    if not a or not b:
        return False
    if field == "user.name":
        return user_key(a) == user_key(b)
    if field == "host.name":
        return host_key(a) == host_key(b)
    return False


# ---------- Construction des tables ----------


def user_aliases(entries: list[dict]) -> dict[str, str]:
    """Alias → identifiant, à partir des comptes de l'annuaire ({sam, upn, mail, display, proxies}). Un alias porté
    par deux comptes (homonymes, adresse partagée) est écarté : mieux vaut ne pas relier que relier à tort."""
    owners: dict[str, set[str]] = {}
    for entry in entries:
        sam = normalize(entry.get("sam", ""))
        if not sam:
            continue
        aliases = {normalize(entry.get("upn", "")), normalize(entry.get("mail", ""))}
        for proxy in entry.get("proxies") or []:
            proxy = str(proxy)
            if proxy.lower().startswith("smtp:"):
                aliases.add(normalize(proxy[5:]))
        display = " ".join(str(entry.get("display") or "").lower().split())
        if display:
            aliases.add(display)
        for alias in aliases - {"", sam}:
            owners.setdefault(alias, set()).add(sam)
    sams = {normalize(e.get("sam", "")) for e in entries}
    # Un alias qui est aussi l'identifiant d'un autre compte n'est jamais réécrit
    return {alias: next(iter(found)) for alias, found in owners.items() if len(found) == 1 and alias not in sams}


def host_aliases(pairs: list[tuple[str, str, datetime | None]]) -> dict[str, str]:
    """Adresse → machine, à partir de couples (nom, adresse, date d'observation) : la plus récente l'emporte ; à date
    égale (ou inconnue), la machine la plus souvent associée à l'adresse."""
    best: dict[str, tuple[datetime, int, str]] = {}
    counts = Counter((ip, base_host_key(name)) for name, ip, _ in pairs)
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    for name, ip, seen in pairs:
        key, ip = base_host_key(name), (ip or "").strip()
        if not key or is_ip(key) or not is_ip(ip) or ip.startswith(("127.", "0.", "169.254.")):
            continue
        seen = seen or epoch
        if seen.tzinfo is None:
            seen = seen.replace(tzinfo=timezone.utc)
        candidate = (seen, counts[(ip, key)], key)
        if ip not in best or candidate[:2] > best[ip][:2]:
            best[ip] = candidate
    return {ip: value[2] for ip, value in best.items()}


async def _save(redis: aioredis.Redis, key: str, mapping: dict[str, str]) -> None:
    pipe = redis.pipeline(transaction=True)
    pipe.delete(key)
    if mapping:
        pipe.hset(key, mapping=mapping)
    await pipe.execute()


async def _status(redis: aioredis.Redis, part: str, value: dict) -> None:
    status = json.loads(await redis.get(STATUS_KEY) or "{}")
    status[part] = value
    await redis.set(STATUS_KEY, json.dumps(status, ensure_ascii=False))


async def sync_users(redis: aioredis.Redis, cfg: dict) -> dict:
    """Comptes de l'annuaire → table des alias (chaque heure, avec la lecture des comptes sensibles)."""
    from minisoc.ldap_auth import user_identities

    status = {"at": datetime.now(timezone.utc).isoformat(), "aliases": 0, "accounts": 0, "error": ""}
    try:
        entries = await asyncio.to_thread(user_identities, cfg)
    except Exception as exc:  # noqa: BLE001 - l'annuaire peut renvoyer des erreurs variées ; l'ancienne table reste
        status["error"] = f"lecture de l'annuaire en échec : {str(exc)[:200]}"
        log.error("identités : %s", status["error"])
    else:
        aliases = user_aliases(entries)
        await _save(redis, USER_ALIASES_KEY, aliases)
        status.update(aliases=len(aliases), accounts=len(entries))
        log.info("identités : %d alias pour %d comptes de l'annuaire", len(aliases), len(entries))
    await _status(redis, "users", status)
    await IDENTITIES.refresh(redis)
    return status


HOST_PAIRS_SQL = """
SELECT host_name, host_ip, max(ts) AS seen FROM events
WHERE ts >= now64(3) - INTERVAL 24 HOUR AND host_name != '' AND host_ip != ''
  AND module IN ('harfanglab', 'bitdefender', 'ninjaone', 'cyberwatch', 'vectra')
GROUP BY host_name, host_ip
ORDER BY seen DESC
LIMIT 50000"""


async def sync_hosts(redis: aioredis.Redis, store, extra: list[tuple[str, str, datetime | None]]) -> dict:
    """Adresses → machines : couples des agents (HarfangLab, GravityZone, NinjaOne) et des événements récents."""
    pairs = list(extra)
    try:
        for row in await store.query(HOST_PAIRS_SQL):
            pairs.append((row["host_name"], row["host_ip"], row["seen"]))
    except Exception as exc:  # noqa: BLE001 - ClickHouse indisponible : la table se contente des agents
        log.warning("identités : adresses des événements illisibles : %s", exc)
    aliases = host_aliases(pairs)
    await _save(redis, HOST_ALIASES_KEY, aliases)
    await _status(redis, "hosts", {"at": datetime.now(timezone.utc).isoformat(), "addresses": len(aliases)})
    await IDENTITIES.refresh(redis)
    return {"addresses": len(aliases)}


async def status(redis: aioredis.Redis) -> dict:
    return json.loads(await redis.get(STATUS_KEY) or "{}")
