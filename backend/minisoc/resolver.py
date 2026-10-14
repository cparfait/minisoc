"""Résolution inverse (PTR) des adresses internes auprès du DNS de l'Active Directory.

Uniquement pour les adresses privées (RFC 1918) et auprès du serveur réglé dans Paramètres › Détection
(`dns_server`) : aucune requête vers l'extérieur, aucune adresse publique résolue. Résultats gardés en mémoire
(6 h, 30 min pour un échec) pour ne pas solliciter le DNS à chaque rafraîchissement d'écran.
"""

from __future__ import annotations

import asyncio
import ipaddress
import secrets
import socket
import struct
import time

CACHE_SECONDS = 6 * 3600
NEGATIVE_SECONDS = 30 * 60
TIMEOUT = 1.5
MAX_PARALLEL = 16
INTERNAL_SUFFIXES = (".lan", ".local", ".internal", ".intra", ".corp", ".home.arpa")

_cache: dict[str, tuple[str | None, float]] = {}


def is_private(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.version == 4 and addr.is_private and not addr.is_loopback


def display_name(fqdn: str | None) -> str:
    """« SRV-RADIUS.chatillon.lan » → « SRV-RADIUS » (domaine interne retiré) ; un nom public reste entier."""
    if not fqdn:
        return ""
    fqdn = fqdn.rstrip(".")
    if fqdn.lower().endswith(INTERNAL_SUFFIXES) and "." in fqdn:
        return fqdn.split(".", 1)[0]
    return fqdn


def _encode(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode("ascii") for p in name.split(".") if p) + b"\x00"


def _read_name(data: bytes, pos: int, depth: int = 0) -> tuple[str, int]:
    labels: list[str] = []
    while depth < 10:
        length = data[pos]
        if length == 0:
            return ".".join(labels), pos + 1
        if length & 0xC0 == 0xC0:  # pointeur de compression
            target = struct.unpack(">H", data[pos : pos + 2])[0] & 0x3FFF
            labels.append(_read_name(data, target, depth + 1)[0])
            return ".".join(labels), pos + 2
        labels.append(data[pos + 1 : pos + 1 + length].decode("ascii", "replace"))
        pos += 1 + length
    raise ValueError("nom DNS trop imbriqué")


def query_ptr(ip: str, server: str, timeout: float = TIMEOUT, port: int = 53) -> str | None:
    """Requête PTR minimale en UDP (sans dépendance) ; None si aucun nom."""
    qname = ".".join(reversed(ip.split("."))) + ".in-addr.arpa"
    tid = secrets.randbelow(0x10000)  # identifiant imprévisible (usurpation de réponse plus difficile)
    question = _encode(qname) + struct.pack(">HH", 12, 1)
    packet = struct.pack(">HHHHHH", tid, 0x0100, 1, 0, 0, 0) + question
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.sendto(packet, (server, port))
        data, _ = sock.recvfrom(2048)
    rid, flags, _qd, answers = struct.unpack(">HHHH", data[:8])
    if rid != tid or flags & 0x000F or not answers:  # identifiant différent, erreur ou aucune réponse
        return None
    pos = 12 + len(question)
    names = []
    for _ in range(answers):
        _, pos = _read_name(data, pos)
        rtype, _cls, _ttl, rdlength = struct.unpack(">HHIH", data[pos : pos + 10])
        pos += 10
        if rtype == 12:
            names.append(_read_name(data, pos)[0])
        pos += rdlength
    # Plusieurs noms pour une même adresse (renvoyés à tour de rôle) : toujours le même, pour un affichage stable
    return min(names, key=lambda n: (len(n), n.lower())) if names else None


async def resolve(ip: str, server: str) -> str:
    """Nom affichable d'une adresse interne (vide si inconnu, adresse publique ou DNS non réglé)."""
    if not server or not is_private(ip):
        return ""
    now = time.monotonic()
    cached = _cache.get(ip)
    if cached and cached[1] > now:
        return display_name(cached[0])
    try:
        name = await asyncio.to_thread(query_ptr, ip, server)
    except (OSError, ValueError, struct.error):
        name = None
    _cache[ip] = (name, now + (CACHE_SECONDS if name else NEGATIVE_SECONDS))
    return display_name(name)


async def annotate(rows: list[dict], server: str, ip_key: str = "ip", name_key: str = "name") -> list[dict]:
    """Ajoute à chaque ligne le nom de son adresse interne (champ `name`, vide si inconnu)."""
    names = await resolve_many([str(r.get(ip_key) or "") for r in rows], server)
    for row in rows:
        row[name_key] = names.get(str(row.get(ip_key) or ""), "")
    return rows


async def resolve_many(ips: list[str], server: str) -> dict[str, str]:
    """Noms de plusieurs adresses (requêtes en parallèle, bornées)."""
    unique = [ip for ip in dict.fromkeys(ips) if ip]
    if not server:
        return {}
    limit = asyncio.Semaphore(MAX_PARALLEL)

    async def one(ip: str) -> tuple[str, str]:
        async with limit:
            return ip, await resolve(ip, server)

    return {ip: name for ip, name in await asyncio.gather(*(one(ip) for ip in unique)) if name}
