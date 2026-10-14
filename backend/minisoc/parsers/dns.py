"""Requêtes DNS des contrôleurs de domaine (serveur DNS Windows), reçues par NXLog.

Deux formats :
- lignes du journal de débogage DNS (dns.log), lues par NXLog Community Edition (configuration fournie) :
  « … PACKET … UDP Rcv 192.168.10.21 1a2b Q [0001 D NOERROR] A (3)www(7)exemple(2)fr(0) » ;
- événements ETW du fournisseur « Microsoft-Windows-DNSServer » (EventID 256 : requête reçue) en JSON, pour un agent
  capable de lire l'ETW (le module im_etw n'existe que dans l'édition payante de NXLog).

Seules les requêtes reçues des clients sont gardées (pas les réponses). Le domaine enregistré (« exemple.fr » pour
« www.exemple.fr ») et un indice de nom généré par algorithme (DGA, typique des logiciels malveillants qui
cherchent leur serveur de commande) sont calculés ici.
"""

from __future__ import annotations

import json
import math
import re
from collections import Counter
from datetime import datetime

from minisoc.ecs import Event
from minisoc.parsers.common import first, parse_ts

MODULE = "dns"
# Suffixes publics à deux niveaux les plus courants (liste volontairement courte : approximation suffisante ici)
MULTI_SUFFIXES = {
    "co.uk",
    "org.uk",
    "ac.uk",
    "gov.uk",
    "com.au",
    "net.au",
    "co.jp",
    "co.nz",
    "com.br",
    "com.cn",
    "co.in",
    "gouv.fr",
    "asso.fr",
    "nom.fr",
    "presse.fr",
    "tm.fr",
    "com.fr",
    "co.za",
    "com.tr",
    "com.mx",
    "com.es",
}
_DEBUG = re.compile(
    r"PACKET\s+\S+\s+(?:UDP|TCP)\s+(?P<dir>Rcv|Snd)\s+(?P<ip>[0-9A-Fa-f.:]+)\s+\S+\s+(?P<resp>R)?\s*Q\s+"
    r"\[(?P<flags>[^\]]*)\]\s+(?P<qtype>\w+)\s+(?P<name>\S+)"
)
_LABEL = re.compile(r"\(\d+\)")
_VOWELS = set("aeiouy")


def decode_debug_name(name: str) -> str:
    """« (3)www(7)exemple(2)fr(0) » → « www.exemple.fr »."""
    return _LABEL.sub(".", name).strip(".").lower()


def registered_domain(name: str) -> str:
    labels = [part for part in name.lower().strip(".").split(".") if part]
    if len(labels) < 2:
        return name.lower()
    if name.endswith((".in-addr.arpa", ".ip6.arpa")):
        return "in-addr.arpa" if "in-addr" in name else "ip6.arpa"
    suffix = ".".join(labels[-2:])
    if suffix in MULTI_SUFFIXES and len(labels) >= 3:
        return ".".join(labels[-3:])
    return suffix


def entropy(text: str) -> float:
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values()) if text else 0.0


def looks_generated(domain: str) -> bool:
    """Nom du domaine enregistré peu prononçable : long, entropie élevée, peu de voyelles ou beaucoup de chiffres."""
    label = domain.split(".")[0]
    if len(label) < 12:
        return False
    letters = [c for c in label if c.isalpha()]
    vowel_ratio = sum(c in _VOWELS for c in letters) / max(1, len(letters))
    digit_ratio = sum(c.isdigit() for c in label) / len(label)
    return entropy(label) >= 3.6 and (vowel_ratio < 0.25 or digit_ratio > 0.3)


def _event(ts: datetime, client: str, name: str, qtype: str, rcode: str, server: str, raw: str) -> Event:
    domain = registered_domain(name)
    failed = rcode.upper() in ("NXDOMAIN", "SERVFAIL", "REFUSED", "3", "2", "5")
    return Event(
        ts=ts,
        module=MODULE,
        category="network",
        action="dns_query",
        outcome="failure" if failed else ("success" if rcode else ""),
        reason=rcode.lower() if failed else "",
        source_ip=client,
        host_name=server,
        observer=server,
        network_service="dns",
        rule_name=f"DNS {qtype}".strip(),
        threat_name="dga_suspect" if looks_generated(domain) else "",
        dns_query=name[:253],
        dns_domain=domain[:253],
        message=f"{client} → {name} ({qtype}){' ' + rcode if rcode else ''}",
        raw=raw,
    )


def is_dns_json(data: dict) -> bool:
    provider = str(data.get("ProviderName") or data.get("SourceName") or data.get("Channel") or "")
    return "DNSServer" in provider or "DNS-Server" in provider or ("QNAME" in data and "EventID" in data)


def parse_dns_json(data: dict, received: datetime, peer: str = "") -> Event | None:
    if str(data.get("EventID")) not in ("256", "260", ""):  # 256 : requête reçue (260 : récursion envoyée)
        return None
    name = str(first(data, "QNAME", "QueryName")).strip(".").lower()
    if not name:
        return None
    return _event(
        parse_ts(first(data, "EventTime", "TimeCreated"), received),
        str(first(data, "Source", "ClientIP", "InterfaceIP")),
        name,
        str(first(data, "QTYPE", "QueryType")),
        str(first(data, "RCODE")),
        str(first(data, "Hostname", "Computer", default=peer)),
        json.dumps(data, ensure_ascii=False, default=str)[:4000],
    )


def looks_like_dns_debug(body: str) -> bool:
    return " PACKET " in body and (" Rcv " in body or " Snd " in body)


def parse_dns_debug(line: str, received: datetime, peer: str = "") -> Event | None:
    match = _DEBUG.search(line)
    if not match or match.group("dir") != "Rcv" or match.group("resp"):
        return None  # réponses et paquets émis : ignorés (une requête = un événement)
    flags = match.group("flags").split()
    rcode = flags[-1] if flags and flags[-1].isalpha() else ""
    return _event(
        received,
        match.group("ip"),
        decode_debug_name(match.group("name")),
        match.group("qtype"),
        rcode if rcode != "NOERROR" else "",
        peer,
        line[:2000],
    )
