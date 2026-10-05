"""Indicateurs de compromission (IOC) : saisie, listes externes et chasse dans tout l'historique des journaux.

- Types : adresse IP ou réseau (CIDR), domaine, empreinte (MD5, SHA-1, SHA-256), URL. Les formes neutralisées des
  bulletins (« hxxp », « [.] ») sont acceptées.
- Chasse : un nouvel IOC est recherché sur tout l'historique conservé, puis tous les IOC sur les nouveaux
  événements. Les IP sont comparées aux adresses source, destination et machine ; les autres types au message et
  au contenu brut, avec contrôle des limites (« evil.com » ne correspond pas à « notevil.com »).
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime

from minisoc.models import IOC_TYPES

MAX_ROWS = 5000
NEEDLES_PER_QUERY = 200  # limite des fonctions multiSearch de ClickHouse
_HASH = re.compile(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$")
_DOMAIN = re.compile(r"^(?=.{4,253}$)(?!-)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$")
_URL = re.compile(r"^https?://[^\s/$.?#][^\s]*$", re.I)


class IocError(ValueError):
    pass


def refang(value: str) -> str:
    v = value.strip().strip("\"'")
    v = re.sub(r"^hxxp", "http", v, flags=re.I)
    return v.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":").replace("[://]", "://")


def detect(value: str) -> tuple[str, str]:
    """(type, valeur normalisée) ; IocError si la valeur n'est pas un IOC reconnu."""
    v = refang(value)
    if not v:
        raise IocError("valeur vide")
    net = None
    try:
        if "/" in v and not v.lower().startswith("http"):
            net = ipaddress.ip_network(v, strict=False)
        else:
            return "ip", str(ipaddress.ip_address(v))
    except ValueError:
        pass
    if net is not None:
        if net.prefixlen < (16 if net.version == 4 else 32):
            raise IocError(f"réseau trop large : {v} (/16 au plus large)")
        return "ip", str(net)
    low = v.lower()
    if _HASH.match(low):
        return "hash", low
    if _URL.match(v):
        return "url", v
    if _DOMAIN.match(low):
        return "domain", low.rstrip(".")
    raise IocError(f"type non reconnu : {value[:80]}")


def parse_text(text: str, forced_type: str = "auto") -> tuple[list[tuple[str, str]], list[str]]:
    """Une valeur par ligne (ou séparées par des espaces, virgules, points-virgules) ; # = commentaire."""
    found: dict[tuple[str, str], None] = {}
    rejected = []
    for line in text.splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        for item in re.split(r"[\s,;]+", line):
            if not item:
                continue
            try:
                kind, value = detect(item)
            except IocError as exc:
                rejected.append(str(exc))
                continue
            if forced_type not in ("auto", kind):
                rejected.append(f"{item[:80]} : type {kind}, attendu {forced_type}")
                continue
            found[(kind, value)] = None
    return list(found), rejected


@dataclass
class Hit:
    ioc_id: int
    type: str
    value: str
    events: list[dict] = field(default_factory=list)


def _ip_queries(iocs: list[tuple[int, str, str]], since: datetime, column: str = "ts") -> list[tuple[str, dict]]:
    single = [v for _, _, v in iocs if "/" not in v]
    nets = [v for _, _, v in iocs if "/" in v]
    out = []
    cols = (
        "ts, module, host_name, user_name, source_ip, destination_ip, host_ip, rule_name, message, "
        "toString(event_id) AS event_id"
    )
    if single:
        out.append(
            (
                f"SELECT {cols} FROM events WHERE {column} >= {{since:DateTime64(3)}} "
                "AND (source_ip IN {ips:Array(String)} OR destination_ip IN {ips:Array(String)} "
                "OR host_ip IN {ips:Array(String)}) "
                f"ORDER BY ts DESC LIMIT {MAX_ROWS}",
                {"since": since, "ips": single},
            )
        )
    for i in range(0, len(nets), 50):
        batch = nets[i : i + 50]
        params: dict = {"since": since}
        ranges = []
        for j, net in enumerate(batch):
            params[f"n{j}"] = net
            ranges.append(
                " OR ".join(
                    f"(isIPv4String({c}) AND isIPAddressInRange({c}, {{n{j}:String}}))"
                    for c in ("source_ip", "destination_ip", "host_ip")
                )
            )
        out.append(
            (
                f"SELECT {cols} FROM events WHERE {column} >= {{since:DateTime64(3)}} AND ({' OR '.join(ranges)}) "
                f"ORDER BY ts DESC LIMIT {MAX_ROWS}",
                params,
            )
        )
    return out


def _text_queries(iocs: list[tuple[int, str, str]], since: datetime, column: str = "ts") -> list[tuple[str, dict]]:
    out = []
    values = [v for _, _, v in iocs]
    for i in range(0, len(values), NEEDLES_PER_QUERY):
        batch = values[i : i + NEEDLES_PER_QUERY]
        out.append(
            (
                "SELECT ts, module, host_name, user_name, source_ip, destination_ip, host_ip, rule_name, message, "
                f"toString(event_id) AS event_id, raw FROM events WHERE {column} >= {{since:DateTime64(3)}} "
                "AND (multiSearchAnyCaseInsensitiveUTF8(message, {needles:Array(String)}) "
                "OR multiSearchAnyCaseInsensitiveUTF8(raw, {needles:Array(String)})) "
                f"ORDER BY ts DESC LIMIT {MAX_ROWS}",
                {"since": since, "needles": batch},
            )
        )
    return out


def _boundary(value: str) -> re.Pattern:
    """Le domaine, l'empreinte ou l'URL doit être isolé : pas précédé d'une lettre, d'un chiffre ou d'un tiret
    (« notevil.com » ne correspond pas à « evil.com »), mais un sous-domaine (« www.evil.com ») correspond."""
    return re.compile(r"(?<![a-z0-9\-])" + re.escape(value.lower()) + r"(?![a-z0-9\-])", re.I)


def match_rows(iocs: list[tuple[int, str, str]], rows: list[dict]) -> dict[int, Hit]:
    """Associe les lignes trouvées aux IOC (contrôle exact, la requête n'étant qu'un pré-filtre)."""
    hits: dict[int, Hit] = {}
    ip_nets = {i: ipaddress.ip_network(v, strict=False) for i, t, v in iocs if t == "ip"}
    patterns = {i: _boundary(v) for i, t, v in iocs if t != "ip"}
    meta = {i: (t, v) for i, t, v in iocs}
    for row in rows:
        addresses = [row.get(c) for c in ("source_ip", "destination_ip", "host_ip") if row.get(c)]
        text = f"{row.get('message', '')}\n{row.get('raw', '')}"
        for ioc_id, net in ip_nets.items():
            for addr in addresses:
                try:
                    if ipaddress.ip_address(addr) in net:
                        break
                except ValueError:
                    continue
            else:
                continue
            hits.setdefault(ioc_id, Hit(ioc_id, *meta[ioc_id])).events.append(row)
        for ioc_id, pattern in patterns.items():
            if pattern.search(text):
                hits.setdefault(ioc_id, Hit(ioc_id, *meta[ioc_id])).events.append(row)
    return hits


async def hunt(store, iocs: list[tuple[int, str, str]], since: datetime, column: str = "ts") -> dict[int, Hit]:
    """iocs : (id, type, valeur). `column` : « ts » (date de l'événement, chasse sur l'historique) ou « ingest_ts »
    (date de réception, chasse incrémentale : les journaux arrivés en retard ne sont pas manqués)."""
    if column not in ("ts", "ingest_ts"):
        raise IocError("colonne de date inconnue")
    ips = [i for i in iocs if i[1] == "ip"]
    texts = [i for i in iocs if i[1] in IOC_TYPES and i[1] != "ip"]
    rows: list[dict] = []
    for sql, params in [*_ip_queries(ips, since, column), *_text_queries(texts, since, column)]:
        rows.extend(await store.query(sql, {**params, "since": since.replace(tzinfo=None)}))
    return match_rows(iocs, rows)


def entity_of(event: dict) -> str:
    """Entité de l'alerte : machine, sinon compte, sinon adresse source."""
    for key, label in (("host_name", "host.name"), ("user_name", "user.name"), ("source_ip", "source.ip")):
        if event.get(key):
            return f"{label}={event[key]}"
    return "global"
