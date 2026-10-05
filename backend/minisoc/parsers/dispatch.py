"""Aiguillage d'un message de la file d'attente vers le bon analyseur."""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from minisoc.ecs import Event
from minisoc.parsers.bitdefender import parse_bitdefender
from minisoc.parsers.cef import parse_cef
from minisoc.parsers.common import parse_ts, strip_pri
from minisoc.parsers.crowdsec import parse_crowdsec
from minisoc.parsers.dns import is_dns_json, looks_like_dns_debug, parse_dns_debug, parse_dns_json
from minisoc.parsers.harfanglab import parse_harfanglab
from minisoc.parsers.m365 import parse_m365
from minisoc.parsers.ninjaone import parse_ninjaone
from minisoc.parsers.sophos import looks_like_sophos, parse_sophos
from minisoc.parsers.windows import looks_like_windows, parse_windows

log = logging.getLogger(__name__)


def parse_syslog(record: dict) -> Event:
    """`record` = objet produit par Vector : {message, peer, received_at}."""
    received = parse_ts(record.get("received_at"))
    peer = str(record.get("peer", "") or "")
    body = strip_pri(str(record.get("message", "")))
    if "CEF:" in body:
        event = parse_cef(body, received, peer)
        if event:
            return event
    if looks_like_dns_debug(body):  # journal de débogage du serveur DNS (contrôleurs de domaine)
        event = parse_dns_debug(body, received, peer)
        return event or Event(ts=received, module="dns", kind="event", category="network", action="dns_other",
                              observer=peer, message=body[:300], raw=body[:2000])
    windows = looks_like_windows(body)
    if windows is not None:
        if is_dns_json(windows):
            event = parse_dns_json(windows, received, peer)
            if event:
                return event
        return parse_windows(windows, received, peer)
    if looks_like_sophos(body):
        return parse_sophos(body, received, peer)
    return Event(ts=received, module="syslog", category="other", observer=peer, message=body, raw=body)


def parse_message(kind: str, payload: str, *, bitdefender_url: str = "", harfanglab_url: str = "") -> Event:
    """Ne lève jamais d'exception : un message illisible est conservé en module `unparsed`."""
    received = datetime.now(timezone.utc)
    try:
        data = json.loads(payload)
        if kind == "syslog":
            return parse_syslog(data)
        if kind == "bitdefender":
            return parse_bitdefender(data, received, bitdefender_url)
        if kind == "crowdsec":
            return parse_crowdsec(data, received)
        if kind == "harfanglab":
            return parse_harfanglab(data, received, harfanglab_url)
        if kind == "m365":
            return parse_m365(data, received)
        if kind == "ninjaone":
            return parse_ninjaone(data, received)
        raise ValueError(f"type de message inconnu : {kind}")
    except Exception as exc:  # noqa: BLE001 - aucun message ne doit être perdu
        log.warning("message non analysable (%s) : %s", kind, exc)
        return Event(ts=received, module="unparsed", category="other", message=str(exc), raw=payload)
