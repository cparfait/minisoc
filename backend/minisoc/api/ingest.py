"""Points de réception : syslog (relayé par Vector) et push Bitdefender GravityZone."""

from __future__ import annotations

import ipaddress
import json
import logging

from fastapi import APIRouter, HTTPException, Request, status

from minisoc import bus
from minisoc.api.deps import client_ip
from minisoc.db import sessionmaker
from minisoc.security import constant_time_equals
from minisoc.settings_store import store as settings_store

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/ingest", tags=["ingest"])

MAX_BODY = 10 * 1024 * 1024


async def _json_body(request: Request):
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > MAX_BODY:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Corps de requête trop volumineux")
    body = await request.body()
    if len(body) > MAX_BODY:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Corps de requête trop volumineux")
    try:
        return json.loads(body)
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "JSON invalide") from None


@router.post("/syslog")
async def ingest_syslog(request: Request):
    settings = request.app.state.settings
    auth = request.headers.get("authorization", "")
    if not constant_time_equals(auth, f"Bearer {settings.ingest_token}") or not settings.ingest_token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Jeton invalide")
    data = await _json_body(request)
    records = data if isinstance(data, list) else [data]
    payloads = [json.dumps(r, ensure_ascii=False) for r in records if isinstance(r, dict)]
    count = await bus.publish(request.app.state.redis, "syslog", payloads)
    return {"accepted": count}


@router.post("/bitdefender")
async def ingest_bitdefender(request: Request):
    """Cible du Push Event Service : `setPushEventSettings` avec serviceType « jsonRPC »."""
    async with sessionmaker()() as db:
        cfg = await settings_store.load(db)
    ip = client_ip(request)
    if not cfg.get("src_bitdefender_enabled", False):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Intégration Bitdefender désactivée")
    allowed = cfg.get("bitdefender_allowed_ips") or []
    if allowed and not _ip_allowed(ip, allowed):
        log.warning("push Bitdefender refusé depuis %s (IP non autorisée)", ip)
        raise HTTPException(status.HTTP_403_FORBIDDEN, "IP non autorisée")
    token = cfg.get("bitdefender_token") or ""
    if not token or not constant_time_equals(request.headers.get("authorization", ""), token):
        log.warning("push Bitdefender refusé depuis %s (jeton invalide)", ip)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Jeton invalide")
    data = await _json_body(request)
    params = data.get("params", {}) if isinstance(data, dict) else {}
    events = params.get("events", []) if isinstance(params, dict) else []
    payloads = [json.dumps(e, ensure_ascii=False) for e in events if isinstance(e, dict)]
    count = await bus.publish(request.app.state.redis, "bitdefender", payloads)
    return {"jsonrpc": "2.0", "result": {"accepted": count}, "id": data.get("id") if isinstance(data, dict) else None}


def _ip_allowed(ip: str, allowed: list[str]) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(net, strict=False) for net in allowed)
