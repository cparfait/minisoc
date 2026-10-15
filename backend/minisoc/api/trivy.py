"""Trivy : réception des rapports des serveurs, état des analyses, jetons des serveurs, agent à installer."""

from __future__ import annotations

import ipaddress
import json
import logging
import secrets
import zlib
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc import audit, trivy
from minisoc.api.deps import ADMIN, ANALYST, ANY_USER, client_ip, get_db
from minisoc.config import get_settings
from minisoc.models import TrivySource, User
from minisoc.security import session_id
from minisoc.settings_store import store as settings_store
from minisoc.threat_feeds import KEV_KEY

log = logging.getLogger(__name__)
router = APIRouter(tags=["trivy"])

# Corps compressé (Content-Encoding: gzip) : 10 Mo au plus par le proxy, 100 Mo une fois décompressé
MAX_BODY = 10 * 1024 * 1024
MAX_INFLATED = 100 * 1024 * 1024
AGENT = Path(__file__).resolve().parent.parent / "agents" / "minisoc-trivy-agent.sh"


def source_key(source_id: int) -> str:
    return f"srv{source_id}"


def _ip_allowed(ip: str, allowed: list[str]) -> bool:
    if not allowed:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(net, strict=False) for net in allowed)


def _inflate(body: bytes) -> bytes:
    inflater = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        data = inflater.decompress(body, MAX_INFLATED + 1)
    except zlib.error:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Corps gzip invalide") from None
    if len(data) > MAX_INFLATED or inflater.unconsumed_tail:
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, "Rapport trop volumineux")
    return data


async def _bundle(request: Request) -> dict:
    length = request.headers.get("content-length")
    if length and length.isdigit() and int(length) > MAX_BODY:
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, "Corps de requête trop volumineux")
    body = await request.body()
    if len(body) > MAX_BODY:
        raise HTTPException(status.HTTP_413_CONTENT_TOO_LARGE, "Corps de requête trop volumineux")
    if "gzip" in request.headers.get("content-encoding", "").lower():
        body = _inflate(body)
    try:
        data = json.loads(body)
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "JSON invalide") from None
    if not isinstance(data, dict):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, "Paquet Trivy attendu : {host, reports: [...]}")
    return data


@router.post("/api/ingest/trivy")
async def ingest_trivy(request: Request, db: AsyncSession = Depends(get_db)):
    """Rapport d'un serveur (agent minisoc-trivy-agent) : jeton propre au serveur, en-tête Authorization: Bearer."""
    ip = client_ip(request)
    auth = request.headers.get("authorization", "")
    token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    source = await db.scalar(select(TrivySource).where(TrivySource.token_hash == session_id(token))) if token else None
    if not source or source.revoked:
        log.warning("rapport Trivy refusé depuis %s (jeton invalide ou révoqué)", ip)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Jeton invalide ou révoqué")
    if not _ip_allowed(ip, source.allowed_ips or []):
        log.warning("rapport Trivy de « %s » refusé depuis %s (IP non autorisée)", source.name, ip)
        raise HTTPException(status.HTTP_403_FORBIDDEN, "IP non autorisée pour ce jeton")
    cfg = await settings_store.load(db)
    if not cfg.get("src_trivy_enabled", True):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Intégration Trivy désactivée")
    bundle = await _bundle(request)
    try:
        result = await trivy.ingest(request.app.state.redis, source_key(source.id), source.name, bundle,
                                    alert_high=bool(cfg.get("trivy_alert_high", False)))
    except trivy.TrivyError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from None
    source.last_used_at = datetime.now(timezone.utc)
    source.last_ip = ip
    await db.commit()
    return result


@router.get("/api/trivy/overview")
async def overview(request: Request, db: AsyncSession = Depends(get_db), _: User = Depends(ANY_USER)):
    """Analyse de la VM (état du service, dernier rapport) et derniers rapports des serveurs."""
    redis = request.app.state.redis
    cfg = await settings_store.load(db)
    kev = set(await redis.hkeys(KEV_KEY))
    states = trivy.load_states(await redis.hgetall(trivy.STATE_KEY))
    sources = sorted((trivy.summary(st, kev) for st in states.values()),
                     key=lambda s: (not s["local"], -s["kev"], -s["critical_fixable"], (s["name"] or "").lower()))
    local = json.loads(await redis.get(trivy.LOCAL_STATUS_KEY) or "{}")
    return {"enabled": bool(cfg.get("src_trivy_enabled", True)), "local": local, "sources": sources}


@router.post("/api/trivy/scan", status_code=202)
async def scan_now(request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(ANALYST)):
    """Analyse des images de la VM : transmise au service minisoc-trivy dans les 15 secondes."""
    await request.app.state.redis.set(trivy.SCAN_NOW_KEY, "1", ex=3600)
    await audit.record(db, actor=user.username, ip=client_ip(request), action="trivy_scan", obj="integration:trivy")
    await db.commit()
    return {"queued": True}


class NewServer(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    allowed_ips: list[str] = []

    @field_validator("name")
    @classmethod
    def _name(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("nom du serveur requis")
        return v

    @field_validator("allowed_ips")
    @classmethod
    def _ips(cls, v: list[str]) -> list[str]:
        out = []
        for item in v:
            item = item.strip()
            if not item:
                continue
            try:
                out.append(str(ipaddress.ip_network(item, strict=False)))
            except ValueError:
                raise ValueError(f"adresse ou plage invalide : {item}") from None
        return out


def _server(s: TrivySource, states: dict[str, dict], kev: set[str]) -> dict:
    st = states.get(source_key(s.id))
    return {"id": s.id, "name": s.name, "allowed_ips": s.allowed_ips or [], "created_by": s.created_by,
            "created_at": s.created_at.isoformat() if s.created_at else None,
            "last_used_at": s.last_used_at.isoformat() if s.last_used_at else None, "last_ip": s.last_ip,
            "revoked": s.revoked, "report": trivy.summary(st, kev) if st else None}


@router.get("/api/admin/trivy/servers")
async def list_servers(request: Request, db: AsyncSession = Depends(get_db), _: User = Depends(ADMIN)):
    redis = request.app.state.redis
    states = trivy.load_states(await redis.hgetall(trivy.STATE_KEY))
    kev = set(await redis.hkeys(KEV_KEY))
    rows = (await db.scalars(select(TrivySource).order_by(TrivySource.revoked, TrivySource.name))).all()
    return {"items": [_server(s, states, kev) for s in rows]}


@router.post("/api/admin/trivy/servers", status_code=201)
async def create_server(body: NewServer, request: Request, db: AsyncSession = Depends(get_db),
                        user: User = Depends(ADMIN)):
    """Jeton d'un serveur : affiché une seule fois (seule son empreinte est gardée)."""
    token = secrets.token_urlsafe(32)
    source = TrivySource(name=body.name, token_hash=session_id(token), allowed_ips=body.allowed_ips,
                         created_by=user.username)
    db.add(source)
    await db.flush()
    await audit.record(db, actor=user.username, ip=client_ip(request), action="trivy_server_create",
                       obj=f"trivy_source:{source.id}", detail={"name": body.name, "allowed_ips": body.allowed_ips})
    await db.commit()
    return {"id": source.id, "name": source.name, "token": token}


@router.delete("/api/admin/trivy/servers/{server_id}")
async def revoke_server(server_id: int, request: Request, db: AsyncSession = Depends(get_db),
                        user: User = Depends(ADMIN)):
    """Révoque le jeton et retire le dernier rapport du serveur (la trace reste dans le journal d'audit)."""
    source = await db.get(TrivySource, server_id)
    if not source:
        raise HTTPException(404, "Serveur inconnu")
    source.revoked = True
    await trivy.forget(request.app.state.redis, source_key(source.id))
    await audit.record(db, actor=user.username, ip=client_ip(request), action="trivy_server_revoke",
                       obj=f"trivy_source:{source.id}", detail={"name": source.name})
    await db.commit()
    return {"revoked": True}


@router.get("/api/admin/trivy/agent", response_class=PlainTextResponse)
async def agent_script(_: User = Depends(ADMIN)):
    """Agent pour un serveur Linux, avec l'adresse du Mini-SOC déjà renseignée (le jeton se met à l'installation)."""
    text = AGENT.read_text(encoding="utf-8").replace("{{MINISOC_URL}}", get_settings().public_url.rstrip("/"))
    return PlainTextResponse(text, headers={"Content-Disposition": 'attachment; filename="minisoc-trivy-agent.sh"'})
