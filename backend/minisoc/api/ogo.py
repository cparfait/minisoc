"""OGO Security (WAF) : synthèse des sites protégés (tableau de bord) et activité d'une IP (« Vu par OGO »)."""

from __future__ import annotations

import json

import httpx
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc.api.deps import ANY_USER, get_db
from minisoc.connectors import ogo
from minisoc.models import User
from minisoc.risk import public_ip
from minisoc.settings_store import store as settings_store

router = APIRouter(prefix="/api/ogo", tags=["ogo"])


async def _active(db: AsyncSession) -> dict | None:
    cfg = await settings_store.load(db)
    return cfg if ogo.configured(cfg) and cfg.get("src_ogo_enabled", False) else None


@router.get("/summary")
async def summary(request: Request, db: AsyncSession = Depends(get_db), _: User = Depends(ANY_USER)):
    """Dernière synthèse calculée par le worker (tous les quarts d'heure) : trafic, blocages, état des sites."""
    if await _active(db) is None:
        return {"enabled": False}
    raw = await request.app.state.redis.get(ogo.SUMMARY_KEY)
    return {"enabled": True, **(json.loads(raw) if raw else {"sites": [], "categories": [], "at": None})}


@router.get("/ip/{ip}")
async def ip_activity(ip: str, request: Request, db: AsyncSession = Depends(get_db), _: User = Depends(ANY_USER)):
    """Requêtes de cette adresse vers les sites protégés sur 7 jours, lues dans OGO (cache de 10 minutes)."""
    address = public_ip(ip)
    if not address:
        raise HTTPException(400, "adresse IP publique attendue")
    cfg = await _active(db)
    if cfg is None:
        return {"enabled": False}
    try:
        return {"enabled": True, **await ogo.ip_activity(cfg, request.app.state.redis, address)}
    except ogo.OgoError as exc:
        return {"enabled": True, "ip": address, "error": str(exc)}
    except httpx.HTTPError as exc:
        return {"enabled": True, "ip": address, "error": f"OGO injoignable ou en erreur ({type(exc).__name__})"}
