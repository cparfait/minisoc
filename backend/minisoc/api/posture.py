"""Score de risque par entité et exposition réelle (que corriger en premier)."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc.api.deps import ANY_USER, get_db
from minisoc.assets import INDEX, key_for
from minisoc.connectors.ninjaone import POSTURE_KEY
from minisoc.exposure import load_postures, ranking
from minisoc.models import OPEN_STATUSES, Alert, Asset, User
from minisoc.risk import RISK_WINDOW, compute_risk
from minisoc.settings_store import store as settings_store

router = APIRouter(prefix="/api", tags=["posture"])


async def _risks(request: Request, db: AsyncSession) -> dict:
    now = datetime.now(timezone.utc)
    alerts = list((await db.scalars(select(Alert).where(Alert.last_seen >= now - RISK_WINDOW))).all())
    index = await INDEX.ensure(db)
    mitre = {r.id: r.mitre for r in request.app.state.rules.rules}

    def criticality(kind: str, name: str) -> str | None:
        info = index.host(name) if kind == "host" else index.account(name)
        return info.criticality if info else None

    return compute_risk(alerts, mitre, criticality, now)


@router.get("/risk")
async def risk_top(
    request: Request,
    limit: int = Query(20, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(ANY_USER),
):
    """Machines et comptes les plus à risque (7 jours) ; le seuil d'alerte vient de Paramètres › Détection."""
    cfg = await settings_store.load(db)
    risks = sorted((r.to_dict() for r in (await _risks(request, db)).values()), key=lambda r: -r["score"])
    return {"threshold": int(cfg.get("risk_threshold") or 60), "items": [r for r in risks if r["score"] > 0][:limit]}


@router.get("/risk/entity")
async def risk_entity(
    request: Request,
    kind: str = Query(pattern="^(host|account)$"),
    name: str = Query(min_length=1, max_length=256),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(ANY_USER),
):
    cfg = await settings_store.load(db)
    risk = (await _risks(request, db)).get(("host" if kind == "host" else "user", key_for(kind, name)))
    return {"threshold": int(cfg.get("risk_threshold") or 60), "risk": risk.to_dict() if risk else None}


@router.get("/exposure")
async def exposure(
    request: Request,
    limit: int = Query(30, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(ANY_USER),
):
    """Machines à corriger en premier : vulnérabilités, antivirus, menaces, failles KEV, exposition, criticité."""
    postures = load_postures(await request.app.state.redis.hgetall(POSTURE_KEY))
    assets = list((await db.scalars(select(Asset).where(Asset.kind == "host"))).all())
    alerts = list((await db.scalars(select(Alert).where(Alert.status.in_(OPEN_STATUSES)))).all())
    return {"items": ranking(postures, assets, alerts, limit), "ninjaone": bool(postures)}
