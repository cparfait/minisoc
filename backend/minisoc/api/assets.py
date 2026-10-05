"""Inventaire des actifs : consultation, classement (criticité, propriétaire, service), import CSV, synchronisation."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import case, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc import audit
from minisoc.api.deps import ADMIN, ANALYST, ANY_USER, client_ip, get_db
from minisoc.assets import INDEX, key_for, parse_csv, upsert
from minisoc.models import ASSET_KINDS, CRITICALITIES, Asset, User
from minisoc.siem_jobs import ASSETS_NOW_KEY, ASSETS_STATUS_KEY

router = APIRouter(prefix="/api/assets", tags=["assets"])


def _asset(a: Asset) -> dict:
    return {
        "id": a.id,
        "kind": a.kind,
        "name": a.name,
        "display_name": a.display_name,
        "criticality": a.criticality,
        "owner": a.owner,
        "service": a.service,
        "description": a.description,
        "asset_type": a.asset_type,
        "source": a.source,
        "reviewed": a.reviewed,
        "internet_exposed": a.internet_exposed,
        "updated_at": a.updated_at.isoformat() if a.updated_at else None,
    }


@router.get("")
async def list_assets(
    request: Request,
    kind: str | None = Query(None, pattern="^(host|account)$"),
    criticality: str | None = Query(None, pattern="^(low|normal|high|vital)$"),
    reviewed: bool | None = None,
    q: str | None = Query(None, max_length=120),
    limit: int = Query(500, ge=1, le=5000),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(ANY_USER),
):
    filters = []
    if kind:
        filters.append(Asset.kind == kind)
    if criticality:
        filters.append(Asset.criticality == criticality)
    if reviewed is not None:
        filters.append(Asset.reviewed.is_(reviewed))
    if q:
        pattern = f"%{q.replace('%', '').replace('_', '')}%"
        filters.append(
            or_(
                Asset.display_name.ilike(pattern),
                Asset.owner.ilike(pattern),
                Asset.service.ilike(pattern),
                Asset.description.ilike(pattern),
            )
        )
    # Les plus critiques d'abord (vitale, haute, normale, basse), puis par nom
    rank = case({"vital": 0, "high": 1, "normal": 2, "low": 3}, value=Asset.criticality, else_=4)
    rows = await db.scalars(select(Asset).where(*filters).order_by(rank, Asset.kind, Asset.name).limit(limit))
    counts = dict((await db.execute(select(Asset.criticality, func.count()).group_by(Asset.criticality))).all())
    to_review = await db.scalar(select(func.count()).where(Asset.reviewed.is_(False))) or 0
    raw = await request.app.state.redis.get(ASSETS_STATUS_KEY)
    return {
        "items": [_asset(a) for a in rows.all()],
        "by_criticality": counts,
        "to_review": to_review,
        "sync": json.loads(raw) if raw else None,
    }


@router.get("/lookup")
async def lookup_asset(
    kind: str = Query(pattern="^(host|account)$"),
    name: str = Query(min_length=1, max_length=256),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(ANY_USER),
):
    """Fiche d'une machine ou d'un compte par son nom (page de la machine) ; `asset` vaut null si elle n'existe pas."""
    asset = await db.scalar(select(Asset).where(Asset.kind == kind, Asset.name == key_for(kind, name)))
    return {"asset": _asset(asset) if asset else None}


class AssetIn(BaseModel):
    kind: str = Field("host", pattern="^(host|account)$")
    name: str = Field(min_length=1, max_length=256)
    criticality: str = Field("normal", pattern="^(low|normal|high|vital)$")
    owner: str = Field("", max_length=256)
    service: str = Field("", max_length=256)
    description: str = Field("", max_length=2000)
    asset_type: str = Field("", max_length=32)
    internet_exposed: bool = False


@router.post("", status_code=201)
async def create_asset(
    body: AssetIn, request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(ANALYST)
):
    asset, _ = await upsert(
        db, body.kind, body.name, source="manual", reviewed=True, **body.model_dump(exclude={"kind", "name"})
    )
    await audit.record(
        db,
        actor=user.username,
        ip=client_ip(request),
        action="asset_update",
        obj=f"asset:{body.kind}:{key_for(body.kind, body.name)}",
        detail=body.model_dump(),
    )
    await db.commit()
    await db.refresh(asset)
    return _asset(asset)


class AssetPatch(BaseModel):
    criticality: str | None = Field(None, pattern="^(low|normal|high|vital)$")
    owner: str | None = Field(None, max_length=256)
    service: str | None = Field(None, max_length=256)
    description: str | None = Field(None, max_length=2000)
    asset_type: str | None = Field(None, max_length=32)
    display_name: str | None = Field(None, max_length=256)
    internet_exposed: bool | None = None


@router.put("/{asset_id}")
async def update_asset(
    asset_id: int, body: AssetPatch, request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(ANALYST)
):
    asset = await db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "Fiche introuvable")
    changes = body.model_dump(exclude_none=True)
    for attr, value in changes.items():
        setattr(asset, attr, value)
    asset.reviewed = True  # classée par la DSI : plus modifiée par les synchronisations
    INDEX.invalidate()
    await audit.record(
        db,
        actor=user.username,
        ip=client_ip(request),
        action="asset_update",
        obj=f"asset:{asset.kind}:{asset.name}",
        detail=changes,
    )
    await db.commit()
    await db.refresh(asset)
    return _asset(asset)


@router.delete("/{asset_id}")
async def delete_asset(
    asset_id: int, request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(ADMIN)
):
    asset = await db.get(Asset, asset_id)
    if not asset:
        raise HTTPException(404, "Fiche introuvable")
    await db.delete(asset)
    INDEX.invalidate()
    await audit.record(
        db, actor=user.username, ip=client_ip(request), action="asset_delete", obj=f"asset:{asset.kind}:{asset.name}"
    )
    await db.commit()
    return {"ok": True}


class ImportIn(BaseModel):
    text: str = Field(min_length=1, max_length=5_000_000)


@router.post("/import")
async def import_assets(
    body: ImportIn, request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(ANALYST)
):
    try:
        rows = parse_csv(body.text)
    except ValueError as exc:
        raise HTTPException(422, str(exc)) from None
    created = 0
    for row in rows:
        kind, name = row.pop("kind"), row.pop("name")
        _, new = await upsert(db, kind, name, source="import", reviewed=True, **row)
        created += int(new)
    await audit.record(
        db,
        actor=user.username,
        ip=client_ip(request),
        action="asset_import",
        obj="assets",
        detail={"rows": len(rows), "created": created},
    )
    await db.commit()
    return {"rows": len(rows), "created": created, "updated": len(rows) - created}


@router.post("/sync")
async def sync_assets(request: Request, _: User = Depends(ANALYST)):
    await request.app.state.redis.set(ASSETS_NOW_KEY, 1, ex=600)
    return {"ok": True, "detail": "Synchronisation demandée : NinjaOne, annuaire et alertes (sous 10 secondes)."}


__all__ = ["router", "ASSET_KINDS", "CRITICALITIES"]
