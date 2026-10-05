"""IOC : saisie (une valeur par ligne), listes externes, chasse à la demande."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc import audit
from minisoc.api.deps import ADMIN, ANALYST, ANY_USER, client_ip, get_db
from minisoc.ioc import parse_text
from minisoc.models import Ioc, IocFeed, User
from minisoc.siem_jobs import IOC_NOW_KEY, IOC_STATUS_KEY

router = APIRouter(prefix="/api/iocs", tags=["iocs"])
MAX_ADD = 20_000


def _ioc(i: Ioc) -> dict:
    iso = lambda v: v.isoformat() if v else None  # noqa: E731
    return {
        "id": i.id,
        "type": i.type,
        "value": i.value,
        "source": i.source,
        "description": i.description,
        "author": i.author,
        "hits": i.hits,
        "last_hit": iso(i.last_hit),
        "hunted_at": iso(i.hunted_at),
        "expires_at": iso(i.expires_at),
        "created_at": iso(i.created_at),
    }


@router.get("")
async def list_iocs(
    request: Request,
    type: str | None = Query(None, pattern="^(ip|domain|hash|url)$"),
    q: str | None = Query(None, max_length=200),
    hits: bool = False,
    limit: int = Query(500, ge=1, le=5000),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(ANY_USER),
):
    filters = []
    if type:
        filters.append(Ioc.type == type)
    if q:
        filters.append(Ioc.value.ilike(f"%{q.replace('%', '')}%") | Ioc.source.ilike(f"%{q.replace('%', '')}%"))
    if hits:
        filters.append(Ioc.hits > 0)
    rows = await db.scalars(select(Ioc).where(*filters).order_by(Ioc.hits.desc(), Ioc.created_at.desc()).limit(limit))
    by_type = dict((await db.execute(select(Ioc.type, func.count()).group_by(Ioc.type))).all())
    pending = await db.scalar(select(func.count()).where(Ioc.hunted_at.is_(None))) or 0
    raw = await request.app.state.redis.get(IOC_STATUS_KEY)
    return {
        "items": [_ioc(i) for i in rows.all()],
        "by_type": by_type,
        "pending": pending,
        "status": json.loads(raw) if raw else None,
    }


class IocIn(BaseModel):
    text: str = Field(min_length=1, max_length=2_000_000)
    type: str = Field("auto", pattern="^(auto|ip|domain|hash|url)$")
    description: str = Field("", max_length=1000)
    source: str = Field("manuel", max_length=100)
    expires_days: int | None = Field(None, ge=1, le=3650)


@router.post("", status_code=201)
async def add_iocs(body: IocIn, request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(ANALYST)):
    found, rejected = parse_text(body.text, body.type)
    if len(found) > MAX_ADD:
        raise HTTPException(422, f"{MAX_ADD} IOC au plus par ajout (utiliser une liste externe au-delà)")
    existing = {(t, v) for t, v in (await db.execute(select(Ioc.type, Ioc.value))).all()}
    expires = datetime.now(timezone.utc) + timedelta(days=body.expires_days) if body.expires_days else None
    added = 0
    for kind, value in found:
        if (kind, value) in existing:
            continue
        db.add(
            Ioc(
                type=kind,
                value=value,
                source=body.source.strip() or "manuel",
                author=user.username,
                description=body.description.strip(),
                expires_at=expires,
            )
        )
        added += 1
    await audit.record(
        db,
        actor=user.username,
        ip=client_ip(request),
        action="ioc_add",
        obj="iocs",
        detail={"added": added, "duplicates": len(found) - added, "rejected": len(rejected), "source": body.source},
    )
    await db.commit()
    if added:
        await request.app.state.redis.set(IOC_NOW_KEY, 1, ex=600)  # chasse sur l'historique tout de suite
    return {
        "added": added,
        "duplicates": len(found) - added,
        "rejected": rejected[:50],
        "rejected_count": len(rejected),
    }


@router.delete("/{ioc_id}")
async def delete_ioc(ioc_id: int, request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(ANALYST)):
    row = await db.get(Ioc, ioc_id)
    if not row:
        raise HTTPException(404, "IOC introuvable")
    await db.delete(row)
    await audit.record(
        db, actor=user.username, ip=client_ip(request), action="ioc_delete", obj=f"ioc:{row.type}:{row.value}"[:128]
    )
    await db.commit()
    return {"ok": True}


@router.post("/hunt")
async def hunt_now(request: Request, _: User = Depends(ANALYST)):
    await request.app.state.redis.set(IOC_NOW_KEY, 1, ex=600)
    return {"ok": True, "detail": "Chasse lancée (résultat sous quelques secondes à quelques minutes)."}


# ---------- Listes externes ----------


def _feed(f: IocFeed) -> dict:
    return {
        "id": f.id,
        "name": f.name,
        "url": f.url,
        "type": f.type,
        "enabled": f.enabled,
        "count": f.count,
        "error": f.error,
        "fetched_at": f.fetched_at.isoformat() if f.fetched_at else None,
    }


@router.get("/feeds")
async def list_feeds(db: AsyncSession = Depends(get_db), _: User = Depends(ANY_USER)):
    return {"items": [_feed(f) for f in (await db.scalars(select(IocFeed).order_by(IocFeed.name))).all()]}


class FeedIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    url: str = Field(pattern=r"^https?://\S+$", max_length=500)
    type: str = Field("auto", pattern="^(auto|ip|domain|hash|url)$")


@router.post("/feeds", status_code=201)
async def add_feed(body: FeedIn, request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(ADMIN)):
    if await db.scalar(select(IocFeed).where(IocFeed.name == body.name.strip())):
        raise HTTPException(409, "Une liste porte déjà ce nom")
    feed = IocFeed(name=body.name.strip(), url=body.url.strip(), type=body.type)
    db.add(feed)
    await audit.record(
        db, actor=user.username, ip=client_ip(request), action="ioc_feed_add", obj="ioc_feeds", detail=body.model_dump()
    )
    await db.commit()
    await db.refresh(feed)
    await request.app.state.redis.set(IOC_NOW_KEY, 1, ex=600)
    return _feed(feed)


class FeedPatch(BaseModel):
    enabled: bool


@router.patch("/feeds/{feed_id}")
async def toggle_feed(
    feed_id: int, body: FeedPatch, request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(ADMIN)
):
    feed = await db.get(IocFeed, feed_id)
    if not feed:
        raise HTTPException(404, "Liste introuvable")
    feed.enabled = body.enabled
    await audit.record(
        db,
        actor=user.username,
        ip=client_ip(request),
        action="ioc_feed_toggle",
        obj=f"ioc_feed:{feed.name}"[:128],
        detail={"enabled": body.enabled},
    )
    await db.commit()
    return _feed(feed)


@router.delete("/feeds/{feed_id}")
async def delete_feed(feed_id: int, request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(ADMIN)):
    feed = await db.get(IocFeed, feed_id)
    if not feed:
        raise HTTPException(404, "Liste introuvable")
    source = f"liste : {feed.name}"[:128]
    removed = (await db.execute(Ioc.__table__.delete().where(Ioc.source == source))).rowcount
    await db.delete(feed)
    await audit.record(
        db,
        actor=user.username,
        ip=client_ip(request),
        action="ioc_feed_delete",
        obj=f"ioc_feed:{feed.name}"[:128],
        detail={"iocs_removed": removed},
    )
    await db.commit()
    return {"ok": True, "iocs_removed": removed}


@router.post("/feeds/{feed_id}/fetch")
async def fetch_feed_now(feed_id: int, request: Request, db: AsyncSession = Depends(get_db), _: User = Depends(ADMIN)):
    feed = await db.get(IocFeed, feed_id)
    if not feed:
        raise HTTPException(404, "Liste introuvable")
    feed.fetched_at = None  # relue au prochain passage de la chasse
    await db.commit()
    await request.app.state.redis.set(IOC_NOW_KEY, 1, ex=600)
    return {"ok": True}
