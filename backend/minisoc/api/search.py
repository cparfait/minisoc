"""Recherche libre dans les événements (langage de recherche, minisoc/search.py) et recherches enregistrées."""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc import audit
from minisoc.api.alerts import _event
from minisoc.api.deps import ANY_USER, client_ip, get_db
from minisoc.models import SavedSearch, User
from minisoc.search import ALIASES, SearchError, build_sql, compile_query

router = APIRouter(prefix="/api/search", tags=["search"])

PERIODS = {
    "15m": timedelta(minutes=15),
    "1h": timedelta(hours=1),
    "24h": timedelta(hours=24),
    "7d": timedelta(days=7),
    "30d": timedelta(days=30),
    "90d": timedelta(days=90),
    "365d": timedelta(days=365),
}


class SearchIn(BaseModel):
    query: str = Field("", max_length=2000)
    period: str = Field("24h", pattern="^(15m|1h|24h|7d|30d|90d|365d|custom)$")
    since: datetime | None = None
    until: datetime | None = None


def _bounds(body: SearchIn) -> tuple[datetime, datetime]:
    now = datetime.now(timezone.utc)
    if body.period == "custom":
        if not body.since:
            raise HTTPException(422, "Date de début attendue")
        since = body.since if body.since.tzinfo else body.since.replace(tzinfo=timezone.utc)
        until = body.until or now
        until = until if until.tzinfo else until.replace(tzinfo=timezone.utc)
        if until <= since:
            raise HTTPException(422, "La date de fin doit suivre la date de début")
        return since, until
    return now - PERIODS[body.period], now


def _naive(value: datetime) -> datetime:
    return value.astimezone(timezone.utc).replace(tzinfo=None)


@router.post("")
async def search(body: SearchIn, request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(ANY_USER)):
    try:
        compiled = compile_query(body.query)
    except SearchError as exc:
        raise HTTPException(422, str(exc)) from None
    since, until = _bounds(body)
    sql, columns = build_sql(compiled, until - since)
    params = {**compiled.params, "since": _naive(since), "until": _naive(until)}
    store = request.app.state.store
    started = time.perf_counter()
    try:
        rows = await store.query(sql, params)
        total = None
        if compiled.stage.kind == "events":
            count_sql = (
                "SELECT count() AS n FROM events WHERE ts >= {since:DateTime64(3)} "
                f"AND ts <= {{until:DateTime64(3)}} AND ({compiled.where})"
            )
            total = int((await store.query(count_sql, params))[0]["n"])
    except Exception as exc:  # noqa: BLE001 - délai dépassé, mémoire… : message compréhensible
        text = str(exc)
        hint = (
            "recherche trop longue : réduire la période ou préciser les conditions"
            if "TIMEOUT" in text.upper() or "time" in text.lower()
            else f"erreur de la base : {text[:200]}"
        )
        raise HTTPException(422, hint) from None
    elapsed = int((time.perf_counter() - started) * 1000)
    # Consultation de journaux (données personnelles) : tracée
    await audit.record(
        db,
        actor=user.username,
        ip=client_ip(request),
        action="search",
        obj="events",
        detail={"query": body.query[:500], "period": body.period},
    )
    await db.commit()
    return {
        "mode": compiled.stage.kind,
        "columns": columns,
        "rows": [_event(r) for r in rows] if compiled.stage.kind != "events" else [],
        "events": [_event(r) for r in rows] if compiled.stage.kind == "events" else [],
        "total": total,
        "since": since.isoformat(),
        "until": until.isoformat(),
        "elapsed_ms": elapsed,
    }


@router.get("/help")
async def search_help(_: User = Depends(ANY_USER)):
    """Raccourcis de champs (aide de la page Recherche)."""
    return {"aliases": {k: (list(v) if isinstance(v, tuple) else [v]) for k, v in sorted(ALIASES.items())}}


class SavedIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    query: str = Field(min_length=1, max_length=2000)
    period: str = Field("24h", pattern="^(15m|1h|24h|7d|30d|90d|365d)$")
    shared: bool = False


def _saved(s: SavedSearch) -> dict:
    return {"id": s.id, "name": s.name, "query": s.query, "period": s.period, "owner": s.owner, "shared": s.shared}


@router.get("/saved")
async def list_saved(db: AsyncSession = Depends(get_db), user: User = Depends(ANY_USER)):
    rows = await db.scalars(
        select(SavedSearch)
        .where(or_(SavedSearch.owner == user.username, SavedSearch.shared.is_(True)))
        .order_by(SavedSearch.name)
    )
    return {"items": [_saved(s) for s in rows.all()]}


@router.post("/saved", status_code=201)
async def save_search(body: SavedIn, db: AsyncSession = Depends(get_db), user: User = Depends(ANY_USER)):
    try:
        compile_query(body.query)
    except SearchError as exc:
        raise HTTPException(422, str(exc)) from None
    saved = SavedSearch(
        name=body.name.strip(),
        query=body.query.strip(),
        period=body.period,
        owner=user.username,
        shared=body.shared and user.role != "viewer",
    )
    db.add(saved)
    await db.commit()
    await db.refresh(saved)
    return _saved(saved)


@router.delete("/saved/{saved_id}")
async def delete_saved(saved_id: int, db: AsyncSession = Depends(get_db), user: User = Depends(ANY_USER)):
    saved = await db.get(SavedSearch, saved_id)
    if not saved:
        raise HTTPException(404, "Recherche introuvable")
    if saved.owner != user.username and user.role != "admin":
        raise HTTPException(403, "Seul son auteur (ou un administrateur) peut la supprimer")
    await db.delete(saved)
    await db.commit()
    return {"ok": True}
