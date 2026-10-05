"""Exceptions (faux positifs acceptés) : justification, auteur et date d'expiration obligatoires."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc import audit
from minisoc.api.deps import ANALYST, ANY_USER, client_ip, get_db
from minisoc.ecs import FIELDS
from minisoc.models import RuleException, User

router = APIRouter(prefix="/api/exceptions", tags=["exceptions"])

MAX_DURATION = timedelta(days=366)


class ExceptionCreate(BaseModel):
    rule_id: str = Field(max_length=64)
    field: str = Field(max_length=64)
    value: str = Field(min_length=1, max_length=512)
    reason: str = Field(min_length=10, max_length=2000)
    expires_at: datetime


def serialize(e: RuleException) -> dict:
    return {
        "id": e.id,
        "rule_id": e.rule_id,
        "field": e.field,
        "value": e.value,
        "reason": e.reason,
        "author": e.author,
        "expires_at": e.expires_at.isoformat(),
        "created_at": e.created_at.isoformat() if e.created_at else None,
        "active": e.expires_at > datetime.now(timezone.utc),
    }


@router.get("")
async def list_exceptions(db: AsyncSession = Depends(get_db), _: User = Depends(ANY_USER)):
    rows = await db.scalars(select(RuleException).order_by(RuleException.expires_at.desc()))
    return {"items": [serialize(e) for e in rows.all()], "fields": sorted(FIELDS)}


@router.post("", status_code=201)
async def create_exception(
    body: ExceptionCreate, request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(ANALYST)
):
    now = datetime.now(timezone.utc)
    expires = body.expires_at if body.expires_at.tzinfo else body.expires_at.replace(tzinfo=timezone.utc)
    if body.rule_id != "*" and body.rule_id not in request.app.state.rules.by_id:
        raise HTTPException(422, "Règle inconnue")
    if body.field not in FIELDS:
        raise HTTPException(422, "Champ inconnu")
    if not now < expires <= now + MAX_DURATION:
        raise HTTPException(422, "La date d'expiration doit être dans le futur et à moins d'un an")
    exc = RuleException(
        rule_id=body.rule_id,
        field=body.field,
        value=body.value.strip(),
        reason=body.reason.strip(),
        author=user.username,
        expires_at=expires,
    )
    db.add(exc)
    await db.flush()
    await audit.record(
        db, actor=user.username, ip=client_ip(request), action="exception_create", obj=f"exception:{exc.id}",
        detail=body.model_dump(mode="json"),
    )
    await db.commit()
    return serialize(exc)


@router.delete("/{exception_id}")
async def delete_exception(
    exception_id: int, request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(ANALYST)
):
    exc = await db.get(RuleException, exception_id)
    if not exc:
        raise HTTPException(404, "Exception introuvable")
    detail = serialize(exc)
    await db.delete(exc)
    await audit.record(
        db, actor=user.username, ip=client_ip(request), action="exception_delete", obj=f"exception:{exception_id}",
        detail=detail,
    )
    await db.commit()
    return {"ok": True}
