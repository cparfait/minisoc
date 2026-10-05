"""Dépendances communes : base de données, utilisateur courant, rôles."""

from __future__ import annotations

from collections.abc import AsyncIterator
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc.config import get_settings
from minisoc.db import sessionmaker
from minisoc.models import Session, User
from minisoc.security import session_id

COOKIE_NAME = "minisoc_session"
_TOUCH_INTERVAL = timedelta(minutes=1)


async def get_db() -> AsyncIterator[AsyncSession]:
    async with sessionmaker()() as session:
        yield session


def client_ip(request: Request) -> str:
    return request.client.host if request.client else ""


async def current_user(request: Request, db: AsyncSession = Depends(get_db)) -> User:
    token = request.cookies.get(COOKIE_NAME)
    unauthorized = HTTPException(status.HTTP_401_UNAUTHORIZED, "Authentification requise")
    if not token:
        raise unauthorized
    row = (
        await db.execute(
            select(Session, User).join(User, User.id == Session.user_id).where(Session.id == session_id(token))
        )
    ).first()
    if not row:
        raise unauthorized
    sess, user = row
    s = get_settings()
    now = datetime.now(timezone.utc)
    expired = (
        now - sess.created_at > timedelta(hours=s.session_hours)
        or now - sess.last_seen > timedelta(minutes=s.session_idle_minutes)
        or not user.active
    )
    if expired:
        await db.delete(sess)
        await db.commit()
        raise unauthorized
    if now - sess.last_seen > _TOUCH_INTERVAL:
        sess.last_seen = now
        await db.commit()
    request.state.user = user
    return user


def require_role(*roles: str):
    async def checker(user: User = Depends(current_user)) -> User:
        if user.role not in roles:
            raise HTTPException(status.HTTP_403_FORBIDDEN, "Droits insuffisants")
        return user

    return checker


ANY_USER = require_role("admin", "analyst", "viewer")
ANALYST = require_role("admin", "analyst")
ADMIN = require_role("admin")
