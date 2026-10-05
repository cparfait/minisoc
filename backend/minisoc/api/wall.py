"""Tableau de bord d'écran mural : accès par jeton d'affichage (lecture seule), sans session interactive.

Flux : l'administrateur crée un jeton (CLI) → l'écran ouvre https://minisoc/wall#token=… → l'interface
échange le jeton contre un cookie limité à /api/wall (le fragment # n'est jamais envoyé au serveur ni
journalisé) → l'écran interroge /api/wall/overview toutes les 15 s.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc import audit
from minisoc.api.auth import _rate_limited
from minisoc.api.data import auth_activity, count_new_24h, count_open_by_severity, sources_status
from minisoc.api.deps import COOKIE_NAME, client_ip, current_user, get_db
from minisoc.config import get_settings
from minisoc.ecs import SEVERITY_BY_NAME, severity_name
from minisoc.models import OPEN_STATUSES, Alert, DisplayToken
from minisoc.security import session_id

router = APIRouter(prefix="/api/wall", tags=["wall"])

WALL_COOKIE = "minisoc_wall"
MAX_ALERTS = 10
_USER_IN_ENTITY = re.compile(r"user\.name=([^|]+)")


class WallSession(BaseModel):
    token: str = Field(min_length=20, max_length=128)


def _ip_allowed(ip: str, allowed: list[str]) -> bool:
    if not allowed:
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(net, strict=False) for net in allowed)


async def _valid_token(db: AsyncSession, token: str, ip: str) -> DisplayToken | None:
    display = await db.scalar(select(DisplayToken).where(DisplayToken.token_hash == session_id(token)))
    now = datetime.now(timezone.utc)
    if not display or display.revoked or display.expires_at <= now or not _ip_allowed(ip, display.allowed_ips):
        return None
    return display


@router.post("/session")
async def open_wall_session(body: WallSession, request: Request, response: Response,
                            db: AsyncSession = Depends(get_db)):
    ip = client_ip(request)
    if _rate_limited(ip):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Trop de tentatives")
    display = await _valid_token(db, body.token, ip)
    if not display:
        await audit.record(db, actor="écran", ip=ip, action="wall_refused", obj="wall")
        await db.commit()
        raise HTTPException(
            status.HTTP_401_UNAUTHORIZED, "Jeton d'affichage invalide, expiré, révoqué ou IP non autorisée"
        )
    display.last_used_at = datetime.now(timezone.utc)
    display.last_ip = ip
    await audit.record(db, actor=f"écran:{display.name}", ip=ip, action="wall_session", obj=f"display:{display.id}")
    await db.commit()
    max_age = int((display.expires_at - datetime.now(timezone.utc)).total_seconds())
    response.set_cookie(WALL_COOKIE, body.token, max_age=max_age, httponly=True, secure=get_settings().cookie_secure,
                        samesite="strict", path="/api/wall")
    return {"name": display.name}


async def wall_viewer(request: Request, db: AsyncSession = Depends(get_db)) -> dict:
    """Écran (cookie d'affichage) ou utilisateur connecté. Retourne les options d'affichage."""
    token = request.cookies.get(WALL_COOKIE)
    if token:
        display = await _valid_token(db, token, client_ip(request))
        if not display:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Jeton d'affichage invalide ou révoqué")
        now = datetime.now(timezone.utc)
        if not display.last_used_at or (now - display.last_used_at).total_seconds() > 300:
            display.last_used_at = now
            display.last_ip = client_ip(request)
            await db.commit()
        return {"name": display.name, "mask_users": display.mask_users}
    if request.cookies.get(COOKIE_NAME):
        user = await current_user(request, db)
        return {"name": user.username, "mask_users": False}
    raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Écran non autorisé")


@router.get("/overview")
async def wall_overview(request: Request, viewer: dict = Depends(wall_viewer), db: AsyncSession = Depends(get_db)):
    state = request.app.state
    high = SEVERITY_BY_NAME["high"]
    alerts = (
        await db.scalars(
            select(Alert)
            .where(Alert.status.in_(OPEN_STATUSES), Alert.severity >= high)
            .order_by(Alert.severity.desc(), (Alert.status == "new").desc(), Alert.last_seen.desc())
            .limit(MAX_ALERTS)
        )
    ).all()
    unhandled = await db.scalar(
        select(func.count()).where(Alert.status == "new", Alert.severity >= high)
    )
    unhandled_critical = await db.scalar(
        select(func.count()).where(Alert.status == "new", Alert.severity >= SEVERITY_BY_NAME["critical"])
    )
    mask = viewer["mask_users"]
    try:
        activity = await auth_activity(state.store, top=5)
        clickhouse_error = False
    except Exception:  # noqa: BLE001 - l'écran reste utile sans la base des événements
        activity = {"top_attackers": [], "auth_failures_hourly": [], "failures_by_country": []}
        clickhouse_error = True
    if mask:
        for row in activity["top_attackers"]:
            row["sample_users"] = [mask_name(u) for u in row["sample_users"] if u]

    return {
        "screen": viewer["name"],
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "open_by_severity": await count_open_by_severity(db),
        "new_24h": await count_new_24h(db),
        "unhandled": unhandled or 0,
        "unhandled_critical": unhandled_critical or 0,
        "alerts": [_alert(a, mask) for a in alerts],
        "sources": await sources_status(state),
        **activity,
        "clickhouse_error": clickhouse_error,
    }


def _alert(alert: Alert, mask: bool) -> dict:
    qualification = (alert.details or {}).get("qualification") or {}
    title = alert.title
    if mask:
        names = set(_USER_IN_ENTITY.findall(alert.entity_key)) | set((alert.details or {}).get("sample_users", []))
        for name in sorted((n.strip() for n in names if n and n.strip()), key=len, reverse=True):
            title = title.replace(name, mask_name(name))
    return {
        "id": alert.id,
        "severity": severity_name(alert.severity),
        "title": title,
        "rule_id": alert.rule_id,
        "status": alert.status,
        "assignee": alert.assignee,
        "count": alert.count,
        "first_seen": alert.first_seen.isoformat(),
        "last_seen": alert.last_seen.isoformat(),
        "verdict": qualification.get("verdict"),
        "verdict_label": qualification.get("label"),
    }


def mask_name(name: str) -> str:
    """« j.dupont » → « j.d***** » : assez pour se repérer, pas assez pour identifier devant un visiteur."""
    name = str(name)
    keep = 3 if len(name) > 5 else 1
    return name[:keep] + "*" * max(len(name) - keep, 2)
