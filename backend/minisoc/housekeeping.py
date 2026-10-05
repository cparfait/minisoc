"""Ménage quotidien : durées de conservation (RGPD) et nettoyage des données techniques expirées.

Le journal d'audit n'est jamais purgé automatiquement : sa chaîne d'empreintes doit rester vérifiable.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, or_
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc.config import Settings
from minisoc.models import Alert, AuthChallenge, Block, LoginThrottle, Session

log = logging.getLogger(__name__)
CLOSED = ("resolved", "false_positive")


async def purge(session: AsyncSession, settings: Settings, cfg: dict, now: datetime | None = None) -> dict[str, int]:
    now = now or datetime.now(timezone.utc)
    counts: dict[str, int] = {}

    async def run(name: str, stmt) -> None:
        result = await session.execute(stmt)
        counts[name] = result.rowcount or 0

    alerts_days = int(cfg.get("alerts_retention_days") or 1095)
    await run("alertes clôturées", delete(Alert).where(
        Alert.status.in_(CLOSED), Alert.updated_at < now - timedelta(days=alerts_days)))
    await run("sessions expirées", delete(Session).where(or_(
        Session.created_at < now - timedelta(hours=settings.session_hours),
        Session.last_seen < now - timedelta(minutes=settings.session_idle_minutes),
    )))
    await run("étapes de connexion abandonnées", delete(AuthChallenge).where(AuthChallenge.expires_at < now))
    await run("compteurs d'échecs anciens", delete(LoginThrottle).where(
        LoginThrottle.updated_at < now - timedelta(days=1),
        or_(LoginThrottle.locked_until.is_(None), LoginThrottle.locked_until < now),
    ))
    await run("blocages levés anciens", delete(Block).where(
        Block.status != "active", func.coalesce(Block.removed_at, Block.created_at) < now - timedelta(days=365)))
    await session.commit()
    return {k: v for k, v in counts.items() if v}

