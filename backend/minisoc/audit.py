"""Journal d'audit chaîné : chaque entrée contient l'empreinte SHA-256 de la précédente."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc.models import AuditLog

GENESIS = "0" * 64


def compute_hash(prev_hash: str, ts: datetime, actor: str, ip: str, action: str, obj: str, detail: dict) -> str:
    payload = json.dumps(
        [prev_hash, ts.isoformat(), actor, ip, action, obj, detail], ensure_ascii=False, sort_keys=True, default=str
    )
    return hashlib.sha256(payload.encode()).hexdigest()


async def record(
    session: AsyncSession, *, actor: str, action: str, obj: str = "", detail: dict | None = None, ip: str = ""
) -> None:
    """Ajoute une entrée (dans la transaction de l'appelant)."""
    await session.execute(text("SELECT pg_advisory_xact_lock(7366824)"))  # sérialise la chaîne
    prev = await session.scalar(select(AuditLog.hash).order_by(AuditLog.id.desc()).limit(1))
    ts = datetime.now(timezone.utc)
    detail = detail or {}
    prev_hash = prev or GENESIS
    session.add(
        AuditLog(
            ts=ts,
            actor=actor,
            ip=ip,
            action=action,
            object=obj,
            detail=detail,
            prev_hash=prev_hash,
            hash=compute_hash(prev_hash, ts, actor, ip, action, obj, detail),
        )
    )


async def verify_chain(session: AsyncSession) -> tuple[bool, int | None]:
    """Retourne (intègre, id de la première entrée altérée)."""
    prev_hash = GENESIS
    for entry in (await session.scalars(select(AuditLog).order_by(AuditLog.id))).all():
        expected = compute_hash(
            prev_hash, entry.ts, entry.actor, entry.ip, entry.action, entry.object, entry.detail
        )
        if entry.prev_hash != prev_hash or entry.hash != expected:
            return False, entry.id
        prev_hash = entry.hash
    return True, None
