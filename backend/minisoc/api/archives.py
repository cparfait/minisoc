"""Archives scellées des événements : liste, vérification de la chaîne, téléchargement (administrateurs)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import FileResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc import audit
from minisoc.api.deps import ADMIN, ANY_USER, client_ip, get_db
from minisoc.archives import archive_dir, verify
from minisoc.models import Archive, User

router = APIRouter(prefix="/api/archives", tags=["archives"])


def _archive(a: Archive) -> dict:
    return {
        "day": a.day,
        "events": a.events,
        "size": a.size,
        "sha256": a.sha256,
        "prev_hash": a.prev_hash,
        "chain_hash": a.chain_hash,
        "created_at": a.created_at.isoformat() if a.created_at else None,
    }


@router.get("")
async def list_archives(db: AsyncSession = Depends(get_db), _: User = Depends(ANY_USER)):
    rows = (await db.scalars(select(Archive).order_by(Archive.day.desc()).limit(400))).all()
    return {
        "items": [_archive(a) for a in rows],
        "head": _archive(rows[0]) if rows else None,
        "total_size": sum(a.size for a in rows),
    }


@router.post("/verify")
async def verify_archives(request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(ADMIN)):
    results = await verify(db)
    broken = [r for r in results if not r["ok"]]
    await audit.record(
        db,
        actor=user.username,
        ip=client_ip(request),
        action="archives_verify",
        obj="archives",
        detail={"checked": len(results), "broken": [r["day"] for r in broken]},
    )
    await db.commit()
    return {"checked": len(results), "ok": not broken, "broken": broken}


@router.get("/{day}/download")
async def download_archive(day: str, request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(ADMIN)):
    record = await db.scalar(select(Archive).where(Archive.day == day))
    if not record:
        raise HTTPException(404, "Archive introuvable")
    base = archive_dir().resolve()
    path = (base / record.path).resolve()
    if base not in path.parents or not path.is_file():
        raise HTTPException(404, "Fichier d'archive absent")
    await audit.record(
        db,
        actor=user.username,
        ip=client_ip(request),
        action="archive_download",
        obj=f"archive:{day}",
        detail={"sha256": record.sha256},
    )
    await db.commit()
    return FileResponse(
        path, media_type="application/gzip", filename=path.name, headers={"X-Archive-SHA256": record.sha256}
    )
