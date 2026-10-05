"""Actions de réponse : blocage d'IP sur le Sophos XGS, liste des blocages, déblocage."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc import audit
from minisoc.api.deps import ADMIN, ANALYST, ANY_USER, client_ip, get_db
from minisoc.models import Block, User
from minisoc.response.blocking import MAX_PER_REQUEST, block_ips, check_ip, unblock
from minisoc.response.xgs import XGSClient, XGSError
from minisoc.settings_store import store as settings_store

router = APIRouter(prefix="/api/response", tags=["response"])


class BlockRequest(BaseModel):
    ips: list[str] = Field(min_length=1, max_length=MAX_PER_REQUEST)
    hours: int | None = Field(None, ge=1, le=24 * 90)
    reason: str = Field(min_length=3, max_length=500)
    alert_id: int | None = None


def _block(b: Block) -> dict:
    return {"id": b.id, "ip": b.ip, "reason": b.reason, "alert_id": b.alert_id, "status": b.status,
            "detail": b.detail, "created_by": b.created_by, "created_at": b.created_at.isoformat(),
            "expires_at": b.expires_at.isoformat(),
            "removed_at": b.removed_at.isoformat() if b.removed_at else None, "removed_by": b.removed_by}


@router.get("/status")
async def response_status(db: AsyncSession = Depends(get_db), _: User = Depends(ANY_USER)):
    cfg = await settings_store.load(db)
    return {"enabled": bool(cfg.get("response_enabled") and cfg.get("xgs_url")),
            "group": cfg.get("xgs_block_group"), "default_hours": cfg.get("block_default_hours")}


@router.post("/check")
async def check(body: BlockRequest, db: AsyncSession = Depends(get_db), _: User = Depends(ANALYST)):
    """Aperçu avant confirmation : quelles IP seront bloquées, lesquelles seront refusées et pourquoi."""
    cfg = await settings_store.load(db)
    verdicts = {ip: check_ip(ip, cfg.get("never_block") or []) for ip in dict.fromkeys(body.ips)}
    return {"allowed": [ip for ip, v in verdicts.items() if v is None],
            "refused": {ip: v for ip, v in verdicts.items() if v}}


@router.post("/block")
async def block(body: BlockRequest, request: Request, db: AsyncSession = Depends(get_db),
                user: User = Depends(ANALYST)):
    cfg = await settings_store.load(db, force=True)
    hours = body.hours or int(cfg.get("block_default_hours") or 24)
    try:
        return await block_ips(db, cfg, body.ips, hours, body.reason, user.username, client_ip(request),
                               body.alert_id)
    except XGSError as exc:
        raise HTTPException(409, str(exc)) from None


@router.get("/blocks")
async def list_blocks(status: str | None = Query(None, pattern="^(active|removed|failed)$"),
                      db: AsyncSession = Depends(get_db), _: User = Depends(ANY_USER)):
    stmt = select(Block).order_by(Block.id.desc()).limit(500)
    if status:
        stmt = stmt.where(Block.status == status)
    return {"items": [_block(b) for b in (await db.scalars(stmt)).all()]}


@router.delete("/blocks/{block_id}")
async def remove_block(block_id: int, request: Request, db: AsyncSession = Depends(get_db),
                       user: User = Depends(ANALYST)):
    item = await db.get(Block, block_id, with_for_update=True)
    if not item or item.status != "active":
        raise HTTPException(404, "Blocage actif introuvable")
    try:
        await unblock(db, await settings_store.load(db, force=True), item, user.username, client_ip(request))
    except XGSError as exc:
        raise HTTPException(409, str(exc)) from None
    return _block(item)


@router.post("/test")
async def test_xgs(request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(ADMIN)):
    try:
        ok, detail = True, await XGSClient(await settings_store.load(db, force=True)).test()
    except XGSError as exc:
        ok, detail = False, str(exc)
    await audit.record(db, actor=user.username, ip=client_ip(request), action="xgs_test", obj="settings:response",
                       detail={"ok": ok})
    await db.commit()
    return {"ok": ok, "detail": detail}


# --- Isolation de poste par l'EDR (F-27) -------------------------------------------------------------------------

class IsolationRequest(BaseModel):
    alert_id: int
    edr: str
    agent_id: str = Field(min_length=1, max_length=128)
    confirm_host: str = Field(min_length=1, max_length=256)
    reason: str = Field(min_length=3, max_length=500)
    release: bool = False


async def _alert_targets(request: Request, db: AsyncSession, alert_id: int):
    from minisoc.models import Alert
    from minisoc.response.isolation import targets_from_events

    alert = await db.get(Alert, alert_id)
    if not alert:
        raise HTTPException(404, "Alerte introuvable")
    events = await request.app.state.store.by_ids(alert.event_ids, limit=50)
    return alert, targets_from_events(events)


@router.get("/isolation/{alert_id}")
async def isolation_targets(alert_id: int, request: Request, db: AsyncSession = Depends(get_db),
                            _: User = Depends(ANY_USER)):
    """Postes isolables d'après les événements EDR de l'alerte, et accès configurés."""
    from minisoc.response.isolation import configured

    cfg = await settings_store.load(db)
    _, targets = await _alert_targets(request, db, alert_id)
    return {"enabled": bool(cfg.get("isolation_enabled")),
            "targets": [{**t.as_dict(), "configured": configured(cfg, t.edr)} for t in targets]}


@router.post("/isolation")
async def isolation_action(body: IsolationRequest, request: Request, db: AsyncSession = Depends(get_db),
                           user: User = Depends(ANALYST)):
    from minisoc.models import AlertHistory, IncidentEntry
    from minisoc.response.isolation import IsolationError, isolate

    alert, targets = await _alert_targets(request, db, body.alert_id)
    target = next((t for t in targets if t.edr == body.edr and t.agent_id == body.agent_id), None)
    if target is None:
        raise HTTPException(422, "Ce poste n'apparaît pas dans les événements de l'alerte")
    if body.confirm_host.strip().lower() != target.host.strip().lower():
        raise HTTPException(422, f"Confirmation incorrecte : saisir exactement le nom du poste ({target.host})")
    cfg = await settings_store.load(db, force=True)
    verb = "levée d'isolation" if body.release else "isolation"
    try:
        detail = await isolate(cfg, target, release=body.release)
        ok = True
    except IsolationError as exc:
        detail, ok = str(exc), False
    note = f"{verb.capitalize()} de {target.host} ({target.edr}) : {'demandée' if ok else 'échec'} — {body.reason}"
    db.add(AlertHistory(alert_id=alert.id, actor=user.username, action="comment", detail=f"{note}. {detail}"))
    if alert.incident_id:
        db.add(IncidentEntry(incident_id=alert.incident_id, actor=user.username, kind="action",
                             detail=f"{note}. {detail}"))
    await audit.record(db, actor=user.username, ip=client_ip(request),
                       action="endpoint_release" if body.release else "endpoint_isolate",
                       obj=f"endpoint:{target.edr}:{target.agent_id}",
                       detail={"host": target.host, "alert": alert.id, "ok": ok, "reason": body.reason})
    await db.commit()
    if not ok:
        raise HTTPException(409, detail)
    return {"detail": detail}


@router.post("/isolation/test")
async def isolation_test(request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(ADMIN)):
    from minisoc.response.isolation import test

    ok, detail = await test(await settings_store.load(db, force=True))
    await audit.record(db, actor=user.username, ip=client_ip(request), action="isolation_test",
                       obj="integration:edr_isolation", detail={"ok": ok})
    await db.commit()
    return {"ok": ok, "detail": detail}
