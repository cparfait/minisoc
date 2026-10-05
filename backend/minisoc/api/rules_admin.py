"""Règles : import Sigma, règles importées (activation, suppression), rejeu sur l'historique, couverture MITRE."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc import audit
from minisoc.api.deps import ADMIN, ANALYST, ANY_USER, client_ip, get_db
from minisoc.models import CustomRule, User
from minisoc.replay import ReplayError, merged_coverage, replay, tool_coverage
from minisoc.rules.custom import load_all
from minisoc.rules.engine import RuleSet
from minisoc.sigma import SigmaError, convert_text

router = APIRouter(prefix="/api/rules", tags=["rules"])


async def reload_rules(request: Request, db: AsyncSession) -> None:
    """L'API recharge tout de suite ; le worker recharge dans la minute (signature des règles importées)."""
    request.app.state.rules = RuleSet(await load_all(db, request.app.state.settings.rules_dir))


class SigmaIn(BaseModel):
    text: str = Field(min_length=10, max_length=2_000_000)
    enable: bool = False  # par défaut : importée désactivée, à rejouer avant activation


def _conversion(c, existing: set[str]) -> dict:
    return {
        "ok": c.ok,
        "title": c.title,
        "sigma_id": c.sigma_id,
        "level": c.level,
        "rule_id": c.rule["id"] if c.rule else None,
        "severity": c.rule["severity"] if c.rule else None,
        "mitre": c.rule["mitre"] if c.rule else [],
        "filter": c.rule["filter"] if c.rule else None,
        "errors": c.errors,
        "warnings": c.warnings,
        "exists": bool(c.rule and c.rule["id"] in existing),
    }


@router.post("/sigma/preview")
async def sigma_preview(body: SigmaIn, request: Request, _: User = Depends(ANALYST)):
    try:
        conversions = convert_text(body.text)
    except SigmaError as exc:
        raise HTTPException(422, str(exc)) from None
    existing = set(request.app.state.rules.by_id)
    return {"items": [_conversion(c, existing) for c in conversions]}


@router.post("/sigma")
async def sigma_import(
    body: SigmaIn, request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(ADMIN)
):
    try:
        conversions = convert_text(body.text)
    except SigmaError as exc:
        raise HTTPException(422, str(exc)) from None
    files = {r.id for r in request.app.state.rules.rules if not r.path.startswith("sigma:")}
    imported, updated, refused = [], [], []
    for c in conversions:
        if not c.ok:
            refused.append({"title": c.title, "errors": c.errors})
            continue
        rule_id = c.rule["id"]
        if rule_id in files:
            refused.append({"title": c.title, "errors": [f"identifiant {rule_id} déjà utilisé par une règle fichier"]})
            continue
        row = await db.scalar(select(CustomRule).where(CustomRule.rule_id == rule_id))
        if row:
            row.definition, row.original, row.author = c.rule, c.original, user.username
            updated.append(rule_id)
        else:
            db.add(
                CustomRule(
                    rule_id=rule_id,
                    source="sigma",
                    original=c.original,
                    definition=c.rule,
                    enabled=body.enable,
                    author=user.username,
                )
            )
            imported.append(rule_id)
    await audit.record(
        db,
        actor=user.username,
        ip=client_ip(request),
        action="sigma_import",
        obj="rules",
        detail={"imported": imported, "updated": updated, "refused": len(refused), "enabled": body.enable},
    )
    await db.commit()
    await reload_rules(request, db)
    return {"imported": imported, "updated": updated, "refused": refused}


@router.get("/custom")
async def custom_list(db: AsyncSession = Depends(get_db), _: User = Depends(ANY_USER)):
    rows = (await db.scalars(select(CustomRule).order_by(CustomRule.rule_id))).all()
    return {
        "items": [
            {
                "rule_id": r.rule_id,
                "source": r.source,
                "enabled": r.enabled,
                "author": r.author,
                "name": r.definition.get("name"),
                "original": r.original,
                "created_at": r.created_at.isoformat() if r.created_at else None,
            }
            for r in rows
        ]
    }


class CustomPatch(BaseModel):
    enabled: bool


@router.patch("/custom/{rule_id}")
async def custom_toggle(
    rule_id: str, body: CustomPatch, request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(ADMIN)
):
    row = await db.scalar(select(CustomRule).where(CustomRule.rule_id == rule_id))
    if not row:
        raise HTTPException(404, "Règle importée introuvable")
    row.enabled = body.enabled
    await audit.record(
        db,
        actor=user.username,
        ip=client_ip(request),
        action="custom_rule_toggle",
        obj=f"rule:{rule_id}",
        detail={"enabled": body.enabled},
    )
    await db.commit()
    await reload_rules(request, db)
    return {"ok": True}


@router.delete("/custom/{rule_id}")
async def custom_delete(
    rule_id: str, request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(ADMIN)
):
    row = await db.scalar(select(CustomRule).where(CustomRule.rule_id == rule_id))
    if not row:
        raise HTTPException(404, "Règle importée introuvable")
    await db.delete(row)
    await audit.record(
        db,
        actor=user.username,
        ip=client_ip(request),
        action="custom_rule_delete",
        obj=f"rule:{rule_id}",
        detail={"name": row.definition.get("name")},
    )
    await db.commit()
    await reload_rules(request, db)
    return {"ok": True}


class ReplayIn(BaseModel):
    days: int = Field(30, ge=1, le=365)


@router.post("/{rule_id}/replay")
async def replay_rule(rule_id: str, body: ReplayIn, request: Request, _: User = Depends(ANALYST)):
    rule = request.app.state.rules.by_id.get(rule_id)
    if rule is None:
        raise HTTPException(404, "Règle inconnue")
    try:
        return await replay(request.app.state.store, rule, body.days)
    except ReplayError as exc:
        raise HTTPException(422, str(exc)) from None
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(422, f"rejeu impossible : {str(exc)[:200]}") from None


@router.get("/coverage/full")
async def coverage_full(request: Request, _: User = Depends(ANY_USER)):
    """Couverture MITRE : règles actives du Mini-SOC et techniques détectées par les outils (90 jours)."""
    active = {r.id: r.mitre for r in request.app.state.rules.rules if r.enabled and r.mitre}
    try:
        tools = await tool_coverage(request.app.state.store, days=90)
    except Exception:  # noqa: BLE001 - la couverture des règles reste affichable sans ClickHouse
        tools = {}
    return {"tactics": merged_coverage(active, tools)}
