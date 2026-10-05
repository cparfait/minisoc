"""Rapport mensuel (F-29) : consultation, téléchargement en Markdown, envoi par e-mail."""

from __future__ import annotations

import re
from datetime import date, datetime, timezone
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc import audit
from minisoc.api.deps import ADMIN, ANY_USER, client_ip, get_db
from minisoc.models import User
from minisoc.reports import last_complete_month, monthly_report, render_html, render_markdown

router = APIRouter(tags=["reports"])
_MONTH = re.compile(r"^(\d{4})-(\d{2})$")


def _month(value: str | None, tz: ZoneInfo) -> date:
    if not value:
        return last_complete_month(datetime.now(timezone.utc), tz)
    match = _MONTH.match(value)
    if not match or not 1 <= int(match.group(2)) <= 12:
        raise HTTPException(422, "Mois attendu au format AAAA-MM")
    month = date(int(match.group(1)), int(match.group(2)), 1)
    if month > datetime.now(timezone.utc).astimezone(tz).date():
        raise HTTPException(422, "Mois à venir")
    return month


async def _report(request: Request, db: AsyncSession, month: str | None) -> dict:
    tz = ZoneInfo(request.app.state.settings.timezone)
    return await monthly_report(db, request.app.state.store, _month(month, tz), tz)


@router.get("/api/reports/monthly")
async def get_monthly(request: Request, month: str | None = Query(None), db: AsyncSession = Depends(get_db),
                      _: User = Depends(ANY_USER)):
    return await _report(request, db, month)


@router.get("/api/reports/monthly.md", response_class=PlainTextResponse)
async def download_monthly(request: Request, month: str | None = Query(None), db: AsyncSession = Depends(get_db),
                           _: User = Depends(ANY_USER)):
    report = await _report(request, db, month)
    return PlainTextResponse(render_markdown(report), media_type="text/markdown; charset=utf-8", headers={
        "Content-Disposition": f'attachment; filename="rapport-securite-{report["month"]}.md"',
        "Cache-Control": "no-store"})


@router.post("/api/admin/reports/monthly/send")
async def send_monthly(request: Request, month: str | None = Query(None), db: AsyncSession = Depends(get_db),
                       user: User = Depends(ADMIN)):
    from minisoc.notify.email import EmailConfigError, send_email
    from minisoc.settings_store import store as settings_store

    report = await _report(request, db, month)
    cfg = await settings_store.load(db, force=True)
    recipients = cfg.get("digest_to") or cfg.get("smtp_to") or []
    try:
        await send_email(cfg, f"[Mini-SOC] Rapport de sécurité : {report['label']}", render_markdown(report),
                         html=render_html(report, request.app.state.settings.public_url), to=recipients)
    except EmailConfigError as exc:
        raise HTTPException(409, str(exc)) from None
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(502, f"Envoi impossible : {type(exc).__name__} : {str(exc)[:200]}") from None
    await audit.record(db, actor=user.username, ip=client_ip(request), action="report_send",
                       obj=f"report:{report['month']}", detail={"to": recipients})
    await db.commit()
    return {"sent_to": recipients}
