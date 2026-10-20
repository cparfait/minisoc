"""WordPress : inventaire des sites (page Vulnérabilités), analyse à la demande, sites déclarés (administration)."""

from __future__ import annotations

import json

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc import audit
from minisoc.api.deps import ADMIN, ANALYST, ANY_USER, client_ip, get_db
from minisoc.connectors import wordpress
from minisoc.models import User
from minisoc.settings_store import SettingsError
from minisoc.settings_store import store as settings_store

router = APIRouter(tags=["wordpress"])


@router.get("/api/wordpress/overview")
async def overview(request: Request, db: AsyncSession = Depends(get_db), _: User = Depends(ANY_USER)):
    """Dernier inventaire de chaque site : composants, mises à jour disponibles, failles connues."""
    cfg = await settings_store.load(db)
    redis = request.app.state.redis
    states = wordpress.load_states(await redis.hgetall(wordpress.STATE_KEY))
    declared = [s["url"] for s in wordpress.sites(cfg)]
    rows = []
    for url in declared:
        st = states.get(url) or {"url": url, "name": wordpress.site_name(url), "components": []}
        rows.append({**wordpress.summary(st), "components": st.get("components") or []})
    rows.sort(key=lambda r: (-r["vulnerable"], -r["updates"], r["name"] or ""))
    return {"enabled": bool(cfg.get("src_wordpress_enabled", False)), "declared": len(declared),
            "vulns_enabled": bool(cfg.get("wordpress_wpscan_token")),
            "status": json.loads(await redis.get(wordpress.STATUS_KEY) or "{}"), "sites": rows}


@router.post("/api/wordpress/scan", status_code=202)
async def scan_now(request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(ANALYST)):
    """Inventaire de tous les sites dans la minute (tâche du worker)."""
    await request.app.state.redis.set(wordpress.SCAN_NOW_KEY, "1", ex=3600)
    await audit.record(db, actor=user.username, ip=client_ip(request), action="wordpress_scan",
                       obj="integration:wordpress")
    await db.commit()
    return {"queued": True}


class Site(BaseModel):
    url: str = Field(min_length=4, max_length=300)
    user: str = Field("", max_length=120)
    password: str = Field("", max_length=200)  # vide : mot de passe déjà enregistré conservé


async def _save(db: AsyncSession, request: Request, user: User, items: list[dict], action: str, url: str) -> None:
    try:
        await settings_store.update_keys(db, {"wordpress_sites"}, {"wordpress_sites": json.dumps(items)},
                                         user.username)
    except SettingsError as exc:
        raise HTTPException(422, str(exc)) from None
    await audit.record(db, actor=user.username, ip=client_ip(request), action=action, obj=f"wordpress_site:{url}")
    await db.commit()


def _public(items: list[dict]) -> list[dict]:
    return [{"url": s["url"], "user": s["user"], "password_set": bool(s["password"])} for s in items]


@router.get("/api/admin/wordpress/sites")
async def list_sites(db: AsyncSession = Depends(get_db), _: User = Depends(ADMIN)):
    """Sites déclarés, sans les mots de passe d'application."""
    return {"items": _public(wordpress.sites(await settings_store.load(db, force=True)))}


@router.put("/api/admin/wordpress/sites")
async def save_site(body: Site, request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(ADMIN)):
    """Ajoute un site ou modifie l'identifiant d'un site déjà déclaré (même adresse)."""
    try:
        url = wordpress.normalize_url(body.url)
    except wordpress.WordPressError as exc:
        raise HTTPException(422, str(exc)) from None
    items = wordpress.sites(await settings_store.load(db, force=True))
    current = next((s for s in items if s["url"] == url), None)
    if current is None and len(items) >= wordpress.MAX_SITES:
        raise HTTPException(422, f"{wordpress.MAX_SITES} sites au plus")
    entry = {"url": url, "user": body.user.strip(),
             "password": body.password.strip() or (current or {}).get("password", "")}
    if not entry["user"]:
        entry["password"] = ""  # sans identifiant : détection publique
    items = [entry if s["url"] == url else s for s in items] if current else [*items, entry]
    await _save(db, request, user, items, "wordpress_site_update" if current else "wordpress_site_add", url)
    return {"items": _public(items)}


@router.delete("/api/admin/wordpress/sites")
async def delete_site(url: str, request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(ADMIN)):
    """Retire un site ; son inventaire disparaît au passage suivant du worker."""
    items = wordpress.sites(await settings_store.load(db, force=True))
    try:
        url = wordpress.normalize_url(url)
    except wordpress.WordPressError as exc:
        raise HTTPException(422, str(exc)) from None
    if not any(s["url"] == url for s in items):
        raise HTTPException(404, "Site inconnu")
    items = [s for s in items if s["url"] != url]
    await _save(db, request, user, items, "wordpress_site_remove", url)
    await request.app.state.redis.hdel(wordpress.STATE_KEY, url)
    return {"items": _public(items)}
