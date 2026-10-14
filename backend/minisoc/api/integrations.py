"""Catalogue des intégrations : liste avec état, configuration, activation, test de connexion."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc import audit, bus, geoip_update
from minisoc.ai.providers import configured as ai_configured
from minisoc.api import admin, ai, response
from minisoc.api.deps import ADMIN, ANY_USER, client_ip, get_db
from minisoc.integrations import BY_ID, CATALOG, DROPPED_KEY, GEOIP_STATUS_KEY, status
from minisoc.models import User
from minisoc.settings_store import FIELDS, SettingsError
from minisoc.settings_store import store as settings_store
from minisoc.threat_feeds import KEV_META

router = APIRouter(tags=["integrations"])


async def _extras(redis, cfg: dict) -> dict[str, dict]:
    geo = json.loads(await redis.get(GEOIP_STATUS_KEY) or "{}")
    download = await geoip_update.state(redis)
    kev = await redis.hgetall(KEV_META)
    files = geo.get("files") or []
    if download.get("error"):
        geo_detail = f"Téléchargement en échec : {download['error']}"
    elif files:
        geo_detail = ", ".join(files) + (f" (mises à jour le {download['updated'][:10]})" if download.get("updated") else "")
    elif not geoip_update.configured(cfg):
        geo_detail = "Renseigner l'identifiant et la clé MaxMind (Configurer)"
    else:
        geo_detail = "Téléchargement des bases en cours (5 minutes au plus)"
    return {
        "geoip": {"ready": bool(files), "detail": geo_detail},
        "veille": {"ready": bool(kev.get("updated")),
                   "detail": f"{kev.get('count', '?')} CVE dans le catalogue KEV" if kev else "Jamais récupérée"},
        "ai": {"ready": ai_configured(cfg), "detail": cfg.get("ai_provider", "")},
    }


@router.get("/api/integrations")
async def list_integrations(request: Request, db: AsyncSession = Depends(get_db), _: User = Depends(ANY_USER)):
    redis = request.app.state.redis
    cfg = await settings_store.load(db)
    last_seen = await bus.sources_last_seen(redis)
    dropped = {k: int(v) for k, v in (await redis.hgetall(DROPPED_KEY)).items()}
    extras = await _extras(redis, cfg)
    items = []
    for item in CATALOG:
        entry = status(item, cfg, last_seen, extras.get(item.id))
        entry["dropped"] = sum(dropped.get(m, 0) for m in item.modules)
        items.append(entry)
    return {"items": items}


GUIDES = Path(__file__).resolve().parent.parent / "guides"
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1", ""}


@router.get("/api/integrations/{integration_id}/guide")
async def integration_guide(integration_id: str, request: Request, _: User = Depends(ANY_USER)):
    """Guide d'installation (Markdown) ; {{MINISOC_HOST}} = adresse sous laquelle le Mini-SOC est consulté."""
    item = BY_ID.get(integration_id)
    path = GUIDES / f"{integration_id}.md"
    if not item or not path.is_file():
        raise HTTPException(404, "Pas de guide pour cette intégration")
    host = request.url.hostname or ""
    text = path.read_text(encoding="utf-8").replace("{{MINISOC_HOST}}", "ADRESSE_DU_MINISOC" if host in LOCAL_HOSTS
                                                     else host)
    return {"id": item.id, "markdown": text}


def _get(integration_id: str):
    item = BY_ID.get(integration_id)
    if not item or item.planned:
        raise HTTPException(404, "Intégration inconnue ou à venir")
    return item


@router.get("/api/admin/integrations/{integration_id}/config")
async def get_config(integration_id: str, db: AsyncSession = Depends(get_db), _: User = Depends(ADMIN)):
    item = _get(integration_id)
    return {"values": await settings_store.public_keys(db, [f.key for f in item.fields])}


@router.put("/api/admin/integrations/{integration_id}/config")
async def set_config(integration_id: str, request: Request, changes: dict = Body(...),
                     db: AsyncSession = Depends(get_db), user: User = Depends(ADMIN)):
    item = _get(integration_id)
    try:
        changed = await settings_store.update_keys(db, {f.key for f in item.fields}, changes, user.username)
    except SettingsError as exc:
        raise HTTPException(422, str(exc)) from None
    if changed:
        await audit.record(db, actor=user.username, ip=client_ip(request), action="integration_config",
                           obj=f"integration:{item.id}", detail={"changed": changed})
        await db.commit()
    return {"changed": changed, "values": await settings_store.public_keys(db, [f.key for f in item.fields])}


class Toggle(BaseModel):
    enabled: bool


@router.post("/api/admin/integrations/{integration_id}/enabled")
async def set_enabled(integration_id: str, body: Toggle, request: Request, db: AsyncSession = Depends(get_db),
                      user: User = Depends(ADMIN)):
    item = _get(integration_id)
    if not item.enable_key or FIELDS.get(item.enable_key) is None:
        raise HTTPException(422, "Cette intégration ne se désactive pas")
    await settings_store.update_keys(db, {item.enable_key}, {item.enable_key: body.enabled}, user.username)
    await audit.record(db, actor=user.username, ip=client_ip(request),
                       action="integration_enable" if body.enabled else "integration_disable",
                       obj=f"integration:{item.id}")
    await db.commit()
    return {"enabled": body.enabled, "at": datetime.now().isoformat()}


@router.post("/api/admin/integrations/{integration_id}/test")
async def test_integration(integration_id: str, request: Request, db: AsyncSession = Depends(get_db),
                           user: User = Depends(ADMIN)):
    item = _get(integration_id)
    if item.test in ("harfanglab", "crowdsec"):
        return await admin.test_connector(admin.ConnectorTest(connector=item.test), request, db, user)
    if item.test == "xgs":
        return await response.test_xgs(request, db, user)
    if item.test == "ninjaone":
        from minisoc.connectors import ninjaone

        ok, detail = await ninjaone.test(await settings_store.load(db, force=True))
        await audit.record(db, actor=user.username, ip=client_ip(request), action="ninjaone_test",
                           obj="integration:ninjaone", detail={"ok": ok})
        await db.commit()
        return {"ok": ok, "detail": detail}
    if item.test in ("varonis", "gravityzone", "vectra"):
        from minisoc.connectors import gravityzone, varonis, vectra

        connector = {"varonis": varonis, "gravityzone": gravityzone, "vectra": vectra}[item.test]
        ok, detail = await connector.test(await settings_store.load(db, force=True))
        await audit.record(db, actor=user.username, ip=client_ip(request), action=f"{item.test}_test",
                           obj=f"integration:{item.id}", detail={"ok": ok})
        await db.commit()
        return {"ok": ok, "detail": detail}
    if item.test == "geoip":
        ok, detail = await geoip_update.test(await settings_store.load(db, force=True))
        await audit.record(db, actor=user.username, ip=client_ip(request), action="geoip_test",
                           obj="integration:geoip", detail={"ok": ok})
        await db.commit()
        return {"ok": ok, "detail": detail}
    if item.test == "cyberwatch":
        from minisoc.connectors import cyberwatch

        ok, detail = await cyberwatch.test(await settings_store.load(db, force=True))
        await audit.record(db, actor=user.username, ip=client_ip(request), action="cyberwatch_test",
                           obj="integration:cyberwatch", detail={"ok": ok})
        await db.commit()
        return {"ok": ok, "detail": detail}
    if item.test == "isolation":
        return await response.isolation_test(request, db, user)
    if item.test == "m365":
        from minisoc.connectors import m365

        ok, detail = await m365.test(await settings_store.load(db, force=True))
        await audit.record(db, actor=user.username, ip=client_ip(request), action="m365_test",
                           obj="integration:m365", detail={"ok": ok})
        await db.commit()
        return {"ok": ok, "detail": detail}
    if item.test == "ai":
        return await ai.test_ai(request, db, user)
    if item.test == "export":
        from minisoc.export import send_test

        ok, detail = await send_test(await settings_store.load(db, force=True))
        await audit.record(db, actor=user.username, ip=client_ip(request), action="export_test",
                           obj="integration:siem_export", detail={"ok": ok})
        await db.commit()
        return {"ok": ok, "detail": detail}
    raise HTTPException(422, "Pas de test automatique pour cette intégration")


@router.post("/api/admin/integrations/harfanglab/history")
async def harfanglab_history(request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(ADMIN)):
    """Relit les alertes HarfangLab passées (profondeur réglée) au prochain passage, sans doublon."""
    from minisoc.connectors.harfanglab import reread_history

    await reread_history(request.app.state.redis)
    await audit.record(db, actor=user.username, ip=client_ip(request), action="harfanglab_reread",
                       obj="integration:harfanglab")
    await db.commit()
    return {"detail": "Relecture de l'historique lancée : les alertes manquantes arrivent dans la minute."}


@router.get("/api/admin/integrations/xgs_response/rules")
async def xgs_rules(request: Request, db: AsyncSession = Depends(get_db), user: User = Depends(ADMIN)):
    """Lecture seule des règles de pare-feu du XGS (aucune modification)."""
    from minisoc.response.xgs import XGSClient, XGSError

    try:
        rules = await XGSClient(await settings_store.load(db, force=True)).firewall_rules()
    except XGSError as exc:
        raise HTTPException(409, str(exc)) from None
    await audit.record(db, actor=user.username, ip=client_ip(request), action="xgs_read_rules",
                       obj="integration:xgs_response", detail={"count": len(rules)})
    await db.commit()
    return {"items": rules}
