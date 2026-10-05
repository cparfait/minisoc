"""Administration : paramètres (AD, messagerie), tests de connexion, comptes utilisateurs. Rôle admin requis."""

from __future__ import annotations

import asyncio
from typing import Any

import httpx
from fastapi import APIRouter, Body, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import delete, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc import audit
from minisoc.api.deps import ADMIN, client_ip, get_db
from minisoc.db import sessionmaker
from minisoc.ldap_auth import test_connection
from minisoc.models import ROLES, AuthChallenge, Session, User
from minisoc.notify.channels import SEVERITY_FR, AlertMessage, EmailChannel, NtfyChannel, TeamsChannel
from minisoc.notify.digest import send_digest
from minisoc.notify.email import send_email
from minisoc.notify.router import Notifier
from minisoc.settings_store import FIELDS, GROUPS, SettingsError
from minisoc.settings_store import store as settings_store

router = APIRouter(prefix="/api/admin", tags=["admin"])


@router.get("/settings/{group}")
async def get_settings_group(group: str, db: AsyncSession = Depends(get_db), _: User = Depends(ADMIN)):
    if group not in GROUPS:
        raise HTTPException(404, "Groupe de paramètres inconnu")
    return {"values": await settings_store.public(db, group),
            "secrets": [k for k, f in FIELDS.items() if f.group == group and f.secret]}


@router.put("/settings/{group}")
async def update_settings_group(group: str, request: Request, changes: dict[str, Any] = Body(...),
                                db: AsyncSession = Depends(get_db), user: User = Depends(ADMIN)):
    if group not in GROUPS:
        raise HTTPException(404, "Groupe de paramètres inconnu")
    try:
        changed = await settings_store.update(db, group, changes, user.username)
    except SettingsError as exc:
        raise HTTPException(422, str(exc)) from None
    if changed:
        # Les valeurs des secrets ne sont jamais journalisées, seulement le fait qu'ils ont changé
        await audit.record(db, actor=user.username, ip=client_ip(request), action="settings_update",
                           obj=f"settings:{group}", detail={"changed": changed})
        await db.commit()
    return {"changed": changed, "values": await settings_store.public(db, group)}


class LdapTest(BaseModel):
    username: str = Field("", max_length=64)
    password: str = Field("", max_length=256)


@router.post("/settings/ldap/test")
async def test_ldap(body: LdapTest, request: Request, db: AsyncSession = Depends(get_db),
                    user: User = Depends(ADMIN)):
    cfg = await settings_store.load(db, force=True)
    steps = await asyncio.to_thread(test_connection, cfg, body.username.strip().lower(), body.password)
    await audit.record(db, actor=user.username, ip=client_ip(request), action="ldap_test", obj="settings:ldap",
                       detail={"ok": all(s["ok"] for s in steps), "user_tested": body.username or None})
    await db.commit()
    return {"ok": bool(steps) and all(s["ok"] for s in steps), "steps": steps}


class SmtpTest(BaseModel):
    to: str = Field("", max_length=256)


@router.post("/settings/smtp/test")
async def test_smtp(body: SmtpTest, request: Request, db: AsyncSession = Depends(get_db),
                    user: User = Depends(ADMIN)):
    cfg = await settings_store.load(db, force=True)
    recipients = [body.to.strip()] if body.to.strip() else None
    try:
        await send_email(cfg, "[Mini-SOC] Message de test",
                         f"Message de test envoyé par {user.username} depuis le Mini-SOC.\n"
                         "Si vous le recevez, les notifications par e-mail fonctionnent.", to=recipients)
        ok, detail = True, f"Message envoyé à {', '.join(recipients or cfg.get('smtp_to', []))}"
    except Exception as exc:  # noqa: BLE001 - message d'erreur affiché à l'administrateur
        ok, detail = False, f"{type(exc).__name__} : {str(exc)[:300]}"
    await audit.record(db, actor=user.username, ip=client_ip(request), action="smtp_test", obj="settings:smtp",
                       detail={"ok": ok})
    await db.commit()
    return {"ok": ok, "detail": detail}


# --- Comptes utilisateurs ----------------------------------------------------------------------------


def _user(u: User, sessions: int) -> dict:
    return {
        "id": u.id,
        "username": u.username,
        "display_name": u.display_name,
        "email": u.email,
        "auth_source": u.auth_source,
        "role": u.role,
        "active": u.active,
        "mfa_enrolled": bool(u.totp_secret_enc),
        "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
        "active_sessions": sessions,
    }


@router.get("/users")
async def list_users(db: AsyncSession = Depends(get_db), _: User = Depends(ADMIN)):
    counts = dict((await db.execute(select(Session.user_id, func.count()).group_by(Session.user_id))).all())
    users = (await db.scalars(select(User).order_by(User.username))).all()
    return {"items": [_user(u, counts.get(u.id, 0)) for u in users]}


class UserUpdate(BaseModel):
    active: bool | None = None
    role: str | None = None


@router.patch("/users/{user_id}")
async def update_user(user_id: int, body: UserUpdate, request: Request, db: AsyncSession = Depends(get_db),
                      admin: User = Depends(ADMIN)):
    target = await db.get(User, user_id, with_for_update=True)
    if not target:
        raise HTTPException(404, "Utilisateur introuvable")
    if target.id == admin.id and (body.active is False or (body.role and body.role != "admin")):
        raise HTTPException(422, "Vous ne pouvez pas vous désactiver ni retirer votre propre rôle admin")
    changes: dict[str, Any] = {}
    if body.role is not None and body.role != target.role:
        if body.role not in ROLES:
            raise HTTPException(422, "Rôle inconnu")
        if target.auth_source == "ldap":
            raise HTTPException(422, "Le rôle d'un compte AD vient de ses groupes AD")
        changes["role"] = [target.role, body.role]
        target.role = body.role
    if body.active is not None and body.active != target.active:
        changes["active"] = [target.active, body.active]
        target.active = body.active
        if not body.active:
            await db.execute(delete(Session).where(Session.user_id == target.id))
    if changes:
        await audit.record(db, actor=admin.username, ip=client_ip(request), action="user_update",
                           obj=f"user:{target.username}", detail=changes)
        await db.commit()
    return {"ok": True}


@router.post("/users/{user_id}/reset-mfa")
async def reset_mfa(user_id: int, request: Request, db: AsyncSession = Depends(get_db),
                    admin: User = Depends(ADMIN)):
    target = await db.get(User, user_id, with_for_update=True)
    if not target:
        raise HTTPException(404, "Utilisateur introuvable")
    target.totp_secret_enc = ""  # nouvel enrôlement par QR code à la prochaine connexion
    target.totp_last_step = 0
    await db.execute(delete(Session).where(Session.user_id == target.id))
    await db.execute(delete(AuthChallenge).where(AuthChallenge.user_id == target.id))
    await audit.record(db, actor=admin.username, ip=client_ip(request), action="mfa_reset",
                       obj=f"user:{target.username}")
    await db.commit()
    return {"ok": True}


# --- Notifications : test des canaux et envoi du résumé à la demande ---------------------------------


class ChannelTest(BaseModel):
    channel: str = Field(pattern="^(email|teams|ntfy)$")


CHANNEL_LABEL = {"email": "E-mail", "teams": "Teams", "ntfy": "Notification mobile (ntfy)"}
CHANNEL_CLASSES = {"email": EmailChannel, "teams": TeamsChannel, "ntfy": NtfyChannel}


def _test_message(severity: str, title: str, url: str) -> AlertMessage:
    return AlertMessage(alert_id=0, severity=severity, title=title, rule="TEST – message de test", entity="—",
                        count=1, first_seen="—", last_seen="—", url=url)


async def _send(channel, message: AlertMessage) -> tuple[bool, str]:
    if not channel.configured:
        return False, "Canal non configuré"
    try:
        await channel.send(message)
        return True, "Message envoyé"
    except Exception as exc:  # noqa: BLE001
        return False, f"{type(exc).__name__} : {str(exc)[:300]}"


@router.post("/settings/notify/test")
async def test_channel(body: ChannelTest, request: Request, db: AsyncSession = Depends(get_db),
                       user: User = Depends(ADMIN)):
    """Message de test sur un canal, avec les réglages enregistrés."""
    settings = request.app.state.settings
    channel = CHANNEL_CLASSES[body.channel](settings)
    channel.cfg = await settings_store.load(db, force=True)
    ok, detail = await _send(channel, _test_message("info", f"Message de test envoyé par {user.username}",
                                                    settings.public_url))
    await audit.record(db, actor=user.username, ip=client_ip(request), action=f"{body.channel}_test",
                       obj="settings:notify", detail={"ok": ok})
    await db.commit()
    return {"ok": ok, "detail": f"{CHANNEL_LABEL[body.channel]} : {detail}"}


class RouteTest(BaseModel):
    severity: str = Field(pattern="^(critical|high|medium|low)$")


@router.post("/settings/notify/test-route")
async def test_route(body: RouteTest, request: Request, db: AsyncSession = Depends(get_db),
                     user: User = Depends(ADMIN)):
    """Alerte fictive de la sévérité choisie, envoyée à tous les canaux prévus pour elle (routage enregistré)."""
    settings = request.app.state.settings
    cfg = await settings_store.load(db, force=True)
    notifier = Notifier(settings, sessionmaker())
    for channel in notifier.channels.values():
        channel.cfg = cfg
    names = notifier.channels_for(body.severity, cfg)
    label = SEVERITY_FR[body.severity]
    message = _test_message(body.severity, f"Test du routage « {label} » envoyé par {user.username}",
                            settings.public_url)
    results = []
    for name in names:
        ok, detail = await _send(notifier.channels[name], message)
        results.append({"channel": name, "label": CHANNEL_LABEL.get(name, name), "ok": ok, "detail": detail})
    note = ""
    if body.severity in (cfg.get("business_hours_only") or []) and not notifier.in_business_hours(cfg):
        note = "En dehors des heures ouvrées, les vraies alertes de cette sévérité attendent la prochaine plage."
    await audit.record(db, actor=user.username, ip=client_ip(request), action="notify_route_test",
                       obj="settings:notify", detail={"severity": body.severity, "results": results})
    await db.commit()
    if not names:
        return {"ok": False, "detail": f"Aucun canal n'est prévu pour la sévérité « {label} ».", "results": [],
                "note": note}
    ok = all(r["ok"] for r in results)
    return {"ok": ok, "detail": "Envoyé sur tous les canaux prévus." if ok else "Au moins un canal a échoué.",
            "results": results, "note": note}


@router.post("/digest/send")
async def send_digest_now(request: Request, body: SmtpTest, db: AsyncSession = Depends(get_db),
                          user: User = Depends(ADMIN)):
    state = request.app.state
    try:
        recipients = await send_digest(sessionmaker(), state.redis, state.store, state.rules, state.settings,
                                       to=[body.to.strip()] if body.to.strip() else None)
        ok, detail = True, f"Résumé envoyé à {recipients}"
    except Exception as exc:  # noqa: BLE001
        ok, detail = False, f"{type(exc).__name__} : {str(exc)[:300]}"
    await audit.record(db, actor=user.username, ip=client_ip(request), action="digest_send", obj="settings:notify",
                       detail={"ok": ok})
    await db.commit()
    return {"ok": ok, "detail": detail}


class ConnectorTest(BaseModel):
    connector: str = Field(pattern="^(harfanglab|crowdsec)$")


@router.post("/settings/connectors/test")
async def test_connector(body: ConnectorTest, request: Request, db: AsyncSession = Depends(get_db),
                         user: User = Depends(ADMIN)):
    """Requête minimale en lecture sur l'outil, avec les paramètres enregistrés."""
    cfg = await settings_store.load(db, force=True)
    try:
        if body.connector == "harfanglab":
            if not cfg.get("harfanglab_url") or not cfg.get("harfanglab_token"):
                raise ValueError("adresse ou jeton manquant")
            async with httpx.AsyncClient(timeout=20, verify=bool(cfg.get("harfanglab_verify_tls", True))) as client:
                response = await client.get(cfg["harfanglab_url"].rstrip("/") + "/api/data/alert/alert/Alert/",
                                            params={"limit": 1},
                                            headers={"Authorization": f"Token {cfg['harfanglab_token']}"})
            response.raise_for_status()
            total = response.json().get("count", "?")
            ok, detail = True, f"Connexion réussie ({total} alerte(s) accessibles)"
        else:
            if not cfg.get("crowdsec_url") or not cfg.get("crowdsec_api_key"):
                raise ValueError("adresse ou clé manquante")
            async with httpx.AsyncClient(timeout=20) as client:
                response = await client.get(cfg["crowdsec_url"].rstrip("/") + "/v1/decisions",
                                            params={"ip": "192.0.2.1"},
                                            headers={"X-Api-Key": cfg["crowdsec_api_key"]})
            response.raise_for_status()
            ok, detail = True, "Connexion réussie à l'API locale CrowdSec"
    except httpx.HTTPStatusError as exc:
        ok, detail = False, f"HTTP {exc.response.status_code} : jeton ou clé refusé(e), ou droits insuffisants"
    except Exception as exc:  # noqa: BLE001
        ok, detail = False, f"{type(exc).__name__} : {str(exc)[:300]}"
    await audit.record(db, actor=user.username, ip=client_ip(request), action=f"{body.connector}_test",
                       obj="settings:connectors", detail={"ok": ok})
    await db.commit()
    return {"ok": ok, "detail": detail}
