"""Boucle d'authentification : identifiant + mot de passe (local ou AD/LDAPS) → second facteur TOTP → session.

  POST /api/auth/login   {username, password} → {step: "totp"} ou {step: "enroll", qr, secret}
                          + cookie « minisoc_challenge » (5 min, limité à /api/auth)
  POST /api/auth/verify  {code}               → session (cookie « minisoc_session »)
  POST /api/auth/logout

Garde-fous :
  - verrouillage par (identifiant, IP), vérifié AVANT d'interroger l'AD : un tiers ne peut ni verrouiller le
    compte d'un collègue dans le Mini-SOC, ni faire verrouiller son compte AD à travers lui ;
  - étape intermédiaire conservée côté serveur (expiration, 5 essais, liée à l'IP), jamais dans le cookie ;
  - code TOTP à usage unique (anti-rejeu), nouvelle session à chaque connexion (anti-fixation) ;
  - message d'erreur générique, sauf motifs AD que l'annuaire ne renvoie qu'avec le bon mot de passe.
"""

from __future__ import annotations

import asyncio
import base64
import io
import json
import logging
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone

import qrcode
import qrcode.image.svg
from fastapi import APIRouter, Body, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, Field
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc import audit
from minisoc.api.deps import COOKIE_NAME, client_ip, current_user, get_db
from minisoc.config import get_settings
from minisoc.crypto import decrypt, encrypt
from minisoc.ldap_auth import LdapAuthFailed, LdapConfigError, LdapUser, authenticate
from minisoc.models import AuthChallenge, LoginThrottle, Session, User
from minisoc.security import (
    hash_password,
    needs_rehash,
    new_session_token,
    new_totp_secret,
    session_id,
    totp_uri,
    verify_password,
    verify_totp,
)
from minisoc.settings_store import store as settings_store

log = logging.getLogger(__name__)
router = APIRouter(prefix="/api/auth", tags=["auth"])

CHALLENGE_COOKIE = "minisoc_challenge"
CHALLENGE_TTL = timedelta(minutes=5)
MAX_CODE_ATTEMPTS = 5
MAX_FAILURES = 5
LOCK_DURATION = timedelta(minutes=15)
IP_WINDOW_SECONDS = 300
IP_MAX_ATTEMPTS = 20
GENERIC_ERROR = "Identifiant ou mot de passe invalide, ou accès temporairement verrouillé"
_attempts_by_ip: dict[str, deque[float]] = defaultdict(deque)


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class VerifyRequest(BaseModel):
    code: str = Field(min_length=6, max_length=10)


def _rate_limited(ip: str) -> bool:
    now = time.monotonic()
    attempts = _attempts_by_ip[ip]
    while attempts and now - attempts[0] > IP_WINDOW_SECONDS:
        attempts.popleft()
    attempts.append(now)
    return len(attempts) > IP_MAX_ATTEMPTS


def user_payload(user: User) -> dict:
    return {"username": user.username, "role": user.role, "display_name": user.display_name,
            "auth_source": user.auth_source}


def _no_store(response: Response) -> None:
    # Une redirection ou réponse d'authentification mise en cache provoque des boucles de connexion
    response.headers["Cache-Control"] = "no-store"


# --- Verrouillage par (identifiant, IP) ----------------------------------------------------------


async def _throttle(db: AsyncSession, username: str, ip: str) -> LoginThrottle:
    row = await db.get(LoginThrottle, (username, ip), with_for_update=True)
    if row is None:
        row = LoginThrottle(username=username, ip=ip, failures=0)
        db.add(row)
    return row


async def _record_failure(db: AsyncSession, username: str, ip: str, reason: str) -> None:
    row = await _throttle(db, username, ip)
    row.failures += 1
    row.updated_at = datetime.now(timezone.utc)
    detail = {"reason": reason, "failures": row.failures}
    if row.failures >= MAX_FAILURES:
        row.locked_until = datetime.now(timezone.utc) + LOCK_DURATION
        row.failures = 0
        detail["locked_until"] = row.locked_until.isoformat()
    await audit.record(db, actor=username, ip=ip, action="login_failed", obj="auth", detail=detail)
    await db.commit()


# --- Étape 1 : identifiant et mot de passe -------------------------------------------------------


@router.post("/login")
async def login(body: LoginRequest, request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    _no_store(response)
    ip = client_ip(request)
    if _rate_limited(ip):
        raise HTTPException(status.HTTP_429_TOO_MANY_REQUESTS, "Trop de tentatives, réessayez plus tard")
    username = body.username.strip().lower()
    now = datetime.now(timezone.utc)

    throttle = await db.get(LoginThrottle, (username, ip))
    if throttle and throttle.locked_until and throttle.locked_until > now:
        await audit.record(db, actor=username, ip=ip, action="login_locked", obj="auth")
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, GENERIC_ERROR)

    user = await db.scalar(select(User).where(User.username == username))
    if user is None or user.auth_source == "ldap":
        user = await _ldap_login(db, user, username, body.password, ip)
    elif not verify_password(user.password_hash, body.password):
        await _record_failure(db, username, ip, "invalid_credentials")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, GENERIC_ERROR)
    elif needs_rehash(user.password_hash):
        user.password_hash = hash_password(body.password)

    if not user.active:
        await _record_failure(db, username, ip, "user_disabled")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, GENERIC_ERROR)

    # Mot de passe validé : on prépare l'étape du second facteur, conservée côté serveur
    await db.execute(delete(AuthChallenge).where(AuthChallenge.user_id == user.id))
    token, token_hash = new_session_token()
    enroll = not user.totp_secret_enc
    secret = new_totp_secret() if enroll else ""
    db.add(AuthChallenge(id=token_hash, user_id=user.id, kind="enroll" if enroll else "totp",
                         pending_secret_enc=encrypt(secret) if enroll else "", ip=ip, expires_at=now + CHALLENGE_TTL))
    await db.commit()
    response.set_cookie(CHALLENGE_COOKIE, token, max_age=int(CHALLENGE_TTL.total_seconds()), httponly=True,
                        secure=get_settings().cookie_secure, samesite="strict", path="/api/auth")
    if enroll:
        uri = totp_uri(secret, user.username)
        return {"step": "enroll", "qr": _qr_data_uri(uri), "secret": secret}
    return {"step": "totp"}


async def _ldap_login(db: AsyncSession, user: User | None, username: str, password: str, ip: str) -> User:
    cfg = await settings_store.load(db)
    if not cfg.get("ldap_enabled"):
        await _record_failure(db, username, ip, "unknown_user")
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, GENERIC_ERROR)
    try:
        ldap_user: LdapUser = await asyncio.to_thread(authenticate, cfg, username, password)
    except LdapAuthFailed as exc:
        await _record_failure(db, username, ip, exc.reason)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, exc.user_message or GENERIC_ERROR) from None
    except LdapConfigError as exc:
        log.error("authentification AD impossible : %s", exc)
        await audit.record(db, actor=username, ip=ip, action="login_ldap_error", obj="auth", detail={"error": str(exc)})
        await db.commit()
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE,
                            "Annuaire indisponible : utilisez un compte local de secours ou réessayez") from None

    # Provisionnement à la volée ; le rôle est resynchronisé depuis les groupes AD à chaque connexion
    if user is None:
        user = User(username=ldap_user.username, auth_source="ldap", password_hash="", totp_secret_enc="")
        db.add(user)
        await audit.record(db, actor=ldap_user.username, ip=ip, action="user_provisioned", obj="auth",
                           detail={"role": ldap_user.role, "groups": ldap_user.groups})
    elif user.role != ldap_user.role:
        await audit.record(db, actor=user.username, ip=ip, action="role_synced", obj="auth",
                           detail={"from": user.role, "to": ldap_user.role})
    user.role = ldap_user.role
    user.display_name = ldap_user.display_name
    user.email = ldap_user.email
    await db.flush()
    return user


def _qr_data_uri(uri: str) -> str:
    image = qrcode.make(uri, image_factory=qrcode.image.svg.SvgPathImage, box_size=8, border=2)
    buffer = io.BytesIO()
    image.save(buffer)
    return "data:image/svg+xml;base64," + base64.b64encode(buffer.getvalue()).decode()


# --- Étape 2 : second facteur ----------------------------------------------------------------------


@router.post("/verify")
async def verify(body: VerifyRequest, request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    _no_store(response)
    ip = client_ip(request)
    expired = HTTPException(status.HTTP_401_UNAUTHORIZED, "Étape expirée : recommencez la connexion")
    token = request.cookies.get(CHALLENGE_COOKIE)
    if not token:
        raise expired
    challenge = await db.get(AuthChallenge, session_id(token), with_for_update=True)
    now = datetime.now(timezone.utc)
    if not challenge or challenge.expires_at <= now or challenge.ip != ip:
        if challenge:
            await db.delete(challenge)
            await db.commit()
        response.delete_cookie(CHALLENGE_COOKIE, path="/api/auth")
        raise expired
    user = await db.get(User, challenge.user_id, with_for_update=True)
    if not user or not user.active:
        raise expired

    if challenge.kind == "enroll":
        secret = decrypt(challenge.pending_secret_enc)
        step = verify_totp(secret, body.code, 0)
    else:
        secret = ""
        step = verify_totp(decrypt(user.totp_secret_enc), body.code, user.totp_last_step)

    if step is None:
        challenge.attempts += 1
        if challenge.attempts >= MAX_CODE_ATTEMPTS:
            await db.delete(challenge)
            await _record_failure(db, user.username, ip, "totp_failed")
            raise expired
        await db.commit()
        raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                            f"Code invalide ({MAX_CODE_ATTEMPTS - challenge.attempts} essai(s) restant(s))")

    if challenge.kind == "enroll":
        user.totp_secret_enc = encrypt(secret)
        await audit.record(db, actor=user.username, ip=ip, action="mfa_enrolled", obj="auth")
    user.totp_last_step = step
    user.last_login_at = now
    await db.delete(challenge)
    await db.execute(delete(LoginThrottle).where(LoginThrottle.username == user.username, LoginThrottle.ip == ip))
    session_token, sid = new_session_token()
    db.add(Session(id=sid, user_id=user.id, ip=ip, user_agent=request.headers.get("user-agent", "")[:256]))
    await audit.record(db, actor=user.username, ip=ip, action="login", obj="auth",
                       detail={"source": user.auth_source})
    await db.commit()

    s = get_settings()
    response.delete_cookie(CHALLENGE_COOKIE, path="/api/auth")
    response.set_cookie(COOKIE_NAME, session_token, max_age=s.session_hours * 3600, httponly=True,
                        secure=s.cookie_secure, samesite="strict", path="/")
    return user_payload(user)


@router.post("/logout")
async def logout(request: Request, response: Response, db: AsyncSession = Depends(get_db)):
    _no_store(response)
    token = request.cookies.get(COOKIE_NAME)
    if token:
        await db.execute(delete(Session).where(Session.id == session_id(token)))
        await db.commit()
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"ok": True}


@router.get("/me")
async def me(user: User = Depends(current_user)):
    return user_payload(user)


PREFERENCE_KEYS = {"dashboard", "wall"}  # préférences d'affichage acceptées
PREFERENCE_MAX = 20_000  # octets (JSON) par préférence


@router.get("/me/preferences/{key}")
async def get_preference(key: str, user: User = Depends(current_user)):
    if key not in PREFERENCE_KEYS:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Préférence inconnue")
    return {"key": key, "value": (user.preferences or {}).get(key)}


@router.put("/me/preferences/{key}")
async def put_preference(key: str, body: dict | None = Body(default=None), user: User = Depends(current_user),
                         db: AsyncSession = Depends(get_db)):
    """Enregistre (ou efface, corps vide) une préférence d'affichage de l'utilisateur connecté."""
    if key not in PREFERENCE_KEYS:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Préférence inconnue")
    if body is not None and len(json.dumps(body)) > PREFERENCE_MAX:
        raise HTTPException(status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, "Préférence trop volumineuse")
    account = await db.get(User, user.id)
    prefs = dict(account.preferences or {})
    if body:
        prefs[key] = body
    else:
        prefs.pop(key, None)
    account.preferences = prefs
    await db.commit()
    return {"key": key, "value": prefs.get(key)}
