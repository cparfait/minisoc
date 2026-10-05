"""Mots de passe (Argon2id), codes TOTP, jetons de session."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_hasher = PasswordHasher()
# Hachage factice : la vérification d'un utilisateur inconnu prend le même temps qu'un vrai échec
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))

MIN_PASSWORD_LENGTH = 12


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    try:
        return _hasher.verify(password_hash or _DUMMY_HASH, password) and password_hash is not None
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def password_problems(password: str, username: str = "") -> list[str]:
    problems = []
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"au moins {MIN_PASSWORD_LENGTH} caractères")
    if username and username.lower() in password.lower():
        problems.append("ne doit pas contenir l'identifiant")
    if len(set(password)) < 6:
        problems.append("trop peu de caractères différents")
    return problems


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="Mini-SOC")


def verify_totp(secret: str, code: str, last_step: int, now: float | None = None) -> int | None:
    """Retourne le pas de temps utilisé si le code est valide et jamais utilisé, sinon None."""
    code = (code or "").strip().replace(" ", "")
    if not code.isdigit() or len(code) != 6:
        return None
    totp = pyotp.TOTP(secret)
    now = time.time() if now is None else now
    current = int(now // totp.interval)
    for step in (current - 1, current, current + 1):  # tolère ±30 s de décalage d'horloge
        if step > last_step and hmac.compare_digest(totp.generate_otp(step), code):
            return step
    return None


def new_session_token() -> tuple[str, str]:
    """Retourne (jeton à placer dans le cookie, empreinte à stocker en base)."""
    token = secrets.token_urlsafe(32)
    return token, session_id(token)


def session_id(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    return bool(a) and bool(b) and hmac.compare_digest(a.encode(), b.encode())
