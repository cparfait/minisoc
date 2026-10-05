"""Chiffrement des secrets stockés en base (AES-256-GCM, clé maître hors base)."""

from __future__ import annotations

import base64
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from minisoc.config import get_settings

_VERSION = "v1"


class CryptoError(RuntimeError):
    pass


def _key(master_key: str | None = None) -> bytes:
    encoded = master_key if master_key is not None else get_settings().master_key
    try:
        key = base64.urlsafe_b64decode(encoded + "=" * (-len(encoded) % 4))
    except (ValueError, TypeError) as exc:
        raise CryptoError("MINISOC_MASTER_KEY invalide (base64url attendu)") from exc
    if len(key) != 32:
        raise CryptoError("MINISOC_MASTER_KEY doit faire 32 octets (générer avec scripts/init_env.py)")
    return key


def encrypt(plaintext: str, master_key: str | None = None) -> str:
    nonce = os.urandom(12)
    data = AESGCM(_key(master_key)).encrypt(nonce, plaintext.encode(), _VERSION.encode())
    return f"{_VERSION}:{base64.urlsafe_b64encode(nonce + data).decode()}"


def decrypt(token: str, master_key: str | None = None) -> str:
    version, _, payload = token.partition(":")
    if version != _VERSION:
        raise CryptoError("format de secret inconnu")
    raw = base64.urlsafe_b64decode(payload)
    return AESGCM(_key(master_key)).decrypt(raw[:12], raw[12:], _VERSION.encode()).decode()
