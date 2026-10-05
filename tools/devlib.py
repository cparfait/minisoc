"""DÉVELOPPEMENT : client HTTPS de test (session par cookie, TOTP) partagé par les scripts de `tools/`."""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.cookiejar
import json
import ssl
import struct
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

BASE = "https://localhost"
CREDS = json.loads((Path(__file__).resolve().parent.parent / ".dev-credentials.json").read_text())
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE  # certificat de l'autorité locale de Caddy
JAR = http.cookiejar.CookieJar()
OPENER = urllib.request.build_opener(urllib.request.HTTPSHandler(context=CTX), urllib.request.HTTPCookieProcessor(JAR))


def totp(secret: str, offset: int = 0) -> str:
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    counter = struct.pack(">Q", int(time.time() // 30) + offset)
    digest = hmac.new(key, counter, hashlib.sha1).digest()
    pos = digest[-1] & 0x0F
    return f"{(struct.unpack('>I', digest[pos:pos + 4])[0] & 0x7FFFFFFF) % 1_000_000:06d}"


def call(method: str, path: str, body=None, csrf: bool = True):
    headers = {"Content-Type": "application/json"}
    if csrf:
        headers["X-MiniSOC"] = "1"
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(BASE + path, data=data, headers=headers, method=method)
    try:
        with OPENER.open(req, timeout=15) as res:
            return res.status, json.loads(res.read() or b"null"), res.headers
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read() or b"null"), err.headers


def login() -> None:
    """Connexion du compte de démonstration (le code TOTP courant peut déjà avoir servi : on tente le suivant)."""
    for offset in (1, 0, 2):
        call("POST", "/api/auth/login", {"username": CREDS["username"], "password": CREDS["password"]})
        status, body, _ = call("POST", "/api/auth/verify", {"code": totp(CREDS["totp_secret"], offset)})
        if status == 200:
            return
    raise RuntimeError(f"connexion impossible : {body}")
