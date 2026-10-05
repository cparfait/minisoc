"""DÉVELOPPEMENT : test de fumée de l'API à travers Caddy (HTTPS), avec le compte de `.dev-credentials.json`.

    python tools/smoke_api.py [https://localhost]

Vérifie : connexion mot de passe + TOTP, anti-rejeu TOTP, protection CSRF, règles de clôture des alertes,
recherche d'événements, exceptions, en-têtes de sécurité. Aucune dépendance externe.
"""

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

BASE = sys.argv[1] if len(sys.argv) > 1 else "https://localhost"
CREDS = json.loads((Path(__file__).resolve().parent.parent / ".dev-credentials.json").read_text())
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE  # certificat de l'autorité locale de Caddy
JAR = http.cookiejar.CookieJar()
OPENER = urllib.request.build_opener(urllib.request.HTTPSHandler(context=CTX), urllib.request.HTTPCookieProcessor(JAR))
failures = 0


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


def check(label: str, condition: bool, detail: object = "") -> None:
    global failures
    print(f"{'OK ' if condition else 'KO '} {label}" + (f"  ({detail})" if not condition and detail else ""))
    failures += 0 if condition else 1


status, _, _ = call("GET", "/api/alerts")
check("accès refusé sans session", status == 401, status)

status, body, _ = call("POST", "/api/auth/login", {"username": CREDS["username"], "password": "faux"})
check("mauvais mot de passe refusé", status == 401, status)

status, _, _ = call("POST", "/api/auth/verify", {"code": "123456"})
check("second facteur sans étape 1 refusé", status == 401, status)

status, body, _ = call("POST", "/api/auth/login", {"username": CREDS["username"], "password": CREDS["password"]})
check("étape 1 : mot de passe accepté, code demandé", status == 200 and body.get("step") == "totp", body)
status, _, _ = call("GET", "/api/alerts")
check("pas d'accès aux données entre les deux étapes", status == 401, status)

status, body, _ = call("POST", "/api/auth/verify", {"code": "000000"})
check("mauvais code refusé avec essais restants", status == 401 and "essai" in str(body), body)

code = totp(CREDS["totp_secret"])
status, body, headers = call("POST", "/api/auth/verify", {"code": code})
check("étape 2 : connexion avec le code TOTP", status == 200, body)
cookie = next((c for c in headers.get_all("Set-Cookie") or [] if c.startswith("minisoc_session=")), "")
check("cookie de session HttpOnly, Secure, SameSite=Strict",
      all(flag in cookie.lower() for flag in ("httponly", "secure", "samesite=strict")), cookie)

saved = list(JAR)
JAR.clear()
call("POST", "/api/auth/login", {"username": CREDS["username"], "password": CREDS["password"]})
status, _, _ = call("POST", "/api/auth/verify", {"code": code})
check("rejeu du même code TOTP refusé", status == 401, status)
JAR.clear()
for c in saved:
    JAR.set_cookie(c)

status, me, headers = call("GET", "/api/auth/me")
check("session active", status == 200 and me["username"] == CREDS["username"], me)
csp = headers.get("Content-Security-Policy") or headers.get("content-security-policy") or ""
check("en-tête Content-Security-Policy présent", "default-src 'self'" in csp, csp)

status, overview, _ = call("GET", "/api/stats/overview")
check("tableau de bord", status == 200 and "open_by_severity" in overview, status)

status, alerts, _ = call("GET", "/api/alerts?status=new,in_progress&limit=5")
check("liste des alertes", status == 200 and alerts["total"] > 0, alerts)
alert_id = alerts["items"][0]["id"]

status, _, _ = call("PATCH", f"/api/alerts/{alert_id}", {"status": "in_progress"}, csrf=False)
check("modification sans en-tête CSRF refusée", status == 403, status)

status, _, _ = call("PATCH", f"/api/alerts/{alert_id}", {"status": "resolved"})
check("clôture sans commentaire refusée", status == 422, status)

status, detail, _ = call("PATCH", f"/api/alerts/{alert_id}", {"status": "in_progress", "assignee": CREDS["username"],
                                                              "comment": "Prise en charge (test de fumée)"})
check("prise en charge avec commentaire", status == 200 and detail["status"] == "in_progress", detail)

status, detail, _ = call("GET", f"/api/alerts/{alert_id}")
check("détail : historique, fiche réflexe, événements",
      status == 200 and detail["history"] and "events" in detail, status)

status, events, _ = call("GET", "/api/events?outcome=failure&limit=5")
check("recherche d'événements", status == 200 and len(events["items"]) > 0, status)

status, events, _ = call("GET", "/api/events?q=%27%20OR%201%3D1%20--&limit=5")
check("recherche avec injection SQL inoffensive", status == 200, status)

status, exc, _ = call("POST", "/api/exceptions", {"rule_id": "UC-01", "field": "source.ip", "value": "192.0.2.99",
                                                   "reason": "court", "expires_at": "2026-12-31T00:00:00Z"})
check("exception sans justification suffisante refusée", status == 422, status)

status, _, _ = call("GET", "/api/docs")
check("documentation de l'API non exposée", status == 404, status)

status, _, _ = call("POST", "/api/auth/logout")
status2, _, _ = call("GET", "/api/auth/me")
check("déconnexion", status == 200 and status2 == 401, (status, status2))

print(f"\n{'Tous les contrôles sont passés.' if not failures else f'{failures} contrôle(s) en échec.'}")
sys.exit(1 if failures else 0)
