"""Application FastAPI. Lancement : uvicorn minisoc.api.main:app"""

from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text

from minisoc import __version__, bus
from minisoc.api import accounts as accounts_api
from minisoc.api import (
    admin,
    ai,
    alerts,
    archives,
    auth,
    data,
    detections,
    exceptions,
    incidents,
    ingest,
    iocs,
    reports,
    rules_admin,
    search,
    trivy,
    wall,
)
from minisoc.api import assets as assets_api
from minisoc.api import integrations as integrations_api
from minisoc.api import posture as posture_api
from minisoc.api import response as response_api
from minisoc.config import get_settings
from minisoc.db import init_db, sessionmaker
from minisoc.events_store import EventStore
from minisoc.identity import IDENTITIES
from minisoc.rules.custom import load_all
from minisoc.rules.engine import RuleSet
from minisoc.upgrade import categorize_rule_alerts, keep_working_integrations, retire_unreliable_antivirus

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
CSRF_HEADER = "x-minisoc"


async def _refresh_identities(redis) -> None:
    """Tables d'alias des comptes et machines (minisoc/identity.py) : risque, inventaire, recherche."""
    while True:
        await IDENTITIES.ensure(redis)
        await asyncio.sleep(30)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()
    await init_db()
    app.state.settings = settings
    app.state.redis = bus.connect()
    app.state.store = await EventStore.connect()
    await app.state.store.ensure_schema()
    async with sessionmaker()() as session:
        app.state.rules = RuleSet(await load_all(session, settings.rules_dir))
        await keep_working_integrations(session, app.state.redis)  # mise à jour d'une installation existante
        await categorize_rule_alerts(session, app.state.rules)
        await retire_unreliable_antivirus(session)
    identities = asyncio.create_task(_refresh_identities(app.state.redis))
    yield
    identities.cancel()
    await app.state.redis.aclose()
    await app.state.store.close()


app = FastAPI(title="Mini-SOC", version=__version__, lifespan=lifespan, docs_url="/api/docs",
              openapi_url="/api/openapi.json", redoc_url=None)


@app.middleware("http")
async def csrf_guard(request: Request, call_next):
    """Toute requête modifiante authentifiée par cookie doit porter l'en-tête X-MiniSOC.

    Un site tiers ne peut pas ajouter cet en-tête sans requête CORS préalable (non autorisée ici).
    Les points de réception sont authentifiés par jeton et exemptés.
    """
    path = request.url.path
    if request.method in UNSAFE_METHODS and path.startswith("/api/") and not path.startswith("/api/ingest/"):
        if request.headers.get(CSRF_HEADER) != "1":
            return JSONResponse({"detail": "En-tête X-MiniSOC manquant"}, status_code=403)
    response = await call_next(request)
    response.headers.setdefault("Cache-Control", "no-store")
    return response


@app.get("/api/health")
async def health():
    """Vivacité de l'API seule."""
    return {"status": "ok"}


WORKER_STALE_SECONDS = 120
QUEUE_LAG_MAX = 50_000


@app.get("/api/health/full")
async def health_full(request: Request):
    """Bilan pour la sonde externe (S-12) : HTTP 503 si un composant est en panne. Aucune donnée sensible."""
    state = request.app.state
    checks: dict[str, object] = {}
    try:
        async with sessionmaker()() as db:
            await db.execute(text("SELECT 1"))
        checks["postgres"] = True
    except Exception:  # noqa: BLE001
        checks["postgres"] = False
    try:
        await state.redis.ping()
        checks["redis"] = True
        beat = await state.redis.get(bus.WORKER_HEARTBEAT_KEY)
        age = (datetime.now(timezone.utc) - datetime.fromisoformat(beat)).total_seconds() if beat else None
        checks["worker"] = age is not None and age < WORKER_STALE_SECONDS
        queue = await bus.queue_state(state.redis)
        checks["queue_lag"] = queue["lag"]
        checks["queue_ok"] = queue["lag"] < QUEUE_LAG_MAX
    except Exception:  # noqa: BLE001
        checks.update(redis=False, worker=False, queue_ok=False)
    try:
        await state.store.query("SELECT 1")
        checks["clickhouse"] = True
    except Exception:  # noqa: BLE001
        checks["clickhouse"] = False
    healthy = all(v for k, v in checks.items() if isinstance(v, bool))
    return JSONResponse({"status": "ok" if healthy else "degraded", "checks": checks},
                        status_code=200 if healthy else 503)


for module in (auth, alerts, data, exceptions, ingest, wall, admin, ai, response_api, integrations_api, accounts_api,
               incidents, reports, detections, search, rules_admin, assets_api, iocs, archives, posture_api, trivy):
    app.include_router(module.router)
