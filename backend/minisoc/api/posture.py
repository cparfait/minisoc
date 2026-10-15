"""Score de risque par entité, exposition réelle (que corriger en premier) et recherche par CVE."""

from __future__ import annotations

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import Text, cast, or_, select
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc import coverage, identity, trivy
from minisoc import cve as cve_search
from minisoc.api.deps import ANALYST, ANY_USER, get_db
from minisoc.assets import INDEX, key_for
from minisoc.connectors import cyberwatch
from minisoc.connectors.ninjaone import POSTURE_KEY
from minisoc.exposure import load_postures, ranking
from minisoc.models import OPEN_STATUSES, Alert, Asset, User
from minisoc.risk import RISK_WINDOW, compute_risk
from minisoc.settings_store import store as settings_store
from minisoc.threat_feeds import CERTFR_KEY, KEV_KEY

router = APIRouter(prefix="/api", tags=["posture"])


async def _risks(request: Request, db: AsyncSession) -> dict:
    now = datetime.now(timezone.utc)
    alerts = list((await db.scalars(select(Alert).where(Alert.last_seen >= now - RISK_WINDOW))).all())
    index = await INDEX.ensure(db)
    mitre = {r.id: r.mitre for r in request.app.state.rules.rules}

    def criticality(kind: str, name: str) -> str | None:
        info = index.host(name) if kind == "host" else index.account(name)
        return info.criticality if info else None

    categories = {r.id: r.category for r in request.app.state.rules.rules}
    return compute_risk(alerts, mitre, criticality, now, categories)


@router.get("/risk")
async def risk_top(
    request: Request,
    limit: int = Query(20, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(ANY_USER),
):
    """Machines et comptes les plus à risque (7 jours) ; le seuil d'alerte vient de Paramètres › Détection."""
    cfg = await settings_store.load(db)
    risks = sorted((r.to_dict() for r in (await _risks(request, db)).values()), key=lambda r: -r["score"])
    return {"threshold": int(cfg.get("risk_threshold") or 60), "items": [r for r in risks if r["score"] > 0][:limit]}


@router.get("/risk/entity")
async def risk_entity(
    request: Request,
    kind: str = Query(pattern="^(host|account)$"),
    name: str = Query(min_length=1, max_length=256),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(ANY_USER),
):
    cfg = await settings_store.load(db)
    risk = (await _risks(request, db)).get(("host" if kind == "host" else "user", key_for(kind, name)))
    return {"threshold": int(cfg.get("risk_threshold") or 60), "risk": risk.to_dict() if risk else None}


@router.get("/exposure")
async def exposure(
    request: Request,
    limit: int = Query(30, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(ANY_USER),
):
    """Machines à corriger en premier : vulnérabilités, antivirus, menaces, failles KEV, exposition, criticité."""
    redis = request.app.state.redis
    postures = load_postures(await redis.hgetall(POSTURE_KEY))
    cyber = cyberwatch.load_states(await redis.hgetall(cyberwatch.STATE_KEY))
    assets = list((await db.scalars(select(Asset).where(Asset.kind == "host"))).all())
    alerts = list((await db.scalars(select(Alert).where(Alert.status.in_(OPEN_STATUSES)))).all())
    return {
        "items": ranking(postures, assets, alerts, limit, cyber),
        "ninjaone": bool(postures),
        "cyberwatch": bool(cyber),
    }


@router.get("/cve")
async def cve_fleet(
    request: Request,
    kev_only: bool = False,
    limit: int = Query(100, ge=1, le=500),
    _: User = Depends(ANY_USER),
):
    """CVE présentes sur le parc (Cyberwatch, et Trivy pour les images et serveurs), les failles KEV d'abord."""
    redis = request.app.state.redis
    states = cyberwatch.load_states(await redis.hgetall(cyberwatch.STATE_KEY))
    scans = trivy.load_states(await redis.hgetall(trivy.STATE_KEY))
    kev = set(await redis.hkeys(KEV_KEY))
    rows = cve_search.fleet({**states, **{f"trivy:{k}": v for k, v in scans.items()}}, kev, limit=100000)
    total = len(rows)
    if kev_only:
        rows = [r for r in rows if r["kev"]]
    at = await redis.get(cyberwatch.STATE_AT_KEY)
    times = [float(at)] if at else []
    for st in scans.values():
        try:
            times.append(datetime.fromisoformat(st["received_at"]).timestamp())
        except (KeyError, TypeError, ValueError):
            continue
    return {"items": rows[:limit], "total": total, "assets": len(states) + len(scans),
            "sources": {"cyberwatch": len(states), "trivy": len(scans)}, "at": max(times) if times else None}


@router.get("/cve/{code}")
async def cve_detail(
    code: str,
    request: Request,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(ANY_USER),
):
    """Une CVE : machines touchées (Cyberwatch), veille (KEV, CERT-FR), détections et alertes qui la citent."""
    try:
        code = cve_search.normalize(code)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    state = request.app.state
    cfg = await settings_store.load(db)
    states = cyberwatch.load_states(await state.redis.hgetall(cyberwatch.STATE_KEY))
    lookup = await cve_search.cyberwatch_lookup(cfg, states, code)
    by_id = {s.get("id"): s for s in states.values()}
    for machine in lookup["machines"]:  # type et adresse connus par le relevé
        known = by_id.get(machine["asset_id"])
        if known:
            machine["server"] = bool(known.get("server"))
            machine["ip"] = machine["ip"] or known.get("ip", "")
    index = await INDEX.ensure(db)
    machines = cve_search.merge_inventory(lookup.pop("machines"), index)
    certfr = [
        {k: item.get(k) for k in ("kind", "title", "link", "date")}
        for item in json.loads(await state.redis.get(CERTFR_KEY) or "[]")
        if code in (item.get("cves") or [])
    ]
    alerts = (
        await db.scalars(
            select(Alert)
            .where(or_(Alert.title.ilike(f"%{code}%"), cast(Alert.details, Text).ilike(f"%{code}%")))
            .order_by(Alert.last_seen.desc())
            .limit(50)
        )
    ).all()
    return {
        "cve": code,
        "kev": cve_search.kev_entry(await state.redis.hget(KEV_KEY, code)),
        "certfr": certfr,
        "cyberwatch": lookup,
        "machines": machines,
        "trivy": trivy.by_cve(trivy.load_states(await state.redis.hgetall(trivy.STATE_KEY)), code),
        "counts": {s: sum(1 for m in machines if m["status"] == s) for s in ("vulnerable", "ignored", "fixed")},
        "detections": await cve_search.detections(state.store, code),
        "alerts": [
            {"id": a.id, "title": a.title, "status": a.status, "severity": a.severity, "rule_id": a.rule_id,
             "last_seen": a.last_seen.isoformat() if a.last_seen else None}
            for a in alerts
        ],
        "ninjaone": {"available": False,
                     "reason": "L'API NinjaOne ne donne pas les CVE par poste (seulement des nombres par gravité)."},
    }


@router.get("/coverage")
async def coverage_status(request: Request, _: User = Depends(ANY_USER)):
    """Dernière vérification de couverture (antivirus GravityZone, EDR HarfangLab) et tables d'identités."""
    return {"coverage": await coverage.status(request.app.state.redis),
            "identities": await identity.status(request.app.state.redis)}


@router.post("/coverage/run", status_code=202)
async def coverage_run(request: Request, _: User = Depends(ANALYST)):
    """Vérification de couverture au prochain passage (dans les 10 secondes)."""
    await request.app.state.redis.set(coverage.NOW_KEY, "1", ex=3600)
    return {"queued": True}
