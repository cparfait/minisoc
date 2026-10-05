"""Vue « par détection » : alertes ouvertes regroupées par détection d'outil, et fiches de ces détections
(catégorie, sévérité recalibrée), appliquées aux nouvelles alertes et, à la demande, aux alertes ouvertes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc import audit
from minisoc.api.deps import ANALYST, ANY_USER, client_ip, get_db
from minisoc.detections import (
    CATEGORY_LABEL,
    SERVER_NAME,
    WIDESPREAD,
    apply_to_open_alerts,
    detection_key,
    load_suggestions,
    topics,
)
from minisoc.ecs import SEVERITY_BY_NAME, severity_name
from minisoc.models import DETECTION_CATEGORIES, OPEN_STATUSES, Alert, DetectionProfile, User

router = APIRouter(prefix="/api/detections", tags=["detections"])
MAX_HOSTS = 200


def _profile(p: DetectionProfile | None) -> dict | None:
    if p is None:
        return None
    return {
        "category": p.category,
        "severity": severity_name(p.severity) if p.severity is not None else None,
        "note": p.note,
        "author": p.author,
        "updated_at": p.updated_at.isoformat() if p.updated_at else None,
    }


@router.get("")
async def list_detections(db: AsyncSession = Depends(get_db), _: User = Depends(ANY_USER)):
    """Une ligne par détection d'outil présente dans les alertes ouvertes (ou dotée d'une fiche)."""
    alerts = (await db.scalars(select(Alert).where(Alert.status.in_(OPEN_STATUSES)))).all()
    grouped = topics(list(alerts))
    profiles = {detection_key(p.module, p.detection): p for p in (await db.scalars(select(DetectionProfile))).all()}
    suggestions = load_suggestions()
    items = []
    for key in set(grouped) | set(profiles):
        topic = grouped.get(key)
        profile = profiles.get(key)
        hosts = sorted((topic.hosts if topic else {}).items(), key=lambda h: (-h[1], h[0].lower()))
        suggestion = suggestions.get(key)
        items.append({
            "module": topic.module if topic else profile.module,
            "detection": topic.detection if topic else profile.detection,
            "category": profile.category if profile else "threat",
            "profile": _profile(profile),
            "suggestion": {
                "category": suggestion["category"],
                "severity": severity_name(int(suggestion["severity"])) if suggestion.get("severity") is not None
                else None,
                "why": suggestion.get("why", ""),
            } if suggestion and not profile else None,
            "alerts": len(topic.alerts) if topic else 0,
            "occurrences": topic.occurrences if topic else 0,
            "machines": len(hosts),
            "servers": sum(1 for h, _ in hosts if SERVER_NAME.match(h)),
            "widespread": len(hosts) >= WIDESPREAD,
            "hosts": [{"name": h, "count": c, "rules": [], "server": bool(SERVER_NAME.match(h))}
                      for h, c in hosts[:MAX_HOSTS]],
            "severity": severity_name(topic.severity) if topic else None,
            "tool_severity": severity_name(topic.tool_severity) if topic else None,
            "first_seen": topic.first_seen.isoformat() if topic and topic.first_seen else None,
            "last_seen": topic.last_seen.isoformat() if topic and topic.last_seen else None,
        })
    order = {"threat": 0, "hygiene": 1, "info": 2}
    items.sort(key=lambda t: (order.get(t["category"], 0), -t["alerts"], t["detection"].lower()))
    return {"items": items, "categories": CATEGORY_LABEL}


class ProfileIn(BaseModel):
    module: str = Field(min_length=1, max_length=64)
    detection: str = Field(min_length=1, max_length=256)
    category: str = Field(pattern="^(threat|hygiene|info)$")
    severity: str | None = Field(None, pattern="^(info|low|medium|high|critical)$")  # None : celle de l'outil
    note: str = Field("", max_length=2000)
    apply_open: bool = True  # appliquer aussi aux alertes ouvertes de cette détection


@router.put("/profile")
async def save_profile(body: ProfileIn, request: Request, db: AsyncSession = Depends(get_db),
                       user: User = Depends(ANALYST)):
    """Crée, modifie ou retire (menace, sévérité de l'outil, sans note) la fiche d'une détection."""
    if body.category not in DETECTION_CATEGORIES:
        raise HTTPException(422, "Catégorie inconnue")
    severity = SEVERITY_BY_NAME[body.severity] if body.severity else None
    module, detection = body.module.strip(), body.detection.strip()
    existing = await db.scalar(
        select(DetectionProfile).where(
            func.lower(DetectionProfile.module) == module.lower(),
            func.lower(DetectionProfile.detection) == detection.lower(),
        )
    )
    reset = body.category == "threat" and severity is None and not body.note.strip()
    if reset:
        profile = None
        if existing:
            await db.delete(existing)
    else:
        profile = existing or DetectionProfile(module=module, detection=detection, author=user.username)
        profile.category, profile.severity, profile.note = body.category, severity, body.note.strip()
        profile.author = user.username
        db.add(profile)
    await db.flush()
    changed = await apply_to_open_alerts(db, module, detection, profile, user.username) if body.apply_open else 0
    await audit.record(
        db, actor=user.username, ip=client_ip(request), action="detection_profile",
        obj=f"detection:{module}:{detection}"[:128],
        detail={"category": body.category, "severity": body.severity, "note": body.note.strip(),
                "reset": reset, "open_alerts_changed": changed},
    )
    await db.commit()
    return {"ok": True, "reset": reset, "open_alerts_changed": changed}
