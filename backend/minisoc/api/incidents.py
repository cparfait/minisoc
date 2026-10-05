"""Incidents (F-24) : regrouper des alertes liées, suivre l'enquête et la remédiation, conclure, produire un rapport."""

from __future__ import annotations

from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc import audit
from minisoc.api.alerts import serialize as serialize_alert
from minisoc.api.deps import ANALYST, ANY_USER, client_ip, get_db
from minisoc.ecs import SEVERITY_BY_NAME, severity_name
from minisoc.models import (
    INCIDENT_CATEGORIES,
    INCIDENT_STATUSES,
    OPEN_STATUSES,
    Alert,
    AlertHistory,
    Incident,
    IncidentEntry,
    User,
)

router = APIRouter(prefix="/api/incidents", tags=["incidents"])

STATUS_LABEL = {"open": "Ouvert", "investigating": "En investigation", "contained": "Maîtrisé", "closed": "Clos"}
CATEGORY_LABEL = {
    "compromission_compte": "Compromission de compte", "malware": "Logiciel malveillant",
    "rancongiciel": "Rançongiciel", "hameconnage": "Hameçonnage", "intrusion": "Intrusion",
    "fuite_donnees": "Fuite de données", "deni_service": "Déni de service", "autre": "Autre",
}
ENTRY_KINDS = ("note", "action")
TZ = ZoneInfo("Europe/Paris")


def _serialize(incident: Incident, alert_count: int = 0) -> dict:
    return {
        "id": incident.id, "title": incident.title, "description": incident.description,
        "category": incident.category, "severity": severity_name(incident.severity), "status": incident.status,
        "owner": incident.owner, "created_by": incident.created_by, "personal_data": incident.personal_data,
        "conclusion": incident.conclusion, "alert_count": alert_count,
        "created_at": incident.created_at.isoformat() if incident.created_at else None,
        "updated_at": incident.updated_at.isoformat() if incident.updated_at else None,
        "closed_at": incident.closed_at.isoformat() if incident.closed_at else None,
    }


async def _get(db: AsyncSession, incident_id: int, lock: bool = False) -> Incident:
    incident = await db.get(Incident, incident_id, with_for_update=lock)
    if not incident:
        raise HTTPException(404, "Incident introuvable")
    await db.refresh(incident)  # dates calculées par la base (création, mise à jour) relues
    return incident


def _entry(db: AsyncSession, incident: Incident, actor: str, kind: str, detail: str) -> None:
    db.add(IncidentEntry(incident_id=incident.id, actor=actor, kind=kind, detail=detail[:8000]))


async def _attach(db: AsyncSession, incident: Incident, alert_ids: list[int], actor: str) -> list[int]:
    """Rattache des alertes ; une alerte nouvelle passe « en cours » (elle est prise en charge par l'incident)."""
    if not alert_ids:
        return []
    alerts = (await db.scalars(select(Alert).where(Alert.id.in_(alert_ids)).with_for_update())).all()
    attached = []
    for alert in alerts:
        if alert.incident_id == incident.id:
            continue
        alert.incident_id = incident.id
        if alert.acknowledged_at is None:
            alert.acknowledged_at = datetime.now(timezone.utc)  # prise en charge par l'incident
        if alert.status == "new":
            alert.status = "in_progress"
            alert.notify_pending = False
            db.add(AlertHistory(alert_id=alert.id, actor=actor, action="status", detail="in_progress"))
        db.add(AlertHistory(alert_id=alert.id, actor=actor, action="comment",
                            detail=f"Rattachée à l'incident n° {incident.id} : {incident.title}"))
        _entry(db, incident, actor, "alert_added", f"Alerte n° {alert.id} : {alert.title}")
        incident.severity = max(incident.severity, alert.severity)
        attached.append(alert.id)
    return attached


@router.get("")
async def list_incidents(status: str | None = Query(None, description="statuts séparés par des virgules"),
                         db: AsyncSession = Depends(get_db), _: User = Depends(ANY_USER)):
    stmt = select(Incident)
    statuses = [s for s in (status or "").split(",") if s in INCIDENT_STATUSES]
    if statuses:
        stmt = stmt.where(Incident.status.in_(statuses))
    stmt = stmt.order_by(Incident.status == "closed", Incident.updated_at.desc()).limit(500)
    incidents = (await db.scalars(stmt)).all()
    counts = dict((await db.execute(
        select(Alert.incident_id, func.count()).where(Alert.incident_id.in_([i.id for i in incidents]))
        .group_by(Alert.incident_id))).all()) if incidents else {}
    by_status = dict((await db.execute(select(Incident.status, func.count()).group_by(Incident.status))).all())
    return {"items": [_serialize(i, counts.get(i.id, 0)) for i in incidents], "by_status": by_status,
            "categories": CATEGORY_LABEL, "statuses": STATUS_LABEL}


class IncidentCreate(BaseModel):
    title: str = Field(min_length=3, max_length=300)
    description: str = Field("", max_length=8000)
    category: str = "autre"
    severity: str | None = None
    alert_ids: list[int] = Field(default_factory=list, max_length=500)


@router.post("", status_code=201)
async def create_incident(body: IncidentCreate, request: Request, db: AsyncSession = Depends(get_db),
                          user: User = Depends(ANALYST)):
    if body.category not in INCIDENT_CATEGORIES:
        raise HTTPException(422, "Catégorie inconnue")
    incident = Incident(title=body.title.strip(), description=body.description.strip(), category=body.category,
                        severity=SEVERITY_BY_NAME.get(body.severity or "", 0), status="open", owner=user.username,
                        created_by=user.username)
    db.add(incident)
    await db.flush()
    _entry(db, incident, user.username, "created", body.description.strip() or "Incident créé")
    attached = await _attach(db, incident, body.alert_ids, user.username)
    if not body.severity and not attached:
        incident.severity = SEVERITY_BY_NAME["medium"]
    await audit.record(db, actor=user.username, ip=client_ip(request), action="incident_create",
                       obj=f"incident:{incident.id}", detail={"alerts": attached})
    await db.commit()
    await db.refresh(incident)
    return _serialize(incident, len(attached))


@router.get("/{incident_id}")
async def get_incident(incident_id: int, db: AsyncSession = Depends(get_db), _: User = Depends(ANY_USER)):
    incident = await _get(db, incident_id)
    alerts = (await db.scalars(select(Alert).where(Alert.incident_id == incident_id).order_by(Alert.first_seen))).all()
    entries = (await db.scalars(select(IncidentEntry).where(IncidentEntry.incident_id == incident_id)
                                .order_by(IncidentEntry.ts))).all()
    return {
        **_serialize(incident, len(alerts)),
        "alerts": [serialize_alert(a) for a in alerts],
        "entries": [{"id": e.id, "ts": e.ts.isoformat(), "actor": e.actor, "kind": e.kind, "detail": e.detail}
                    for e in entries],
        "categories": CATEGORY_LABEL, "statuses": STATUS_LABEL,
    }


class IncidentUpdate(BaseModel):
    title: str | None = Field(None, min_length=3, max_length=300)
    description: str | None = Field(None, max_length=8000)
    category: str | None = None
    severity: str | None = None
    status: str | None = None
    owner: str | None = Field(None, max_length=64)
    personal_data: bool | None = None
    conclusion: str | None = Field(None, max_length=8000)
    close_alerts: bool = True  # à la clôture : clôturer aussi les alertes rattachées encore ouvertes


@router.patch("/{incident_id}")
async def update_incident(incident_id: int, body: IncidentUpdate, request: Request, db: AsyncSession = Depends(get_db),
                          user: User = Depends(ANALYST)):
    incident = await _get(db, incident_id, lock=True)
    changes: dict = {}
    for field in ("title", "description", "personal_data", "conclusion"):
        value = getattr(body, field)
        if value is not None and value != getattr(incident, field):
            setattr(incident, field, value.strip() if isinstance(value, str) else value)
            changes[field] = True
    if body.category is not None and body.category != incident.category:
        if body.category not in INCIDENT_CATEGORIES:
            raise HTTPException(422, "Catégorie inconnue")
        _entry(db, incident, user.username, "update", f"Catégorie : {CATEGORY_LABEL[body.category]}")
        incident.category, changes["category"] = body.category, body.category
    if body.severity is not None and SEVERITY_BY_NAME.get(body.severity) != incident.severity:
        if body.severity not in SEVERITY_BY_NAME:
            raise HTTPException(422, "Sévérité inconnue")
        _entry(db, incident, user.username, "update", f"Sévérité : {body.severity}")
        incident.severity, changes["severity"] = SEVERITY_BY_NAME[body.severity], body.severity
    if "owner" in body.model_fields_set and body.owner != incident.owner:
        _entry(db, incident, user.username, "update", f"Responsable : {body.owner or '—'}")
        incident.owner, changes["owner"] = body.owner or None, body.owner
    if body.status is not None and body.status != incident.status:
        if body.status not in INCIDENT_STATUSES:
            raise HTTPException(422, "Statut inconnu")
        if body.status == "closed":
            if len((incident.conclusion or "").strip()) < 20:
                raise HTTPException(422, "Une conclusion d'au moins 20 caractères est obligatoire pour clore "
                                         "l'incident (cause, impact, mesures prises)")
            incident.closed_at = datetime.now(timezone.utc)
            if body.close_alerts:
                for alert in (await db.scalars(select(Alert).where(Alert.incident_id == incident.id,
                                                                    Alert.status.in_(OPEN_STATUSES)))).all():
                    alert.status = "resolved"
                    alert.notify_pending = False
                    db.add(AlertHistory(alert_id=alert.id, actor=user.username, action="status", detail="resolved"))
                    db.add(AlertHistory(alert_id=alert.id, actor=user.username, action="comment",
                                        detail=f"Clôturée avec l'incident n° {incident.id}"))
        else:
            incident.closed_at = None
        _entry(db, incident, user.username, "status", STATUS_LABEL[body.status])
        changes["status"] = [incident.status, body.status]
        incident.status = body.status
    if changes:
        await audit.record(db, actor=user.username, ip=client_ip(request), action="incident_update",
                           obj=f"incident:{incident.id}", detail=changes)
        await db.commit()
    return await get_incident(incident_id, db, user)


class EntryCreate(BaseModel):
    kind: str = "note"
    detail: str = Field(min_length=1, max_length=8000)


@router.post("/{incident_id}/entries", status_code=201)
async def add_entry(incident_id: int, body: EntryCreate, db: AsyncSession = Depends(get_db),
                    user: User = Depends(ANALYST)):
    incident = await _get(db, incident_id)
    if body.kind not in ENTRY_KINDS:
        raise HTTPException(422, "Type d'entrée inconnu (note ou action)")
    _entry(db, incident, user.username, body.kind, body.detail.strip())
    incident.updated_at = datetime.now(timezone.utc)
    await db.commit()
    return {"ok": True}


class AlertLinks(BaseModel):
    alert_ids: list[int] = Field(min_length=1, max_length=500)
    remove: bool = False


@router.post("/{incident_id}/alerts")
async def link_alerts(incident_id: int, body: AlertLinks, request: Request, db: AsyncSession = Depends(get_db),
                      user: User = Depends(ANALYST)):
    incident = await _get(db, incident_id, lock=True)
    if body.remove:
        alerts = (await db.scalars(select(Alert).where(Alert.id.in_(body.alert_ids),
                                                       Alert.incident_id == incident.id))).all()
        for alert in alerts:
            alert.incident_id = None
            _entry(db, incident, user.username, "alert_removed", f"Alerte n° {alert.id} : {alert.title}")
        changed = [a.id for a in alerts]
    else:
        changed = await _attach(db, incident, body.alert_ids, user.username)
    if changed:
        incident.updated_at = datetime.now(timezone.utc)
        await audit.record(db, actor=user.username, ip=client_ip(request),
                           action="incident_unlink" if body.remove else "incident_link",
                           obj=f"incident:{incident.id}", detail={"alerts": changed})
        await db.commit()
    return {"changed": changed}


def _date(value: datetime | None) -> str:
    return value.astimezone(TZ).strftime("%d/%m/%Y %H:%M") if value else "—"


@router.get("/{incident_id}/report", response_class=PlainTextResponse)
async def incident_report(incident_id: int, request: Request, db: AsyncSession = Depends(get_db),
                          user: User = Depends(ANY_USER)):
    """Rapport d'incident en Markdown (archivage, déclaration CNIL / ANSSI, retour d'expérience)."""
    incident = await _get(db, incident_id)
    alerts = (await db.scalars(select(Alert).where(Alert.incident_id == incident_id).order_by(Alert.first_seen))).all()
    entries = (await db.scalars(select(IncidentEntry).where(IncidentEntry.incident_id == incident_id)
                                .order_by(IncidentEntry.ts))).all()
    first = min((a.first_seen for a in alerts), default=incident.created_at)
    lines = [
        f"# Incident n° {incident.id} : {incident.title}",
        "",
        "| | |",
        "| --- | --- |",
        f"| Statut | {STATUS_LABEL.get(incident.status, incident.status)} |",
        f"| Catégorie | {CATEGORY_LABEL.get(incident.category, incident.category)} |",
        f"| Sévérité | {severity_name(incident.severity)} |",
        f"| Responsable | {incident.owner or '—'} |",
        f"| Premier signe | {_date(first)} |",
        f"| Ouvert le | {_date(incident.created_at)} par {incident.created_by} |",
        f"| Clos le | {_date(incident.closed_at)} |",
        "| Données personnelles concernées | "
        + ("oui : notification CNIL sous 72 h à évaluer" if incident.personal_data else "non") + " |",
        "",
        "## Description",
        "",
        incident.description or "—",
        "",
        f"## Alertes rattachées ({len(alerts)})",
        "",
        "| N° | Règle | Sévérité | Première / dernière détection | Statut | Alerte |",
        "| --- | --- | --- | --- | --- | --- |",
        *[f"| {a.id} | {a.rule_id} | {severity_name(a.severity)} | {_date(a.first_seen)} / {_date(a.last_seen)} | "
          f"{a.status} | {a.title.replace('|', '/')} |" for a in alerts],
        "",
        "## Chronologie",
        "",
        *[f"- **{_date(e.ts)}** · {e.actor} · {e.kind} : {e.detail}" for e in entries],
        "",
        "## Conclusion",
        "",
        incident.conclusion or "_Incident non conclu._",
        "",
        f"_Rapport généré par le Mini-SOC le {_date(datetime.now(timezone.utc))} pour {user.username}._",
    ]
    await audit.record(db, actor=user.username, ip=client_ip(request), action="incident_report",
                       obj=f"incident:{incident.id}")
    await db.commit()
    return PlainTextResponse("\n".join(lines), media_type="text/markdown; charset=utf-8", headers={
        "Content-Disposition": f'attachment; filename="incident-{incident.id}.md"', "Cache-Control": "no-store"})
