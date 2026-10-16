"""Statistiques (page Statistiques) : chargement des données de la période, calculs dans `minisoc.analytics`."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from sqlalchemy import func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import defer

from minisoc import analytics
from minisoc.api.deps import ANY_USER, get_db
from minisoc.models import OPEN_STATUSES, Alert, AlertHistory, Incident, IncidentEntry, User

router = APIRouter(prefix="/api/analytics", tags=["analytics"])


@router.get("")
async def get_analytics(
    request: Request,
    since: datetime | None = Query(None, description="début de la période (ISO 8601), 30 jours par défaut"),
    until: datetime | None = Query(None, description="fin de la période (ISO 8601), maintenant par défaut"),
    db: AsyncSession = Depends(get_db),
    _: User = Depends(ANY_USER),
):
    """Volumes d'alertes, qualité des détections, délais de traitement, MITRE et cibles, avec leur méthode de
    calcul. Période : alertes créées entre `since` (inclus) et `until` (exclu), 366 jours au plus."""
    now = datetime.now(timezone.utc)
    until = analytics.aware(until) if until else now
    since = analytics.aware(since) if since else until - timedelta(days=30)
    if since >= until:
        raise HTTPException(422, "Le début de la période doit précéder sa fin")
    if until - since > timedelta(days=analytics.MAX_DAYS):
        raise HTTPException(422, f"Période limitée à {analytics.MAX_DAYS} jours")
    previous_since = since - (until - since)

    in_period = (Alert.created_at >= since, Alert.created_at < until)
    alerts = list((await db.scalars(select(Alert).options(defer(Alert.event_ids)).where(*in_period))).all())
    previous_total = await db.scalar(select(func.count()).select_from(Alert).where(
        Alert.created_at >= previous_since, Alert.created_at < since)) or 0
    history = list((await db.scalars(
        select(AlertHistory).join(Alert, Alert.id == AlertHistory.alert_id)
        .where(*in_period, AlertHistory.action == "status")
    )).all())
    open_now = [(s, c) for s, c in (await db.execute(
        select(Alert.severity, Alert.created_at).where(Alert.status.in_(OPEN_STATUSES)))).all()]
    incidents = list((await db.scalars(select(Incident).where(or_(
        (Incident.created_at >= since) & (Incident.created_at < until),
        (Incident.closed_at >= since) & (Incident.closed_at < until),
    )))).all())
    entries = list((await db.scalars(select(IncidentEntry).where(
        IncidentEntry.incident_id.in_([i.id for i in incidents]), IncidentEntry.kind == "status"
    ))).all()) if incidents else []

    state = request.app.state
    tz = ZoneInfo(state.settings.timezone)
    rule_mitre = {r.id: list(r.mitre) for r in state.rules.rules}
    closings = analytics.closing_entries(alerts, history)
    return {
        "period": {"since": since.isoformat(), "until": until.isoformat(),
                   "previous_since": previous_since.isoformat(), "timezone": state.settings.timezone},
        "volumes": analytics.volumes(alerts, previous_total, since, until, tz),
        "quality": analytics.quality(alerts, closings),
        "delays": analytics.delays(alerts, closings, open_now, incidents, entries, since, until, tz, now),
        "mitre": analytics.mitre_targets(alerts, rule_mitre),
    }
