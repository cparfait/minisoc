"""Suivi des alertes : prise en charge, assignation, mise en attente, échéances.

Le Mini-SOC ne modifie jamais les outils (lecture seule) : pour une alerte venue d'un outil, il suit qui la traite et
où on en est ; l'état de l'outil (lu, voir minisoc/source_sync.py) et la marche à suivre pour y agir s'affichent sur
l'alerte. Échéances (Paramètres › Suivi) : prise en charge en heures, traitement en jours, selon la sévérité ;
suspendues pendant une mise en attente.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from sqlalchemy import and_, case, or_
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc.ecs import severity_name
from minisoc.models import ALERT_STATUSES, WAITING_REASONS, Alert, AlertHistory, User

log = logging.getLogger(__name__)

SLA_SEVERITIES = {4: "critical", 3: "high", 2: "medium", 1: "low"}  # info (0) : pas d'échéance
WAITING_LABEL = {
    "utilisateur": "réponse de l'utilisateur",
    "prestataire": "intervention d'un prestataire",
    "editeur": "réponse de l'éditeur",
    "correctif": "correctif planifié",
    "autre": "autre",
}
DEFAULT_ACK = {"critical": 1, "high": 4, "medium": 24, "low": 72}  # heures
DEFAULT_RESOLVE = {"critical": 1, "high": 3, "medium": 7, "low": 30}  # jours


class FollowupError(ValueError):
    pass


def _aware(value: datetime | None) -> datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def sla(cfg: dict, severity: int) -> tuple[timedelta, timedelta] | None:
    name = SLA_SEVERITIES.get(severity)
    if not name:
        return None
    ack = int(cfg.get(f"sla_ack_{name}") or DEFAULT_ACK[name])
    resolve = int(cfg.get(f"sla_resolve_{name}") or DEFAULT_RESOLVE[name])
    return timedelta(hours=ack), timedelta(days=resolve)


def deadlines(alert: Alert, cfg: dict, now: datetime | None = None) -> dict:
    """Échéances de prise en charge et de traitement, et retard éventuel (« ack », « resolve » ou None)."""
    now = now or datetime.now(timezone.utc)
    limits = sla(cfg, alert.severity)
    created = _aware(alert.created_at) or _aware(alert.first_seen)
    if not limits or created is None:
        return {"ack_due": None, "resolve_due": None, "overdue": None}
    ack_due, resolve_due = created + limits[0], created + limits[1]
    overdue = None
    if alert.status in ("new", "in_progress"):  # en attente : échéances suspendues ; clôturée : sans objet
        if alert.acknowledged_at is None and now > ack_due:
            overdue = "ack"
        elif now > resolve_due:
            overdue = "resolve"
    return {"ack_due": ack_due.isoformat(), "resolve_due": resolve_due.isoformat(), "overdue": overdue}


def overdue_filter(cfg: dict, now: datetime | None = None):
    """Condition SQL « en retard » (mêmes règles que `deadlines`)."""
    now = now or datetime.now(timezone.utc)
    ack_cut, res_cut = {}, {}
    for severity in SLA_SEVERITIES:
        ack, resolve = sla(cfg, severity)
        ack_cut[severity], res_cut[severity] = now - ack, now - resolve
    ack_limit = case(ack_cut, value=Alert.severity, else_=None)
    res_limit = case(res_cut, value=Alert.severity, else_=None)
    active = Alert.status.in_(("new", "in_progress"))
    return and_(
        active,
        Alert.severity > 0,
        or_(
            and_(Alert.acknowledged_at.is_(None), Alert.created_at < ack_limit),
            Alert.created_at < res_limit,
        ),
    )


def apply_update(
    session: AsyncSession,
    alert: Alert,
    actor: str,
    *,
    status: str | None = None,
    assignee: str | None = None,
    assign: bool = False,
    waiting_reason: str | None = None,
    comment: str | None = None,
) -> dict:
    """Applique une mise à jour de suivi (une alerte ou un lot) ; renvoie les changements (journal d'audit)."""
    changes: dict = {}
    now = datetime.now(timezone.utc)
    comment = (comment or "").strip()
    if status is not None and status != alert.status:
        if status not in ALERT_STATUSES:
            raise FollowupError("Statut invalide")
        if status in ("resolved", "false_positive") and not comment:
            raise FollowupError("Un commentaire est obligatoire pour clôturer une alerte")
        if status == "waiting":
            if waiting_reason not in WAITING_REASONS:
                raise FollowupError(f"Motif de mise en attente attendu ({', '.join(WAITING_REASONS)})")
            alert.details = {
                **(alert.details or {}),
                "waiting": {"reason": waiting_reason, "since": now.isoformat(), "by": actor},
            }
        elif alert.status == "waiting":
            alert.details = {k: v for k, v in (alert.details or {}).items() if k != "waiting"}
        changes["status"] = [alert.status, status]
        detail = status if status != "waiting" else f"waiting : {WAITING_LABEL[waiting_reason]}"
        session.add(AlertHistory(alert_id=alert.id, actor=actor, action="status", detail=detail))
        alert.status = status
        if status not in ("new", "in_progress"):
            alert.notify_pending = False
    if assign and assignee != alert.assignee:
        changes["assignee"] = [alert.assignee, assignee]
        session.add(AlertHistory(alert_id=alert.id, actor=actor, action="assign", detail=assignee or "—"))
        alert.assignee = assignee or None
    if comment:
        changes["comment"] = True
        session.add(AlertHistory(alert_id=alert.id, actor=actor, action="comment", detail=comment))
    # Prise en charge : première fois que l'alerte quitte « nouvelle » ou reçoit un responsable
    if alert.acknowledged_at is None and (alert.status != "new" or alert.assignee):
        alert.acknowledged_at = now
    return changes


async def notify_assignee(cfg: dict, user: User | None, alerts: list[Alert], actor: str, public_url: str) -> bool:
    """E-mail à la personne assignée (si elle a une adresse et que la messagerie est réglée)."""
    if not user or not user.email or user.username == actor or not cfg.get("assign_notify", True):
        return False
    from minisoc.notify.email import configured, send_email

    if not configured(cfg):
        return False
    base = public_url.rstrip("/")
    lines = [f"- [{severity_name(a.severity)}] {a.title}\n  {base}/alerts/{a.id}" for a in alerts[:50]]
    more = f"\n… et {len(alerts) - 50} autre(s)." if len(alerts) > 50 else ""
    subject = (
        f"[Mini-SOC] Alerte assignée par {actor} : {alerts[0].title}"
        if len(alerts) == 1
        else f"[Mini-SOC] {len(alerts)} alertes assignées par {actor}"
    )
    body = (
        f"Bonjour,\n\n{actor} vous a assigné {'cette alerte' if len(alerts) == 1 else 'ces alertes'} :\n\n"
        + "\n".join(lines)
        + more
        + f"\n\nVos alertes : {base}/alerts?assignee=me\n"
    )
    try:
        await send_email(cfg, subject, body, to=[user.email])
        return True
    except Exception as exc:  # noqa: BLE001 - l'assignation reste valable même si l'e-mail échoue
        log.warning("e-mail d'assignation non envoyé à %s : %s", user.username, exc)
        return False
