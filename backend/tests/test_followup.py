"""Suivi des alertes : échéances, prise en charge, mise en attente, assignation (lecture seule sur les outils)."""

from datetime import datetime, timedelta, timezone

import pytest

from minisoc.followup import FollowupError, apply_update, deadlines, overdue_filter
from minisoc.models import Alert, AlertHistory

NOW = datetime(2026, 10, 4, 12, 0, tzinfo=timezone.utc)


class Session:
    def __init__(self):
        self.added = []

    def add(self, obj):
        self.added.append(obj)


def alert(severity=4, status="new", hours_ago=2, **kw):
    created = NOW - timedelta(hours=hours_ago)
    return Alert(
        id=1,
        severity=severity,
        status=status,
        created_at=created,
        first_seen=created,
        last_seen=created,
        details={},
        notify_pending=True,
        **kw,
    )


def test_deadlines_follow_severity_and_pause_while_waiting():
    cfg = {}
    late = deadlines(alert(severity=4, hours_ago=2), cfg, now=NOW)  # critique : prise en charge sous 1 h
    assert late["overdue"] == "ack" and late["ack_due"].startswith("2026-10-04T11:00")
    acknowledged = alert(severity=4, hours_ago=2, acknowledged_at=NOW - timedelta(hours=1))
    assert deadlines(acknowledged, cfg, now=NOW)["overdue"] is None
    old = alert(severity=4, hours_ago=30, acknowledged_at=NOW)  # traitement sous 1 jour dépassé
    assert deadlines(old, cfg, now=NOW)["overdue"] == "resolve"
    assert deadlines(alert(severity=4, status="waiting", hours_ago=30), cfg, now=NOW)["overdue"] is None
    assert deadlines(alert(severity=4, status="resolved", hours_ago=30), cfg, now=NOW)["overdue"] is None
    assert deadlines(alert(severity=0), cfg, now=NOW) == {"ack_due": None, "resolve_due": None, "overdue": None}
    assert deadlines(alert(severity=2, hours_ago=2), cfg, now=NOW)["overdue"] is None  # moyenne : 24 h
    assert deadlines(alert(severity=2, hours_ago=2), {"sla_ack_medium": 1}, now=NOW)["overdue"] == "ack"


def test_overdue_filter_compiles():
    from sqlalchemy.dialects import postgresql

    sql = str(overdue_filter({}, NOW).compile(dialect=postgresql.dialect()))
    assert "acknowledged_at IS NULL" in sql and "CASE" in sql


def test_waiting_needs_a_reason_and_closing_a_comment():
    session = Session()
    a = alert()
    with pytest.raises(FollowupError, match="Motif"):
        apply_update(session, a, "m.durand", status="waiting")
    changes = apply_update(session, a, "m.durand", status="waiting", waiting_reason="prestataire")
    assert changes["status"] == ["new", "waiting"] and a.details["waiting"]["reason"] == "prestataire"
    assert a.acknowledged_at is not None and not a.notify_pending
    history = [h for h in session.added if isinstance(h, AlertHistory)]
    assert "intervention d'un prestataire" in history[0].detail
    apply_update(session, a, "m.durand", status="in_progress")
    assert "waiting" not in a.details
    with pytest.raises(FollowupError, match="commentaire"):
        apply_update(session, a, "m.durand", status="resolved")
    assert apply_update(session, a, "m.durand", status="resolved", comment="Traité dans HarfangLab")["comment"]


def test_assignment_counts_as_acknowledgement():
    session = Session()
    a = alert()
    changes = apply_update(session, a, "m.durand", assignee="j.dupont", assign=True)
    assert changes == {"assignee": [None, "j.dupont"]} and a.assignee == "j.dupont" and a.status == "new"
    assert a.acknowledged_at is not None
    assert apply_update(session, a, "m.durand", assignee="j.dupont", assign=True) == {}  # rien ne change
    apply_update(session, a, "m.durand", assignee=None, assign=True)
    assert a.assignee is None
