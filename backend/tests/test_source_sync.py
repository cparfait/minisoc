"""Synchronisation des statuts avec les outils d'origine et stockage du contenu brut en JSON valide."""

import json
from datetime import datetime, timezone

from minisoc.models import Alert, AlertHistory
from minisoc.parsers.common import compact_json
from minisoc.parsers.harfanglab import BULKY, parse_harfanglab
from minisoc.source_sync import (
    close,
    harfanglab_closure,
    harfanglab_ids,
    ninjaone_closure,
    posture_resolved,
)

NOW = datetime(2026, 10, 3, 9, 0, tzinfo=timezone.utc)


def test_harfanglab_closure_keeps_author_and_date():
    detail = {
        "status": "false_positive",
        "status_history": [
            {"action": "created", "timestamp": "2026-10-01T13:30:01Z"},
            {"action": "status_update", "from_status": "new", "to_status": "false_positive",
             "timestamp": "2026-10-03T08:12:00Z", "username": "informatique"},
        ],
    }
    closure = harfanglab_closure(detail, sources=68)
    assert closure.status == "false_positive" and closure.label == "faux positif"
    assert closure.by == "informatique" and closure.at == "2026-10-03T08:12:00Z"
    text = closure.text()
    assert "Clôturée dans HarfangLab : faux positif, par informatique, le 03/10/2026 10:12" in text
    assert "68 alertes HarfangLab, toutes traitées" in text and "sans suppression" in text
    assert harfanglab_closure({"status": "closed", "status_history": []}, 1).status == "resolved"
    assert harfanglab_closure({"status": "investigating"}, 1) is None
    assert harfanglab_closure({"status": "new"}, 1) is None
    deleted = harfanglab_closure(None, 1)
    assert deleted.label == "alerte supprimée de la console" and "constaté le" in deleted.text()


def test_harfanglab_ids_from_console_link_then_raw():
    rows = [
        {"reference": "https://edr.local/security-event/AAA/summary", "source": ""},
        {"reference": "", "source": "BBB"},
        {"reference": "https://edr.local/security-event/AAA/summary", "source": "AAA"},
    ]
    assert harfanglab_ids(rows) == ["AAA", "BBB"]
    assert harfanglab_ids([{"reference": "", "source": ""}]) == []  # non identifiable : pas de conclusion


def test_ninjaone_alerts_closed_only_when_all_reset():
    from minisoc.connectors.ninjaone import alert_key

    records = [{"type": "alert", "alert": {"uid": "u1"}}, {"type": "alert", "alert": {"uid": "u2"}}]
    assert ninjaone_closure(records, {"u2", "x"}, None) is None
    closure = ninjaone_closure(records, {"x"}, None)
    assert closure.tool == "NinjaOne" and closure.sources == 2 and closure.observed
    assert ninjaone_closure(records, None, None) is None  # liste des actives trop ancienne
    assert alert_key({"uid": "u1"}) == "u1" and len(alert_key({"deviceId": 3, "message": "m"})) == 32


def test_ninjaone_posture_resolution():
    assert posture_resolved("antivirus_inactive", {"antivirus": "ok"})
    assert not posture_resolved("antivirus_inactive", {"antivirus": "inactive"})
    assert not posture_resolved("antivirus_inactive", {"antivirus": "unknown"})
    assert not posture_resolved("antivirus_outdated", {"antivirus": "outdated"})
    assert posture_resolved("active_threat", {"threats": 0})
    assert not posture_resolved("critical_vulnerabilities", {"critical": 2})
    assert not posture_resolved("patches_failed", None)  # poste absent du relevé
    records = [{"type": "posture", "kind": "active_threat", "device_id": 7}]
    assert ninjaone_closure(records, None, {"7": {"threats": 1}}) is None
    closure = ninjaone_closure(records, None, {"7": {"threats": 0}})
    assert closure.label == "plus aucune menace active"
    mixed = records + [{"type": "alert", "alert": {"uid": "u"}}]
    assert ninjaone_closure(mixed, set(), {"7": {"threats": 0}}) is None


class _Session:
    def __init__(self, alert):
        self.alert, self.added, self.committed, self.rolled_back = alert, [], False, False

    async def get(self, model, key, **kw):
        return self.alert

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        pass

    async def execute(self, *a, **kw):
        class R:
            def scalar(self):
                return None

            def scalar_one_or_none(self):
                return None

        return R()

    async def scalar(self, *a, **kw):
        return None

    async def commit(self):
        self.committed = True

    async def rollback(self):
        self.rolled_back = True


async def test_close_keeps_trace_and_skips_moved_alerts(monkeypatch):
    from minisoc import source_sync

    recorded = []

    async def record(session, **kw):
        recorded.append(kw)

    monkeypatch.setattr(source_sync.audit, "record", record)
    alert = Alert(id=5, status="in_progress", last_seen=NOW, details={"sample": {}}, notify_pending=True)
    closure = harfanglab_closure({"status": "closed", "status_history": []}, 1)
    session = _Session(alert)
    assert await close(session, 5, NOW, closure)
    assert alert.status == "resolved" and not alert.notify_pending
    assert alert.details["source_closure"]["tool"] == "HarfangLab" and "sample" in alert.details
    history = [h for h in session.added if isinstance(h, AlertHistory)]
    assert [h.action for h in history] == ["status", "comment"] and history[0].actor == "HarfangLab (synchro)"
    assert recorded[0]["action"] == "alert_source_closed" and recorded[0]["detail"]["previous_status"] == "in_progress"
    # Nouvelle détection arrivée entre-temps (last_seen a changé) : l'alerte reste ouverte
    moved = Alert(id=6, status="new", last_seen=NOW, details={})
    assert not await close(_Session(moved), 6, datetime(2026, 1, 1, tzinfo=timezone.utc), closure)
    assert moved.status == "new"


def test_compact_json_stays_valid_and_keeps_essentials():
    alert = {
        "id": "44a_yaABzh4rCUJ4Aw2o",
        "rule_name": "Suspicious PowerShell script",
        "rule_content": "description: x\n" * 300,
        "process": {"sigma_rule_content": "y" * 9000, "stacktrace": "z" * 9000, "commandline": "powershell -c 1"},
        "details_powershell": {"PowershellCommand": "Write-Host 1;" * 3000},
    }
    raw = compact_json(alert, drop=BULKY)
    data = json.loads(raw)
    assert len(raw) <= 16000
    assert data["id"] == "44a_yaABzh4rCUJ4Aw2o" and data["process"]["commandline"] == "powershell -c 1"
    assert "sigma_rule_content" not in data["process"]
    assert data["details_powershell"]["PowershellCommand"].endswith("…[tronqué]")
    small = {"id": "1", "msg": "ok"}
    assert json.loads(compact_json(small, drop=BULKY)) == small
    event = parse_harfanglab({**alert, "status": "new", "agent": {"hostname": "PTB-00100"}}, NOW)
    assert json.loads(event.raw)["id"] == "44a_yaABzh4rCUJ4Aw2o"


def test_tool_state_reads_harfanglab_status():
    from minisoc.source_sync import status_change, tool_state

    state = tool_state(["a", "b"], {"a": "new", "b": "investigating", "c": "new"}, total=3)
    assert state["status"] == "investigating" and state["label"] == "en investigation"
    assert state["open"] == 2 and state["total"] == 3
    assert tool_state(["a"], {"a": "new"}, 1)["label"] == "nouvelle"
    detail = {"status_history": [{"to_status": "investigating", "username": "informatique",
                                  "timestamp": "2026-10-03T09:49:19Z"}]}
    assert status_change(detail, "investigating") == {"by": "informatique", "at": "2026-10-03T09:49:19Z"}
    assert status_change(None, "investigating") == {}
