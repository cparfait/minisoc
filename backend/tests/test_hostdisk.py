"""Espace des disques de la VM : relevé, seuil, ancienneté, alerte UC-63 et clôture automatique."""

import json
from datetime import datetime, timedelta, timezone

import pytest
from conftest import RULES_DIR

from minisoc import hostdisk
from minisoc.models import Alert, AlertHistory
from minisoc.rules import load_rules
from minisoc.rules.engine import RuleSet

NOW = datetime(2026, 10, 18, 22, 0, tzinfo=timezone.utc)
GIB = 1024**3


def fs(mount, percent, inodes=1, device="/dev/sda2"):
    return {"mount": mount, "device": device, "fstype": "ext4", "size": 28 * GIB, "used": percent * 28 * GIB // 100,
            "avail": (100 - percent) * 28 * GIB // 100, "percent": percent, "inodes_percent": inodes}


def report(*filesystems, at=NOW - timedelta(minutes=3)):
    return {"at": at.isoformat(), "host": "minisoc", "filesystems": list(filesystems)}


def test_assess_marks_partitions_over_threshold():
    status = hostdisk.assess(report(fs("/", 86), fs("/var/log", 40), fs("/var/lib/docker", 10, inodes=91)), NOW, 85)
    assert status["state"] == "alert" and status["age_minutes"] == 3 and status["host"] == "minisoc"
    assert [f["over"] for f in status["filesystems"]] == [True, True, False]  # triées : /, /var/lib/docker, /var/log
    found = {f["mount"]: f for f in hostdisk.findings(status)}
    assert set(found) == {"/", "/var/lib/docker"}
    assert found["/"]["severity"] == 2 and found["/"]["what"] == "plein"
    assert found["/var/lib/docker"]["what"] == "sans inodes libres" and found["/var/lib/docker"]["metric"] == 91


def test_high_severity_from_95_percent():
    status = hostdisk.assess(report(fs("/", 95)), NOW, 85)
    assert hostdisk.findings(status)[0]["severity"] == 3


def test_ok_absent_error_and_bad_entries():
    assert hostdisk.assess(report(fs("/", 84)), NOW, 85)["state"] == "ok"
    assert hostdisk.findings(hostdisk.assess(report(fs("/", 84)), NOW, 85)) == []
    assert hostdisk.assess(None, NOW, 85)["state"] == "absent"  # poste de développement : rien à signaler
    assert hostdisk.findings(hostdisk.assess(None, NOW, 85)) == []
    assert hostdisk.assess(None, NOW, 85, error="illisible")["state"] == "error"
    assert hostdisk.assess({"at": "hier"}, NOW, 85)["state"] == "error"
    status = hostdisk.assess(report({"mount": "relatif", "percent": 99}, "x", fs("/", 120)), NOW, 85)
    assert [f["mount"] for f in status["filesystems"]] == ["/"] and status["filesystems"][0]["percent"] == 100


def test_stale_report_raises_its_own_alert_only():
    status = hostdisk.assess(report(fs("/", 99), at=NOW - timedelta(hours=2)), NOW, 85)
    assert status["state"] == "stale"
    found = hostdisk.findings(status)
    assert len(found) == 1 and found[0]["mount"] == hostdisk.REPORT_ENTITY and found[0]["stale"]
    assert "2 h" in found[0]["title"]


def test_resolution_with_margin():
    status = hostdisk.assess(report(fs("/", 83), fs("/var/log", 81)), NOW, 85)
    assert hostdisk.resolution("/", status) == ""  # 83 % : sous le seuil mais pas assez (clôture sous 82 %)
    assert "81 %" in hostdisk.resolution("/var/log", status)
    assert "plus monté" in hostdisk.resolution("/boot", status)
    assert hostdisk.resolution(hostdisk.REPORT_ENTITY, status)
    stale = hostdisk.assess(report(fs("/var/log", 10), at=NOW - timedelta(hours=3)), NOW, 85)
    assert hostdisk.resolution("/var/log", stale) == ""  # relevé arrêté : on ne sait pas, l'alerte reste
    assert hostdisk.resolution(hostdisk.REPORT_ENTITY, stale) == ""


def test_read_report(tmp_path):
    assert hostdisk.read_report(tmp_path / "absent.json") is None
    (tmp_path / "ok.json").write_text(json.dumps(report(fs("/", 50))), encoding="utf-8")
    assert hostdisk.read_report(tmp_path / "ok.json")["host"] == "minisoc"
    (tmp_path / "bad.json").write_text("{", encoding="utf-8")
    with pytest.raises(hostdisk.HostDiskError):
        hostdisk.read_report(tmp_path / "bad.json")


def test_rule_is_shipped():
    rule = RuleSet(load_rules(RULES_DIR, strict=True)).by_id[hostdisk.DISK_RULE]
    assert rule.group_by == ["file.path"] and rule.severity_level == 2 and rule.playbook


# --- Tâche du worker -------------------------------------------------------------------------


class FakeRedis:
    def __init__(self):
        self.kv, self.hashes = {}, {}

    async def get(self, key):
        return self.kv.get(key)

    async def set(self, key, value, ex=None):
        self.kv[key] = value

    async def hgetall(self, key):
        return dict(self.hashes.get(key, {}))

    async def hset(self, key, field, value):
        self.hashes.setdefault(key, {})[field] = value

    async def hdel(self, key, *fields):
        for f in fields:
            self.hashes.get(key, {}).pop(f, None)


class FakeScalars:
    def __init__(self, items):
        self.items = items

    def all(self):
        return self.items


class FakeSession:
    def __init__(self, db):
        self.db = db

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def scalars(self, stmt):
        return FakeScalars([a for a in self.db["alerts"] if a.status in ("new", "in_progress", "on_hold")])

    def add(self, obj):
        self.db["history"].append(obj)

    async def commit(self):
        pass


@pytest.fixture
def job(tmp_path, monkeypatch):
    db = {"alerts": [], "history": [], "cfg": {"disk_alert_percent": 85}}

    async def load(_session):
        return db["cfg"]

    monkeypatch.setattr(hostdisk.settings_store, "load", load)
    rules = RuleSet(load_rules(RULES_DIR))
    raised = []

    async def raise_alert(det):
        raised.append(det)
        alert = next((a for a in db["alerts"] if a.entity_key == det.entity_key and a.status == "new"), None)
        if alert is None:
            alert = Alert(id=len(db["alerts"]) + 1, rule_id=det.rule.id, entity_key=det.entity_key, status="new",
                          severity=det.severity, title=det.title, last_seen=det.last_seen)
            db["alerts"].append(alert)
        return alert, "created"

    j = hostdisk.HostDiskJob(lambda: FakeSession(db), FakeRedis(), str(tmp_path), lambda: rules, raise_alert)
    j.db, j.raised = db, raised
    return j


def write(job, data):
    (job.directory / hostdisk.REPORT_FILE).write_text(json.dumps(data), encoding="utf-8")


async def test_job_raises_then_resolves(job):
    write(job, report(fs("/", 90), fs("/var/log", 30)))
    status = await job.tick(NOW)
    assert status["state"] == "alert"
    assert json.loads(job.redis.kv[hostdisk.STATUS_KEY])["filesystems"][0]["over"] is True
    [det] = job.raised
    assert det.entity_key == "file.path=/" and det.metric == 90 and det.severity == 2
    assert det.title == "Disque de la VM presque plein : / (90 %)"
    assert "host.name" not in det.details["sample"]  # pas de poids dans le score de risque d'une machine
    first = det.first_seen

    write(job, report(fs("/", 96), at=NOW + timedelta(minutes=2)))  # aggravation : même début de dépassement
    await job.tick(NOW + timedelta(minutes=5))
    assert job.raised[-1].severity == 3 and job.raised[-1].first_seen == first

    write(job, report(fs("/", 83), at=NOW + timedelta(minutes=8)))  # sous le seuil, pas sous la marge
    await job.tick(NOW + timedelta(minutes=10))
    assert job.db["alerts"][0].status == "new" and len(job.raised) == 2

    write(job, report(fs("/", 70), at=NOW + timedelta(minutes=13)))
    await job.tick(NOW + timedelta(minutes=15))
    assert job.db["alerts"][0].status == "resolved"
    comments = [h.detail for h in job.db["history"] if isinstance(h, AlertHistory) and h.action == "comment"]
    assert comments and "70 %" in comments[0] and "clôture automatique" in comments[0]
    assert "/" not in job.redis.hashes.get(hostdisk.SINCE_KEY, {})


async def test_job_stale_report_and_return(job):
    write(job, report(fs("/", 50), at=NOW - timedelta(hours=3)))
    await job.tick(NOW)
    [det] = job.raised
    assert det.entity_key == f"file.path={hostdisk.REPORT_ENTITY}"
    write(job, report(fs("/", 50), at=NOW))
    await job.tick(NOW + timedelta(minutes=1))
    assert job.db["alerts"][0].status == "resolved"


async def test_job_without_report_or_with_custom_threshold(job):
    assert (await job.tick(NOW))["state"] == "absent" and job.raised == []
    job.db["cfg"]["disk_alert_percent"] = 95
    write(job, report(fs("/", 90)))
    assert (await job.tick(NOW))["state"] == "ok" and job.raised == []
