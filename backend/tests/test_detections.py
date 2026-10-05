"""Fiches des détections d'outils (recalibrage), regroupement par détection et priorité des alertes."""

from datetime import datetime, timedelta, timezone

from minisoc.detections import (
    alert_detections,
    apply_to_alert,
    load_suggestions,
    priority,
    recalibrate,
    spread,
    topics,
)
from minisoc.models import Alert, AlertHistory, DetectionProfile

NOW = datetime(2026, 10, 3, 18, 0, tzinfo=timezone.utc)
DRIVER = "Recommended driver block list"


def native(alert_id, host, rule=DRIVER, count=1, severity=4, last_seen=NOW, details=None):
    return Alert(
        id=alert_id, entity_key=f"event.module=harfanglab | host.name={host} | rule.name={rule}", count=count,
        severity=severity, modules=["harfanglab"], first_seen=last_seen - timedelta(hours=1), last_seen=last_seen,
        details=details or {}, status="new", notify_pending=True,
    )


class Session:
    def __init__(self):
        self.added = []

    def add(self, obj):
        self.added.append(obj)


def test_recalibrate_keeps_tool_severity():
    assert recalibrate(None, 4) == (4, {})
    profile = DetectionProfile(module="harfanglab", detection=DRIVER, category="hygiene", severity=2)
    assert recalibrate(profile, 4) == (2, {"category": "hygiene", "tool_severity": 4})
    category_only = DetectionProfile(module="harfanglab", detection=DRIVER, category="hygiene", severity=None)
    assert recalibrate(category_only, 3) == (3, {"category": "hygiene", "tool_severity": 3})


def test_apply_to_alert_traces_and_can_be_undone():
    alert = native(1, "PC-1")
    session = Session()
    profile = DetectionProfile(module="harfanglab", detection=DRIVER, category="hygiene", severity=2)
    assert apply_to_alert(session, alert, profile, "m.durand")
    assert alert.severity == 2 and alert.details == {"category": "hygiene", "tool_severity": 4}
    assert not alert.notify_pending  # déclassée : plus de notification en attente
    history = [h for h in session.added if isinstance(h, AlertHistory)]
    assert "hygiène du parc" in history[0].detail and "critique → moyenne" in history[0].detail
    assert not apply_to_alert(session, alert, profile, "m.durand")  # déjà appliquée : rien ne change
    assert apply_to_alert(session, alert, None, "m.durand")  # retrait de la fiche : sévérité de l'outil
    assert alert.severity == 4 and "category" not in alert.details


def test_alert_detections_and_topics_with_storm_alert():
    storm = Alert(
        id=3, entity_key="*regroupement*", count=7, severity=4, modules=["harfanglab"], first_seen=NOW,
        last_seen=NOW, status="new",
        details={"storm": True, "entities": {
            f"event.module=harfanglab | host.name=PC-1 | rule.name={DRIVER}": 5,
            f"event.module=harfanglab | host.name=PC-10 | rule.name={DRIVER}": 1,
            "event.module=harfanglab | host.name=SRV-WEB | rule.name=React RCE": 1,
        }},
    )
    assert ("harfanglab", DRIVER, "PC-10", 1) in alert_detections(storm)
    grouped = topics([native(1, "PC-1", count=2), native(2, "PC-2"), storm])
    driver = grouped[("harfanglab", DRIVER.lower())]
    assert driver.alerts == {1, 2, 3} and driver.hosts == {"PC-1": 7, "PC-2": 1, "PC-10": 1}
    assert driver.occurrences == 9
    assert grouped[("harfanglab", "react rce")].hosts == {"SRV-WEB": 1}
    assert spread([native(1, "PC-1"), native(2, "PC-2")]) == {("harfanglab", DRIVER.lower()): 2}


def test_priority_is_explained():
    rare_server = native(1, "SRV-AUDIT", rule="Suspicious PowerShell script", severity=4)
    score, reasons = priority(rare_server, {("harfanglab", "suspicious powershell script"): 1}, ["SRV-AUDIT"],
                              now=NOW)
    labels = [r["label"] for r in reasons]
    assert score == 100  # 70 + serveur 15 + rare 10 + récente 10, plafonné
    assert labels[0] == "sévérité critique" and "serveur touché (SRV-AUDIT)" in labels

    widespread = native(2, "PC-2", severity=4, details={"category": "hygiene"},
                        last_seen=NOW - timedelta(days=10))
    score, reasons = priority(widespread, {("harfanglab", DRIVER.lower()): 44}, ["PC-2"], now=NOW)
    assert score == 70 - 30 - 15 - 10
    assert any("44 machines" in r["label"] for r in reasons)


def test_suggestions_file_is_valid():
    suggestions = load_suggestions()
    driver = suggestions[("harfanglab", DRIVER.lower())]
    assert driver["category"] == "hygiene" and driver["severity"] == 2 and driver["why"]
    assert all(s["category"] in ("threat", "hygiene", "info") for s in suggestions.values())


async def test_mark_seen_never_goes_back():
    from minisoc import bus

    class Redis:
        def __init__(self):
            self.h = {}

        async def hmget(self, key, names):
            return [self.h.get(n) for n in names]

        async def hset(self, key, mapping):
            self.h.update(mapping)

    redis = Redis()
    await bus.mark_seen(redis, {"harfanglab": NOW})
    await bus.mark_seen(redis, {"harfanglab": NOW - timedelta(days=30), "sophos_xgs": NOW})  # import d'historique
    assert redis.h == {"harfanglab": NOW.isoformat(), "sophos_xgs": NOW.isoformat()}
    await bus.mark_seen(redis, {"harfanglab": NOW + timedelta(minutes=1)})
    assert redis.h["harfanglab"] == (NOW + timedelta(minutes=1)).isoformat()
