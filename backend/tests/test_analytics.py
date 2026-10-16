"""Page Statistiques : volumes, qualité des détections, délais, MITRE et cibles (calculs purs)."""

from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from minisoc import analytics
from minisoc.models import Alert, AlertHistory, Incident, IncidentEntry

TZ = ZoneInfo("Europe/Paris")
SINCE = datetime(2026, 10, 1, tzinfo=TZ)  # minuit heure de Paris, comme les bornes envoyées par la page
UNTIL = datetime(2026, 10, 8, tzinfo=TZ)
NOW = UNTIL


def alert(alert_id, rule_id="UC-01", severity=2, created=SINCE + timedelta(hours=10), status="new", modules=("windows",),
          entity="host.name=PC-1", count=1, details=None, acknowledged=None):
    return Alert(id=alert_id, rule_id=rule_id, rule_name=f"Règle {rule_id}", severity=severity, title=f"Alerte {alert_id}",
                 entity_key=entity, status=status, modules=list(modules), count=count, details=details or {},
                 created_at=created, first_seen=created, last_seen=created, acknowledged_at=acknowledged)


def closed(alert_id, actor, status="resolved", at=SINCE + timedelta(hours=12)):
    return AlertHistory(alert_id=alert_id, actor=actor, action="status", detail=status, ts=at)


def test_buckets_switch_to_weeks_beyond_92_days():
    assert analytics.granularity(SINCE, UNTIL) == "day"
    assert analytics.buckets(SINCE, UNTIL, "day", TZ)[0] == "2026-10-01"
    assert len(analytics.buckets(SINCE, UNTIL, "day", TZ)) == 7  # 1er au 7 octobre (fin exclue)
    assert len(analytics.buckets(SINCE.astimezone(timezone.utc), UNTIL.astimezone(timezone.utc), "day", TZ)) == 7
    long_since = UNTIL - timedelta(days=120)
    assert analytics.granularity(long_since, UNTIL) == "week"
    weeks = analytics.buckets(long_since, UNTIL, "week", TZ)
    assert all(datetime.fromisoformat(w).weekday() == 0 for w in weeks)  # lundis


def test_volumes_count_each_tool_and_compare_with_previous_period():
    alerts = [
        alert(1, severity=4, modules=("sophos_xgs", "m365"), count=5),
        alert(2, severity=2, created=SINCE + timedelta(days=2)),
        alert(3, severity=2, rule_id="UC-02", modules=(), details={"category": "hygiene"}),
    ]
    v = analytics.volumes(alerts, previous_total=2, since=SINCE, until=UNTIL, tz=TZ)
    assert v["total"] == 3 and v["occurrences"] == 7 and v["delta_pct"] == 50
    assert v["by_severity"]["critical"] == 1 and v["by_severity"]["medium"] == 2
    tools = {t["module"]: t["total"] for t in v["by_tool"]}
    assert tools == {"sophos_xgs": 1, "m365": 1, "windows": 1, analytics.NO_TOOL: 1}  # somme 4 > total 3 : expliqué
    assert any("peut donc dépasser le total" in line for line in v["method"])
    assert v["timeline"][0]["critical"] == 1 and v["timeline"][2]["medium"] == 1
    assert {c["category"]: c["count"] for c in v["by_category"]} == {"threat": 2, "hygiene": 1}
    assert v["by_rule"][0] == {"rule_id": "UC-01", "rule_name": "Règle UC-01", "total": 2, "occurrences": 6,
                               "severity": "critical", "tools": ["m365", "sophos_xgs", "windows"]}


def test_quality_false_positive_rate_and_closer():
    alerts = [alert(i, status="false_positive") for i in range(1, 5)]
    alerts += [alert(5, status="resolved"), alert(6, status="new"), alert(7, rule_id="UC-09", status="resolved")]
    history = [closed(i, "j.martin", "false_positive") for i in range(1, 5)]
    history += [closed(5, "Bitdefender (synchro)"), closed(7, "système")]
    q = analytics.quality(alerts, analytics.closing_entries(alerts, history))
    assert q["closed"] == 6 and q["false_positive"] == 4 and q["fp_rate"] == 67
    assert q["closed_by"] == {"human": 4, "system": 1, "source": 1}
    uc01 = next(r for r in q["by_rule"] if r["rule_id"] == "UC-01")
    assert uc01["fp_rate"] == 80 and uc01["noisy"] and uc01["open"] == 1
    assert [r["rule_id"] for r in q["noisy_rules"]] == ["UC-01"]


def test_closing_entry_is_the_last_one_matching_current_status():
    a = alert(1, status="resolved")
    history = [closed(1, "système", "resolved", SINCE + timedelta(hours=11)),
               AlertHistory(alert_id=1, actor="j.martin", action="status", detail="new", ts=SINCE + timedelta(hours=12)),
               closed(1, "j.martin", "resolved", SINCE + timedelta(hours=14))]
    found = analytics.closing_entries([a], history)
    assert found[1].actor == "j.martin"


def test_delays_separate_human_and_automatic_closures():
    created = SINCE + timedelta(hours=10)
    alerts = [
        alert(1, severity=3, status="resolved", acknowledged=created + timedelta(minutes=30)),
        alert(2, severity=3, status="resolved", acknowledged=created + timedelta(minutes=90)),
        alert(3, severity=2, status="resolved"),  # clôture automatique, jamais prise en charge
        alert(4, status="new"),
    ]
    history = [closed(1, "j.martin", at=created + timedelta(hours=2)),
               closed(2, "j.martin", at=created + timedelta(hours=4)),
               closed(3, "système", at=created + timedelta(minutes=5))]
    open_now = [(2, NOW - timedelta(hours=2)), (3, NOW - timedelta(days=3)), (4, NOW - timedelta(days=45))]
    d = analytics.delays(alerts, analytics.closing_entries(alerts, history), open_now, [], [], SINCE, UNTIL, TZ, NOW)
    assert d["acknowledge"]["all"] == {"count": 2, "median": 60, "p90": 90}
    assert d["close_human"]["high"]["count"] == 2 and d["close_human"]["all"]["median"] == 180
    assert d["close_system"] == {"count": 1, "median": 5, "p90": 5}
    assert d["never_acknowledged_open"] == 1
    assert [b["total"] for b in d["backlog"]] == [1, 1, 0, 1] and d["backlog_total"] == 3
    assert d["backlog"][3]["critical"] == 1


def test_incident_delays():
    inc = Incident(id=1, title="Compte compromis", category="compromission_compte", status="closed",
                   created_at=SINCE + timedelta(hours=1), closed_at=SINCE + timedelta(hours=25), created_by="j.martin")
    entries = [IncidentEntry(incident_id=1, kind="status", detail="En investigation", ts=SINCE + timedelta(hours=2)),
               IncidentEntry(incident_id=1, kind="status", detail="Maîtrisé", ts=SINCE + timedelta(hours=4))]
    d = analytics.delays([], {}, [], [inc], entries, SINCE, UNTIL, TZ, NOW)
    i = d["incidents"]
    assert i["opened"] == 1 and i["closed"] == 1 and i["still_open"] == 0
    assert i["time_to_contain"]["median"] == 180 and i["time_to_close"]["median"] == 1440


def test_mitre_counts_ambiguous_techniques_in_each_tactic_but_not_as_certain():
    rule_mitre = {"UC-03": ["T1110", "T1078.002"], "UC-20": ["T1059"]}
    alerts = [
        alert(1, rule_id="UC-03", entity="user.name=MAIRIE\\j.dupont"),
        alert(2, rule_id="UC-20", entity="host.name=PC-1"),
        alert(3, rule_id="UC-20", entity="host.name=pc-1.mairie.local", status="false_positive"),
        alert(4, rule_id="UC-44", entity="host.name=PC-1"),  # chaîne d'attaque : calculée, écartée
    ]
    m = analytics.mitre_targets(alerts, rule_mitre)
    assert m["considered"] == 2 and m["excluded"] == 2
    tactics = {t["id"]: t for t in m["tactics"]}
    assert tactics["TA0006"]["alerts"] == 1 and tactics["TA0006"]["exclusive"] == 0  # T1110 + T1078 : ambiguë
    assert tactics["TA0001"]["alerts"] == 1  # possible via T1078.002, comptée mais pas « certaine »
    assert tactics["TA0002"] == {"id": "TA0002", "name": "Exécution", "alerts": 1, "exclusive": 1, "rules": 1,
                                 "entities": 1}
    assert {t["id"] for t in m["techniques"]} == {"T1110", "T1078.002", "T1059"}
    assert [h["alerts"] for h in m["hosts"]] == [1]
    assert m["accounts"][0]["name"] == "MAIRIE\\j.dupont"


def test_mitre_ranks_public_ips_only():
    alerts = [alert(1, entity="source.ip=185.220.101.4", modules=("sophos_xgs",)),
              alert(2, entity="source.ip=185.220.101.4", modules=("m365",)),
              alert(3, entity="source.ip=192.168.2.10")]
    m = analytics.mitre_targets(alerts, {})
    assert [(i["ip"], i["alerts"], i["tools"]) for i in m["ips"]] == [("185.220.101.4", 2, ["m365", "sophos_xgs"])]
    assert m["unmapped"] == 3
