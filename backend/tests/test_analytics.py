"""Page Statistiques : volumes, qualité des détections, délais, MITRE et cibles, santé des sources, carte jour × heure,
corrélation et réponse (calculs purs)."""

from datetime import date, datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from minisoc import analytics
from minisoc.models import Alert, AlertHistory, Block, Incident, IncidentEntry

TZ = ZoneInfo("Europe/Paris")
SINCE = datetime(2026, 10, 1, tzinfo=TZ)  # minuit heure de Paris, comme les bornes envoyées par la page
UNTIL = datetime(2026, 10, 8, tzinfo=TZ)
NOW = UNTIL


def alert(alert_id, rule_id="UC-01", severity=2, created=SINCE + timedelta(hours=10), status="new",
          modules=("windows",), entity="host.name=PC-1", count=1, details=None, acknowledged=None):
    return Alert(id=alert_id, rule_id=rule_id, rule_name=f"Règle {rule_id}", severity=severity,
                 title=f"Alerte {alert_id}", entity_key=entity, status=status, modules=list(modules), count=count,
                 details=details or {},
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
               AlertHistory(alert_id=1, actor="j.martin", action="status", detail="new",
                            ts=SINCE + timedelta(hours=12)),
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


def utc(value):
    """Date telle que la renvoie ClickHouse : UTC, sans fuseau."""
    return value.astimezone(timezone.utc).replace(tzinfo=None)


def test_source_health_silences_and_availability():
    expected = {m: timedelta(minutes=30) for m in ("sophos_xgs", "windows", "bitdefender")}
    volume = [{"module": "sophos_xgs", "b": date(2026, 10, 1), "n": 100},
              {"module": "dns", "b": date(2026, 10, 2), "n": 5}]
    seen = [{"module": "sophos_xgs", "first": utc(SINCE + timedelta(minutes=10)),
             "last": utc(UNTIL - timedelta(minutes=10))},
            {"module": "windows", "first": utc(SINCE + timedelta(hours=3)), "last": utc(UNTIL - timedelta(hours=1))},
            {"module": "dns", "first": utc(SINCE + timedelta(days=1)), "last": utc(SINCE + timedelta(days=1))}]
    # Silences de 175, 35 et 25 minutes (tranche de 5 minutes comprise)
    gaps = [{"module": "sophos_xgs", "gap_start": utc(SINCE + timedelta(hours=a)),
             "gap_end": utc(SINCE + timedelta(hours=b))} for a, b in ((2, 5), (6, 6 + 40 / 60), (7, 7.5))]
    h = analytics.source_health(volume, [{"module": "sophos_xgs", "n": 50}], gaps, seen, expected, SINCE, UNTIL, NOW,
                                TZ, 365, silence_alerts=2)
    rows = {r["module"]: r for r in h["sources"]}
    assert rows["sophos_xgs"]["series"][0] == 100 and rows["sophos_xgs"]["delta_pct"] == 100
    assert rows["sophos_xgs"]["silences"] == 2 and rows["sophos_xgs"]["silent_minutes"] == 210  # 25 min < délai
    assert rows["sophos_xgs"]["availability"] == 97.9 and rows["sophos_xgs"]["longest"][0]["minutes"] == 175
    assert rows["windows"]["silent_minutes"] == 240  # 3 h avant le premier événement, 1 h après le dernier
    assert rows["bitdefender"]["silences"] == 1 and rows["bitdefender"]["availability"] == 0.0  # jamais reçue
    assert not rows["dns"]["monitored"] and "silences" not in rows["dns"]
    assert any("source silencieuse" in line and ": 2." in line for line in h["method"])


def test_source_health_ignores_purged_events():
    h = analytics.source_health([], [], [], [], {"bitdefender": timedelta(minutes=30)}, SINCE, UNTIL, NOW, TZ, 3, 0)
    assert h["sources"][0]["silent_minutes"] == 3 * 24 * 60  # 3 jours conservés, pas 7


def test_heatmap_counts_off_hours():
    alerts = [alert(1, created=datetime(2026, 10, 5, 10, tzinfo=TZ)),  # lundi 10 h
              alert(2, created=datetime(2026, 10, 3, 3, tzinfo=TZ))]  # samedi 3 h
    auth = [{"d": 1, "h": 9, "failures": 4, "successes": 10}, {"d": 7, "h": 23, "failures": 6, "successes": 1}]
    m = analytics.heatmap(alerts, auth, [], {1, 2, 3, 4, 5}, 8, 18, TZ)
    assert m["grids"]["alerts"][0][10] == 1 and m["grids"]["alerts"][5][3] == 1
    assert m["summary"]["alerts"]["off_hours_pct"] == 50
    assert m["summary"]["failures"] == {"total": 10, "off_hours": 6, "off_hours_pct": 60,
                                        "peak": {"day": "dimanche", "hour": 23, "count": 6}}
    assert m["summary"]["successes"]["off_hours"] == 1
    assert any("lundi, mardi, mercredi, jeudi, vendredi, de 8 h à 18 h" in line for line in m["method"])


def test_correlation_and_response():
    at = SINCE + timedelta(days=1)
    alerts = [
        alert(1, modules=("harfanglab",), entity="host.name=PC-1"),
        alert(2, modules=("bitdefender",), entity="host.name=pc-1.mairie.local"),
        alert(3, modules=("harfanglab",), entity="host.name=PC-2", status="false_positive"),
        alert(4, modules=("bitdefender",), entity="host.name=PC-2"),
        alert(5, modules=("sophos_xgs", "m365"), entity="source.ip=185.220.101.4"),
        alert(6, rule_id="UC-44", status="resolved", created=at, details={"chain": {"tactics": ["TA0001", "TA0002",
              "TA0006"], "steps": [{}, {}, {}, {}]}}),
        alert(7, rule_id="UC-61", created=at + timedelta(hours=1), modules=("sophos_xgs", "m365"),
              details={"shared_ip": {"tools": ["m365", "sophos_xgs"]}}),
    ]
    incidents = [Incident(id=1, created_by="système", created_at=at),
                 Incident(id=2, created_by="j.martin", created_at=at),
                 Incident(id=3, created_by="système", created_at=SINCE - timedelta(days=1))]
    blocks = [Block(ip="185.220.101.4", status="active", alert_id=5, created_at=at),
              Block(ip="185.220.101.4", status="removed", removed_by="expiration", created_at=at),
              Block(ip="45.155.205.33", status="removed", removed_by="j.martin", created_at=at),
              Block(ip="45.155.205.34", status="failed", created_at=at),
              Block(ip="45.155.205.35", status="active", created_at=SINCE - timedelta(days=2))]
    isolations = [{"action": "endpoint_isolate", "ok": True, "host": "PC-1"},
                  {"action": "endpoint_isolate", "ok": False, "host": "PC-2"},
                  {"action": "endpoint_release", "ok": True, "host": "PC-1"}]
    c = analytics.correlation(alerts, incidents, blocks, isolations, SINCE, UNTIL)
    assert c["multi_tool_alerts"] == 1  # l'alerte 5 ; l'UC-61, calculée, est à part
    assert c["corroborated_hosts"] == [{"host": "pc-1", "tools": ["bitdefender", "harfanglab"], "alerts": 2}]
    derived = {d["rule_id"]: d for d in c["derived"]}
    assert derived["UC-44"]["resolved"] == 1 and derived["UC-61"]["open"] == 1 and derived["UC-43"]["total"] == 0
    assert [(r["id"], r["why"]) for r in c["recent"]] == [(7, "Microsoft 365, pare-feu Sophos"),
                                                         (6, "3 tactiques, 4 étapes")]
    assert c["incidents"] == {"opened": 2, "automatic": 1}
    assert c["blocks"] == {"total": 4, "ips": 3, "active": 1, "failed": 1, "removed_manual": 1, "expired": 1,
                           "from_alert": 1}
    assert c["isolations"] == {"requested": 2, "failed": 1, "released": 1, "hosts": ["PC-1", "PC-2"]}
