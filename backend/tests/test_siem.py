"""Briques SIEM : langage de recherche, import Sigma, rejeu, IOC, archives scellées, export, inventaire."""

import gzip
import json
from datetime import date, datetime, timedelta, timezone

import pytest

from minisoc.ecs import Event
from minisoc.rules.filters import matches

NOW = datetime(2026, 10, 3, 18, 0, tzinfo=timezone.utc)


# ---------- Recherche ----------


def test_search_conditions_are_parameterized():
    from minisoc.search import build_sql, compile_query

    c = compile_query('user.name=j.dupont outcome=failure (message~"mot de passe" OR source.ip=10.0.0.0/8)')
    assert "j.dupont" not in c.where and "mot de passe" not in c.where  # valeurs en paramètres liés
    assert set(c.params.values()) >= {"j.dupont", "failure", "mot de passe", "10.0.0.0/8"}
    assert " OR " in c.where and "isIPAddressInRange" in c.where
    sql, cols = build_sql(c, timedelta(hours=24))
    assert sql.startswith("SELECT ts,") and "ORDER BY ts DESC" in sql and cols == []


def test_search_french_keywords_alias_and_wildcard():
    from minisoc.search import compile_query

    c = compile_query("host=PC-* ET NON module=harfanglab OU ip=192.0.2.7")
    assert "ILIKE" in c.where and "NOT (" in c.where
    assert "PC-%" in c.params.values()
    assert c.where.count("192.0.2.7") == 0 and list(c.params.values()).count("192.0.2.7") == 3  # 3 colonnes IP


def test_search_stages():
    from minisoc.search import build_sql, compile_query

    sql, cols = build_sql(compile_query("outcome=failure | count by source.ip, user.name"), timedelta(days=1))
    assert "GROUP BY g0, g1" in sql and cols == ["source.ip", "user.name", "count"]
    sql, cols = build_sql(compile_query("| top user.name 5"), timedelta(days=1))
    assert "LIMIT 5" in sql and cols == ["user.name", "count"]
    sql, cols = build_sql(compile_query("| distinct host.name by user.name"), timedelta(days=1))
    assert "uniqExact(host_name)" in sql and cols[-2:] == ["distinct", "sample"]
    sql, cols = build_sql(compile_query("module=windows | timeline by event.action"), timedelta(days=7))
    assert "INTERVAL 6 HOUR" in sql and cols == ["bucket", "event.action", "count"]
    sql, _ = build_sql(compile_query("password | head 20"), timedelta(hours=1))
    assert sql.endswith("LIMIT 20")


@pytest.mark.parametrize(
    "query, message",
    [
        ("champ.inconnu=1", "champ inconnu"),
        ("source.port>abc", "nombre"),
        ("user.name>3", "pas numérique"),
        ("(module=windows", "parenthèse"),
        ("x | count | top user.name", "une seule étape"),
        ("| frobnicate", "étape inconnue"),
        ("ip=1.2.3.0/99", "réseau invalide"),
    ],
)
def test_search_errors_are_explicit(query, message):
    from minisoc.search import SearchError, compile_query

    with pytest.raises(SearchError, match=message):
        compile_query(query)


# ---------- Sigma ----------

SIGMA_OK = """
title: Effacement du journal de sécurité
id: 0a1b2c3d-0000-4000-8000-000000000001
status: stable
level: high
logsource: {product: windows, service: security}
detection:
  selection:
    EventID: 1102
  filter_machine:
    TargetUserName|endswith: '$'
  condition: selection and not filter_machine
tags: [attack.defense_evasion, attack.t1070.001]
falsepositives: [Rotation planifiée des journaux]
"""


def _event(**kw):
    base = dict(ts=NOW, module="windows", kind="event", category="iam", action="log_cleared", severity=3)
    return Event(**{**base, **kw})


def test_sigma_conversion_matches_like_the_engine():
    from minisoc.sigma import convert_text

    [c] = convert_text(SIGMA_OK)
    assert c.ok, c.errors
    rule = c.rule
    assert rule["id"].startswith("SIGMA-") and rule["severity"] == "high" and rule["mitre"] == ["T1070.001"]
    flt = rule["filter"]
    assert matches(flt, _event(rule_name="Windows 1102", user_name="j.dupont"))
    assert not matches(flt, _event(rule_name="Windows 1102", user_name="PC-01$"))  # exclusion respectée
    assert not matches(flt, _event(rule_name="Windows 4624", user_name="j.dupont"))
    assert not matches(flt, _event(module="sophos_xgs", rule_name="Windows 1102"))
    assert "Faux positifs possibles" in rule["description"]


def test_sigma_one_of_and_keywords_case_insensitive():
    from minisoc.sigma import convert_text

    text = """
title: Connexions refusées
logsource: {category: firewall}
detection:
  sel_a: {dst_port: [3389, 445]}
  sel_b: {src_ip|cidr: 203.0.113.0/24}
  keywords: ['*DENY*']
  condition: 1 of sel_* and keywords
"""
    [c] = convert_text(text)
    assert c.ok, c.errors
    flt = c.rule["filter"]
    assert matches(flt, Event(ts=NOW, module="sophos_xgs", destination_port=445, message="Action deny"))
    assert matches(flt, Event(ts=NOW, module="sophos_xgs", source_ip="203.0.113.9", message="deny"))
    assert not matches(flt, Event(ts=NOW, module="sophos_xgs", destination_port=80, message="deny"))
    assert c.rule["group_by"] == ["source.ip"]


@pytest.mark.parametrize(
    "text, reason",
    [
        (
            "title: t\nlogsource: {product: windows, category: process_creation}\n"
            "detection: {sel: {Image|endswith: '\\\\cmd.exe'}, condition: sel}",
            "EDR",
        ),
        (
            "title: t\nlogsource: {product: windows, service: security}\n"
            "detection: {sel: {EventID: 4624, LogonProcessName: Advapi}, condition: sel}",
            "LogonProcessName",
        ),
        (
            "title: t\nlogsource: {product: windows, service: security}\n"
            "detection: {sel: {TargetUserName|re: '^adm'}, condition: sel}",
            "modificateur",
        ),
        (
            "title: t\nlogsource: {product: windows, service: security}\n"
            "detection: {sel: {EventID: 4625}, condition: sel | count() > 5}",
            "agrégation",
        ),
        (
            "title: t\nlogsource: {product: linux, service: auth}\ndetection: {sel: {x: 1}, condition: sel}",
            "non collectée",
        ),
    ],
)
def test_sigma_refuses_what_cannot_be_matched_faithfully(text, reason):
    from minisoc.sigma import convert_text

    [c] = convert_text(text)
    assert not c.ok and reason in " ".join(c.errors)


# ---------- Rejeu et couverture ----------


def test_replay_queries_match_and_threshold():
    from minisoc.replay import ReplayError, replay_queries
    from minisoc.rules.model import Rule

    match = Rule.from_dict(
        {
            "id": "T1",
            "name": "t",
            "type": "match",
            "severity": "high",
            "filter": {"event.action": "log_cleared"},
            "group_by": ["host.name"],
        }
    )
    q = replay_queries(match, 30)
    assert set(q) == {"summary", "entities", "by_day", "sample"}
    sql, params = q["summary"]
    assert "log_cleared" in params.values() and "toStartOfInterval" in sql
    threshold = Rule.from_dict(
        {
            "id": "T2",
            "name": "t",
            "type": "threshold",
            "severity": "high",
            "window": "10m",
            "condition": "count() >= 20",
            "filter": {"event.outcome": "failure"},
            "group_by": ["source.ip"],
        }
    )
    assert "HAVING value >=" in replay_queries(threshold, 7)["summary"][0]
    absence = Rule.from_dict(
        {"id": "T3", "name": "t", "type": "absence", "severity": "medium", "sources": {"windows": "30m"}}
    )
    with pytest.raises(ReplayError):
        replay_queries(absence, 7)


def test_tool_coverage_merges_with_rules():
    from minisoc.replay import merged_coverage, tool_coverage_from_tags

    tools = tool_coverage_from_tags(
        [["attack.discovery", "attack.t1087.002", "attack.t1018"], ["attack.t1110", "attack.credential_access"]]
    )
    assert tools["T1087.002"]["tactics"] == {"TA0007"} and tools["T1110"]["count"] == 1
    tactics = {t["id"]: t for t in merged_coverage({"UC-01": ["T1110"]}, tools)}
    brute = next(t for t in tactics["TA0006"]["techniques"] if t["id"] == "T1110")
    assert brute["covered_by"] == "both" and brute["rules"] == ["UC-01"]
    assert any(t["covered_by"] == "tools" for t in tactics["TA0007"]["techniques"])


# ---------- IOC ----------


def test_ioc_detection_and_refang():
    from minisoc.ioc import IocError, detect, parse_text

    assert detect("hxxps://evil[.]example/payload") == ("url", "https://evil.example/payload")
    assert detect("Evil-Domain[.]fr") == ("domain", "evil-domain.fr")
    assert detect("203.0.113.0/24") == ("ip", "203.0.113.0/24")
    assert detect("E3B0C44298FC1C149AFBF4C8996FB92427AE41E4649B934CA495991B7852B855")[0] == "hash"
    with pytest.raises(IocError, match="trop large"):
        detect("10.0.0.0/8")
    found, rejected = parse_text("# commentaire\n198.51.100.7, evil.example ; pas_un_ioc\n198.51.100.7")
    assert found == [("ip", "198.51.100.7"), ("domain", "evil.example")] and len(rejected) == 1
    _, rejected = parse_text("evil.example", "ip")
    assert "attendu ip" in rejected[0]


def test_ioc_match_rows_checks_boundaries_and_networks():
    from minisoc.ioc import match_rows

    iocs = [(1, "domain", "evil.com"), (2, "ip", "203.0.113.0/24"), (3, "hash", "a" * 64)]
    rows = [
        {"message": "requête DNS notevil.com", "raw": ""},
        {"message": "connexion vers evil.com:443", "raw": ""},
        {"message": "", "raw": "", "destination_ip": "203.0.113.50"},
        {"message": "", "raw": '{"sha256": "' + "a" * 64 + '"}'},
    ]
    hits = match_rows(iocs, rows)
    assert len(hits[1].events) == 1 and "evil.com:443" in hits[1].events[0]["message"]
    assert len(hits[2].events) == 1 and len(hits[3].events) == 1


# ---------- Archives ----------


class _Store:
    def __init__(self, rows):
        self.rows = rows

    async def query(self, sql, params):
        return [
            r
            for r in self.rows
            if params["start"] <= r["ts"] < params["end"] and (r["ts"], r["event_id"]) > (params["cts"], params["cid"])
        ][:50_000]


async def test_archive_export_and_chain_verification(tmp_path):
    from minisoc.archives import GENESIS, chain, export_day, file_sha256, verify_records
    from minisoc.models import Archive

    day = date(2026, 10, 2)
    rows = [
        {"ts": datetime(2026, 10, 2, h), "event_id": f"id{h}", "module": "windows", "message": "é"} for h in range(3)
    ] + [{"ts": datetime(2026, 10, 3, 1), "event_id": "x", "module": "w", "message": ""}]
    path = tmp_path / "2026" / "events-2026-10-02.jsonl.gz"
    assert await export_day(_Store(rows), day, path) == 3
    lines = gzip.open(path, "rt", encoding="utf-8").read().splitlines()
    assert json.loads(lines[0])["message"] == "é"
    sha = file_sha256(path)
    first = Archive(
        day="2026-10-02",
        path="2026/events-2026-10-02.jsonl.gz",
        events=3,
        size=1,
        sha256=sha,
        prev_hash=GENESIS,
        chain_hash=chain(GENESIS, "2026-10-02", sha, 3),
    )
    assert verify_records([first], tmp_path)[0]["ok"]
    path.write_bytes(path.read_bytes() + b"x")  # falsification
    result = verify_records([first], tmp_path)[0]
    assert not result["ok"] and "modifié" in result["problems"][0]
    second = Archive(
        day="2026-10-03", path="absent.gz", events=0, size=0, sha256="0", prev_hash="faux", chain_hash="faux"
    )
    problems = verify_records([first, second], tmp_path)[1]["problems"]
    assert any("chaînage rompu" in p for p in problems) and "fichier absent" in problems


# ---------- Export ----------


def test_export_formats():
    from minisoc.export import cef, format_alert, format_event, frame, syslog_line

    line = cef("UC-01", "Attaque | VPN", 4, {"src": "203.0.113.7", "msg": "a=b"})
    assert line.startswith("CEF:0|Ville de Chatillon|Mini-SOC|1.0|UC-01|Attaque \\| VPN|10|")
    assert "msg=a\\=b" in line
    alert = {
        "id": 7,
        "rule_id": "UC-01",
        "rule_name": "Brute force",
        "severity": "high",
        "title": "t",
        "entity_key": "source.ip=203.0.113.7",
        "status": "new",
        "count": 3,
        "modules": ["sophos_xgs"],
        "first_seen": NOW.isoformat(),
        "last_seen": NOW.isoformat(),
        "sample": {"source.ip": "203.0.113.7"},
    }
    doc = json.loads(format_alert(alert, "json"))
    assert doc["minisoc"]["alert_id"] == 7 and doc["source"]["ip"] == "203.0.113.7"
    assert "src=203.0.113.7" in format_alert(alert, "cef")
    ev = json.loads(format_event(Event(ts=NOW, module="windows", user_name="j.dupont", severity=2), "json"))
    assert ev["user"]["name"] == "j.dupont" and ev["event"]["module"] == "windows"
    syslog = syslog_line("msg", 4, "minisoc", now=NOW)
    assert syslog.startswith("<162>1 2026-10-03T18:00:00.000Z minisoc minisoc - - - msg")
    assert frame("abc", "tcp") == b"3 abc" and frame("abc", "udp") == b"abc"


# ---------- Inventaire ----------


def test_assets_csv_and_priority_points():
    from minisoc.assets import AssetIndex, AssetInfo, criticality_reasons, host_key, parse_csv

    rows = parse_csv(
        "nom;type;criticité;propriétaire;service\nPC-00742;machine;vitale;DGS;Direction générale\n"
        "j.dupont;compte;haute;;Informatique\n"
    )
    assert rows[0] == {
        "kind": "host",
        "name": "PC-00742",
        "criticality": "vital",
        "owner": "DGS",
        "service": "Direction générale",
        "description": "",
    }
    assert rows[1]["kind"] == "account" and rows[1]["criticality"] == "high"
    with pytest.raises(ValueError, match="criticité inconnue"):
        parse_csv("nom;type;criticite\nPC-1;machine;énorme")
    assert host_key("PTB-00100.mairie.local") == "ptb-00100"
    index = AssetIndex()
    index.items = {
        ("host", "pc-00742"): AssetInfo("vital", "DGS", "Direction générale", "PC-00742", "poste"),
        ("account", "j.dupont"): AssetInfo("high", "", "Informatique", "j.dupont", ""),
    }
    reasons = criticality_reasons(index, ["PC-00742.mairie.local"], "MAIRIE\\j.dupont")
    assert reasons == [{"label": "machine vitale : PC-00742.mairie.local (DGS · Direction générale)", "points": 20}]
    assert criticality_reasons(index, ["PC-9"], "") == []


def test_alert_cites_exact_host_or_account():
    import re

    from minisoc.api.alerts import cites

    host = re.compile(cites("host", "PC-1"), re.I)
    assert host.search("event.module=harfanglab | host.name=PC-1 | rule.name=X {}")
    assert host.search('*regroupement* {"entities": {"event.module=h | rule.name=X | host.name=PC-1": 2}}')
    assert host.search('global {"sample_hosts": ["PC-9", "pc-1"]}')
    assert not host.search("event.module=harfanglab | host.name=PC-10 | rule.name=X {}")
    account = re.compile(cites("user", "j.dupont"), re.I)
    assert account.search('source.ip=1.2.3.4 {"sample": {"user.name": "j.dupont"}}')
    assert not account.search('source.ip=1.2.3.4 {"sample": {"user.name": "j.dupontaud"}}')
