from datetime import datetime, timedelta, timezone

import pytest
from conftest import RULES_DIR

from minisoc.ecs import Event
from minisoc.rules import Rule, RuleError, load_rules
from minisoc.rules.engine import RuleSet, entity_key, render_title
from minisoc.rules.filters import Params, matches, to_sql
from minisoc.rules.model import Condition
from minisoc.rules.sql import LATE_SECONDS, USER_KEY, sequence_query, threshold_query

NOW = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


def vpn_failure(**kw) -> Event:
    base = dict(
        ts=NOW,
        module="sophos_xgs",
        category="authentication",
        outcome="failure",
        network_service="ssl_vpn",
        source_ip="185.220.101.45",
        user_name="j.dupont",
    )
    return Event(**{**base, **kw})


def rule(rule_id: str) -> Rule:
    return next(r for r in load_rules(RULES_DIR) if r.id == rule_id)


def test_all_shipped_rules_are_valid():
    ids = {r.id for r in load_rules(RULES_DIR, strict=True)}
    assert {"UC-01", "UC-02a", "UC-02b", "UC-03a", "UC-03b", "UC-05", "UC-06", "UC-10", "UC-16", "NATIVE"} <= ids


@pytest.mark.parametrize(
    "flt,expected",
    [
        ({"event.outcome": "failure"}, True),
        ({"network.service": ["ipsec", "ssl_vpn"]}, True),
        ({"network.service": ["ipsec"]}, False),
        ({"user.name": {"contains": "DUPONT"}}, True),
        ({"source.ip": {"cidr": ["185.220.0.0/16"]}}, True),
        ({"source.ip": {"not_cidr": ["10.0.0.0/8"]}}, True),
        ({"event.severity": {"gte": 2}}, False),
        ({"any": [{"user.name": "x"}, {"event.outcome": "failure"}]}, True),
        ({"not": {"event.outcome": "failure"}}, False),
        ({"host.name": {"exists": True}}, False),
    ],
)
def test_filter_matching(flt, expected):
    assert matches(flt, vpn_failure()) is expected


def test_not_cidr_never_matches_missing_ip():
    assert matches({"source.ip": {"not_cidr": ["10.0.0.0/8"]}}, vpn_failure(source_ip="")) is False


def test_sql_uses_bound_parameters_only():
    params = Params()
    sql = to_sql({"user.name": "x' OR 1=1 --", "network.service": ["a", "b"], "event.severity": {"gte": 3}}, params)
    assert "OR 1=1" not in sql
    assert "user_name = {p0:String}" in sql
    assert "network_service IN {p1:Array(String)}" in sql
    assert params.values["p0"] == "x' OR 1=1 --"


def test_unknown_field_is_rejected():
    with pytest.raises(RuleError, match="champ inconnu"):
        Rule.from_dict({"id": "T", "name": "t", "type": "match", "severity": "high", "filter": {"user.nom": "x"}})


def test_condition_parsing():
    assert Condition.parse("count_distinct(source.ip) >= 20") == Condition("count_distinct", "source.ip", ">=", 20)
    assert Condition.parse("count() > 5").function == "count"
    with pytest.raises(RuleError):
        Condition.parse("sum(source.port) > 5")


def test_threshold_query_groups_and_excludes_empty_values():
    sql, params = threshold_query(rule("UC-02a"))
    assert "uniqExact(source_ip) OVER (PARTITION BY" in sql  # fenêtre glissante exacte
    assert f"{USER_KEY} AS g0" in sql and "user_name != ''" in sql  # compte unifié
    assert "RANGE BETWEEN 3600000 PRECEDING" in sql and 20 in params.values()
    assert 3600 + LATE_SECONDS in params.values()  # retard toléré des sources


def test_global_threshold_query():
    sql, _ = threshold_query(rule("UC-02b"))
    assert "'global' AS g0" in sql and "PARTITION BY" not in sql


def test_sequence_query_joins_on_key():
    r = rule("UC-03a")
    sql, _ = sequence_query(r)
    assert "HAVING count() >=" in sql and "INNER JOIN" in sql
    # Ordre : seuls les « first » antérieurs à l'événement « then », dans la fenêtre `within` qui le précède
    assert "arrayCount(x -> x < t.ts AND x >= t.ts - toIntervalSecond(" in sql
    assert "lower(source_ip)" not in sql  # adresse : comparée telle quelle
    assert r.group_by == ["source.ip"]
    sql_user, _ = sequence_query(rule("UC-03b"))
    assert f"{USER_KEY} AS g0" in sql_user  # compte : clé unifiée (toutes formes du nom, sans casse)


def test_ruleset_fallback_only_when_no_specific_rule():
    rs = RuleSet(load_rules(RULES_DIR))
    unneutralized = Event(
        ts=NOW, module="bitdefender", kind="alert", category="malware", outcome="failure", severity=4,
        host_name="PC-01", threat_name="Trojan.X",
    )
    assert [r.id for r in rs.match(unneutralized)] == ["UC-05"]
    blocked = Event(
        ts=NOW, module="bitdefender", kind="alert", category="malware", outcome="success", severity=2,
        host_name="PC-01", rule_name="av",
    )
    assert [r.id for r in rs.match(blocked)] == ["NATIVE"]
    assert rs.match(vpn_failure()) == []


def test_admin_console_from_internet_matches_uc10_but_not_from_lan():
    rs = RuleSet(load_rules(RULES_DIR))
    outside = vpn_failure(network_service="admin_console", source_ip="203.0.113.9")
    inside = vpn_failure(network_service="admin_console", source_ip="192.168.1.10")
    assert [r.id for r in rs.match(outside)] == ["UC-10"]
    assert rs.match(inside) == []


def test_entity_key_and_title():
    values = {"user.name": "j.dupont", "value": 42}
    assert entity_key(["user.name"], values) == "user.name=j.dupont"
    assert entity_key([], values) == "global"
    assert render_title("Compte {user.name} : {value} IP ({host.name})", values) == "Compte j.dupont : 42 IP (?)"
    # Valeur de repli : la première renseignée (ex. UC-22 sur une alerte EDR, sans IP de destination)
    assert render_title("visant {destination.ip|host.name}", {"host.name": "SRV-WEB"}) == "visant SRV-WEB"
    assert render_title("visant {destination.ip|host.name}", {}) == "visant ?"


def test_duration_validation():
    base = {"id": "T", "name": "t", "type": "threshold", "severity": "high",
            "filter": {"event.outcome": "failure"}, "condition": "count() > 1"}
    with pytest.raises(RuleError, match="durée invalide"):
        Rule.from_dict({**base, "window": "1 heure"})
    assert Rule.from_dict({**base, "window": "90m"}).window == timedelta(minutes=90)
