"""Événements Windows / AD (JSON NXLog) et règles UC-12, UC-13, UC-21."""

import json
from datetime import datetime, timezone

import pytest
from conftest import RULES_DIR

from minisoc.parsers import parse_message
from minisoc.rules import load_rules
from minisoc.rules.engine import RuleSet
from minisoc.rules.sql import threshold_query

NOW = datetime(2026, 10, 3, 9, 0, tzinfo=timezone.utc)


def windows(**fields):
    body = json.dumps({"Hostname": "DC01.mairie.local", "EventTime": "2026-10-03 10:00:00", **fields})
    return parse_message("syslog", json.dumps({"message": f"<14>Oct  3 10:00:00 DC01 {body}", "peer": "10.1.0.10",
                                               "received_at": NOW.isoformat()}))


@pytest.mark.parametrize("status,reason", [("0xC000006A", "invalid_credentials"), ("0xC0000064", "unknown_user"),
                                           ("0xC0000234", "account_locked"), ("0xC0000071", "password_expired")])
def test_logon_failure_reason(status, reason):
    ev = windows(EventID=4625, TargetUserName="j.dupont", IpAddress="10.1.4.22", LogonType="3",
                 Status="0xC000006D", SubStatus=status)
    assert (ev.module, ev.category, ev.outcome, ev.reason) == ("windows", "authentication", "failure", reason)
    assert (ev.user_name, ev.source_ip, ev.network_service) == ("j.dupont", "10.1.4.22", "network")


def test_rdp_logon_success_and_kerberos():
    ok = windows(EventID=4624, TargetUserName="admin.local", IpAddress="::ffff:10.1.4.30", LogonType="10")
    assert (ok.outcome, ok.network_service, ok.source_ip) == ("success", "rdp", "10.1.4.30")
    krb = windows(EventID=4771, TargetUserName="m.martin", IpAddress="::ffff:10.1.4.31", Status="0x18")
    assert (krb.network_service, krb.reason) == ("kerberos", "invalid_credentials")


def test_privileged_group_addition_triggers_uc12():
    ev = windows(EventID=4728, TargetUserName="Admins du domaine", SubjectUserName="stagiaire",
                 MemberName="CN=Pirate Test,OU=Utilisateurs,DC=mairie,DC=local")
    assert (ev.action, ev.rule_name, ev.user_name) == ("group_member_added", "Admins du domaine", "Pirate Test")
    rules = RuleSet(load_rules(RULES_DIR))
    assert [r.id for r in rules.match(ev)] == ["UC-12"]
    normal = windows(EventID=4728, TargetUserName="GG-Comptabilite", SubjectUserName="admin",
                     MemberName="CN=Paul,OU=Utilisateurs,DC=mairie,DC=local")
    assert rules.match(normal) == []


def test_log_cleared_triggers_uc13_only():
    ev = windows(EventID=1102, SubjectUserName="admin")
    assert ev.action == "log_cleared"
    assert [r.id for r in RuleSet(load_rules(RULES_DIR)).match(ev)] == ["UC-13"]


def test_lockout_uses_caller_computer():
    ev = windows(EventID=4740, TargetUserName="c.bernard", TargetDomainName="PC-ACCUEIL-03")
    assert (ev.action, ev.user_name, ev.host_name) == ("account_locked", "c.bernard", "PC-ACCUEIL-03")


def test_spraying_rule_query():
    rule = next(r for r in load_rules(RULES_DIR) if r.id == "UC-21")
    sql, params = threshold_query(rule)
    assert "uniqExact(user_name) OVER" in sql and "reason IN" in sql


def test_non_windows_json_is_not_misparsed():
    ev = parse_message("syslog", json.dumps({"message": '<14>app {"level": "info", "msg": "ok"}', "peer": "x",
                                             "received_at": NOW.isoformat()}))
    assert ev.module == "syslog"


def test_nxlog_ce_local_time_and_utc_field():
    """NXLog Community Edition date en heure locale sans fuseau ; EventTimeUTC (ms, nxlog.conf) fait foi."""
    from minisoc.parsers.windows import parse_windows

    received = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)
    local = parse_windows({"EventID": 4625, "Hostname": "DC01", "EventTime": "2026-10-07 10:00:00"}, received)
    assert local.ts == datetime(2026, 10, 7, 8, 0, tzinfo=timezone.utc)  # heure d'été de Paris : UTC+2
    winter = parse_windows({"EventID": 4625, "Hostname": "DC01", "EventTime": "2026-12-07 10:00:00"}, received)
    assert winter.ts == datetime(2026, 12, 7, 9, 0, tzinfo=timezone.utc)
    utc = parse_windows({"EventID": 4625, "Hostname": "DC01", "EventTime": "2026-10-07 10:00:00",
                         "EventTimeUTC": 1791360000123}, received)
    assert utc.ts == datetime.fromtimestamp(1791360000.123, tz=timezone.utc)
