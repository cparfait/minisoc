"""Comptes sensibles (administrateurs, comptes de service) et règles UC-23 à UC-31."""

import json
from datetime import datetime, timezone

from conftest import RULES_DIR

from minisoc.accounts import SensitiveAccounts, normalize
from minisoc.ldap_auth import _account, _filetime
from minisoc.parsers import parse_message
from minisoc.rules import load_rules
from minisoc.rules.engine import RuleSet
from minisoc.rules.sql import HOST_KEY, novelty_query, threshold_query

NOW = datetime(2026, 10, 3, 9, 0, tzinfo=timezone.utc)
RULES = {r.id: r for r in load_rules(RULES_DIR)}


def windows(**fields):
    body = json.dumps({"Hostname": "DC01.mairie.local", "EventTime": "2026-10-03 10:00:00", **fields})
    return parse_message("syslog", json.dumps({"message": f"<14>Oct  3 10:00:00 DC01 {body}", "peer": "10.1.0.10",
                                               "received_at": NOW.isoformat()}))


class _Redis:
    def __init__(self, data):
        self.data = data

    async def hkeys(self, key):
        return list(self.data.get(key, {}))


async def accounts(admins=(), services=(), cfg=None):
    acc = SensitiveAccounts(_Redis({"minisoc:accounts:admin": dict.fromkeys(admins, "{}"),
                                    "minisoc:accounts:service": dict.fromkeys(services, "{}")}))
    await acc.refresh(cfg or {"accounts_admin_patterns": ["adm-*"], "accounts_service_patterns": ["svc*", "srv-*"]})
    return acc


def test_normalize_strips_domain_forms():
    assert normalize("MAIRIE\\J.Dupont") == normalize("j.dupont@mairie.local") == "j.dupont"


async def test_roles_from_directory_and_patterns():
    acc = await accounts(admins=["m.durand"], services=["sql_prod"])
    assert acc.roles("MAIRIE\\M.Durand") == "admin"
    assert acc.roles("adm-jdupont") == "admin"
    assert acc.roles("svc_backup") == "service"
    assert acc.roles("sql_prod@mairie.local") == "service"
    assert acc.roles("j.dupont") == ""
    assert acc.roles("SRV-WEB$") == ""  # compte machine : les motifs ne s'appliquent pas


def test_ad_account_attributes():
    entry = {"attributes": {"sAMAccountName": ["svc_sql"], "userAccountControl": ["66048"],
                            "servicePrincipalName": ["MSSQLSvc/sql01:1433", "MSSQLSvc/sql01"],
                            "lastLogonTimestamp": ["134040000000000000"], "pwdLastSet": ["0"]}}
    account = _account(entry)
    assert account["name"] == "svc_sql" and account["password_never_expires"] and not account["disabled"]
    assert account["spn_count"] == 2 and account["password_set"] is None
    assert account["last_logon"].startswith("2025-")
    assert _filetime(["9223372036854775807"]) is None


def test_failure_keeps_source_workstation():
    ev = windows(EventID=4625, TargetUserName="j.dupont", IpAddress="10.1.4.22", LogonType="3",
                 WorkstationName="PC-COMPTA-03", Status="0xC000006D", SubStatus="0xC000006A")
    assert (ev.host_name, ev.observer) == ("PC-COMPTA-03", "DC01.mairie.local")
    ntlm = windows(EventID=4776, TargetUserName="j.dupont", Workstation="\\\\PC-RH-01", Status="0xC000006A")
    assert ntlm.host_name == "PC-RH-01"


def test_account_management_events():
    reset = windows(EventID=4724, TargetUserName="adm-jdupont", SubjectUserName="helpdesk1")
    assert (reset.action, reset.user_name, reset.threat_name) == ("password_reset", "adm-jdupont", "par helpdesk1")
    unlock = windows(EventID=4767, TargetUserName="j.dupont", SubjectUserName="helpdesk1")
    assert unlock.action == "account_unlocked"
    removed = windows(EventID=4729, TargetUserName="Admins du domaine", SubjectUserName="m.durand",
                      MemberName="CN=Jean Dupont,OU=DSI,DC=mairie,DC=local")
    assert (removed.action, removed.user_name, removed.rule_name) == ("group_member_removed", "Jean Dupont",
                                                                      "Admins du domaine")


async def test_sensitive_lockout_and_service_interactive_logon_rules():
    acc = await accounts(services=["svc_sql"])
    rs = RuleSet(load_rules(RULES_DIR))
    lock = windows(EventID=4740, TargetUserName="svc_sql", TargetDomainName="SRV-APP01")
    lock.user_roles = acc.roles(lock.user_name)
    assert "UC-23" in {r.id for r in rs.match(lock)}
    plain = windows(EventID=4740, TargetUserName="j.dupont", TargetDomainName="PC-RH-01")
    plain.user_roles = acc.roles(plain.user_name)
    assert "UC-23" not in {r.id for r in rs.match(plain)}
    rdp = windows(EventID=4624, TargetUserName="svc_sql", IpAddress="10.1.4.30", LogonType="10",
                  WorkstationName="PC-COMPTA-03")
    rdp.user_roles = acc.roles(rdp.user_name)
    assert "UC-25" in {r.id for r in rs.match(rdp)}
    network = windows(EventID=4624, TargetUserName="svc_sql", IpAddress="10.1.4.30", LogonType="3")
    network.user_roles = acc.roles(network.user_name)
    assert "UC-25" not in {r.id for r in rs.match(network)}


def test_kerberoasting_event_and_query():
    ev = windows(EventID=4769, TargetUserName="j.dupont@MAIRIE.LOCAL", ServiceName="svc_sql",
                 TicketEncryptionType="0x17", IpAddress="::ffff:10.1.4.22", Status="0x0")
    assert (ev.action, ev.user_name, ev.rule_name, ev.threat_name) == ("service_ticket", "j.dupont", "svc_sql", "rc4")
    sql, params = threshold_query(RULES["UC-30"])
    assert "uniqExact(rule_name)" in sql and ["rc4", "des"] in params.values()


def test_admin_new_workstation_is_a_novelty_on_host():
    sql, _ = novelty_query(RULES["UC-28"])
    assert "host_name" in sql and "user_roles" in sql


def test_new_rules_are_mapped_to_mitre():
    for rule_id in ("UC-23", "UC-24", "UC-25", "UC-26", "UC-27", "UC-28", "UC-29", "UC-30", "UC-31"):
        assert RULES[rule_id].mitre, rule_id


def test_file_delete_and_rename_on_file_server():
    ev = windows(EventID=4663, Hostname="FS01.mairie.local", SubjectUserName="j.dupont", AccessMask="0x10000",
                 ObjectType="File", ObjectName=r"D:\Partages\RH\paie-2026.xlsx",
                 ProcessName=r"C:\Windows\explorer.exe")
    assert (ev.category, ev.action, ev.user_name, ev.host_name) == ("file", "file_delete", "j.dupont",
                                                                    "FS01.mairie.local")
    assert (ev.rule_name, ev.threat_name) == (".xlsx", "explorer.exe")
    read = windows(EventID=4663, SubjectUserName="j.dupont", AccessMask="0x1", ObjectName=r"D:\a.txt")
    assert read.action != "file_delete"
    sql, _ = threshold_query(RULES["UC-32"])
    assert "uniqExact(file_path)" in sql and f"{HOST_KEY} AS g1" in sql


def test_fsrm_ransomware_extension_is_critical():
    rs = RuleSet(load_rules(RULES_DIR))
    for message in (
        r"The system detected that user MAIRIE\j.dupont attempted to save D:\Partages\RH\x.docx.locky on D: "
        "on server FS01. This file matches the 'Ransomware' file group.",
        r"Le système a détecté que l'utilisateur MAIRIE\j.dupont a tenté d'enregistrer D:\Partages\RH\x.docx.locky "
        "sur D: sur le serveur FS01.",
    ):
        ev = windows(EventID=8215, Hostname="FS01.mairie.local", Message=message)
        assert (ev.action, ev.user_name, ev.file_path) == ("ransomware_file_blocked", "j.dupont",
                                                           r"D:\Partages\RH\x.docx.locky")
        assert "UC-33" in {r.id for r in rs.match(ev)}


