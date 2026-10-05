import json
from datetime import datetime, timezone

from minisoc.parsers import parse_message
from minisoc.parsers.bitdefender import parse_bitdefender
from minisoc.parsers.cef import parse_cef
from minisoc.parsers.common import parse_kv
from minisoc.parsers.harfanglab import parse_harfanglab

NOW = datetime(2026, 10, 1, 12, 0, tzinfo=timezone.utc)


def syslog(line: str):
    return parse_message("syslog", json.dumps({"message": line, "peer": "192.0.2.1", "received_at": NOW.isoformat()}))


def test_parse_kv_handles_quotes_and_empty_values():
    kv = parse_kv('a=1 b="deux mots" c= d="x \\"y\\"" e=fin')
    assert kv == {"a": "1", "b": "deux mots", "c": "", "d": 'x "y"', "e": "fin"}


def test_sophos_ssl_vpn_failure_legacy_format(sophos_lines):
    ev = syslog(sophos_lines[0])
    assert ev.module == "sophos_xgs"
    assert ev.category == "authentication"
    assert ev.outcome == "failure"
    assert ev.network_service == "ssl_vpn"
    assert ev.user_name == "j.dupont"
    assert ev.source_ip == "185.220.101.45"
    assert ev.observer == "XGS2100"
    assert ev.ts == NOW  # pas de champ timestamp : heure de réception


def test_sophos_ipsec_failure_v20_format_uses_timestamp(sophos_lines):
    ev = syslog(sophos_lines[1])
    assert (ev.category, ev.outcome, ev.network_service) == ("authentication", "failure", "ipsec")
    assert ev.ts == datetime(2026, 10, 1, 1, 12, 46, tzinfo=timezone.utc)


def test_sophos_success(sophos_lines):
    ev = syslog(sophos_lines[2])
    assert (ev.outcome, ev.network_service, ev.user_name) == ("success", "ssl_vpn", "m.martin")


def test_sophos_admin_console(sophos_lines):
    ev = syslog(sophos_lines[3])
    assert ev.network_service == "admin_console"
    assert ev.outcome == "failure"


def test_sophos_atp_is_native_alert(sophos_lines):
    ev = syslog(sophos_lines[4])
    assert ev.kind == "alert"
    assert ev.category == "intrusion_detection"
    assert ev.severity >= 3
    assert ev.threat_name == "C2/Generic-A"


def test_sophos_ipsec_tunnel_event_is_not_an_ips_alert(sophos_lines):
    ev = syslog(sophos_lines[5])
    assert ev.kind == "event"
    assert ev.category != "intrusion_detection"


def test_unknown_syslog_kept_as_generic():
    ev = syslog("<13>Oct  1 12:00:00 nas01 backup job failed")
    assert ev.module == "syslog"
    assert "backup job failed" in ev.message


def test_invalid_payload_is_never_lost():
    ev = parse_message("syslog", "{pas du json")
    assert ev.module == "unparsed"
    assert ev.raw == "{pas du json"


def test_cef_vectra():
    line = (
        "CEF:0|Vectra Networks|X Series|7.1|hsc|Host Score Change|7|dvchost=brain01 shost=PC-COMPTA "
        "src=10.1.2.30 msg=Score de menace en hausse cs1=C2 activity"
    )
    ev = parse_cef(line, NOW)
    assert ev.module == "vectra"
    assert ev.kind == "alert"
    assert ev.severity == 3
    assert ev.host_name == "PC-COMPTA"
    assert ev.message == "Score de menace en hausse"


def test_cef_header_with_escaped_pipe():
    ev = parse_cef(r"CEF:0|Varonis|DatAlert|8|42|Accès a\|b anormal|High|suser=CORP\\alice", NOW)
    assert ev.module == "varonis"
    assert ev.rule_name == "Accès a|b anormal"
    assert ev.user_name == "alice"  # « DOMAINE\utilisateur » ramené à l'identifiant (comme l'AD)
    assert ev.severity == 3


def test_cef_vectra_quadrant_severity_and_console_link():
    line = (
        "CEF:0|Vectra Networks|X Series|7.1|hsc|Host Score Change|3|externalId=812 cat=HOST SCORING dvchost=brain01 "
        "shost=PC-COMPTA src=10.1.2.30 flexNumber1Label=threat flexNumber1=67 flexNumber2Label=certainty "
        "flexNumber2=80 cs4Label=Vectra Internal Host URL cs4=https://brain01/hosts/812"
    )
    ev = parse_cef(line, NOW)
    assert (ev.action, ev.severity, ev.reference) == ("host_scoring", 4, "https://brain01/hosts/812")
    assert "menace 67, certitude 80" in ev.message
    low = parse_cef(line.replace("flexNumber1=67", "flexNumber1=20").replace("flexNumber2=80", "flexNumber2=30"), NOW)
    assert low.severity == 1
    account = parse_cef(
        "CEF:0|Vectra Networks|X Series|7.1|asc|Account Score Change|3|cat=ACCOUNT SCORING suser=adm-jdupont "
        "flexNumber1Label=threat flexNumber1=70 flexNumber2Label=certainty flexNumber2=40", NOW)
    assert (account.action, account.user_name, account.severity) == ("account_scoring", "adm-jdupont", 3)


def test_cef_varonis_ransomware_goes_to_uc06():
    from conftest import RULES_DIR

    from minisoc.rules import load_rules
    from minisoc.rules.engine import RuleSet

    ev = parse_cef(r"CEF:0|Varonis Inc.|DatAdvantage|8.6|7|Ransomware: encryption of files detected|Medium|"
                   r"suser=CORP\\j.dupont dhost=FS01 filePath=D:\\Partages\\RH", NOW)
    assert (ev.action, ev.severity, ev.user_name) == ("ransomware_detected", 4, "j.dupont")
    assert "UC-06" in {r.id for r in RuleSet(load_rules(RULES_DIR)).match(ev)}


def test_bitdefender_malware_blocked_is_medium():
    ev = parse_bitdefender(
        {"module": "av", "computer_name": "PC-01", "malware_name": "EICAR-Test-File", "final_status": "deleted"}, NOW
    )
    assert (ev.category, ev.outcome, ev.severity) == ("malware", "success", 2)


def test_bitdefender_malware_not_neutralized_is_critical():
    ev = parse_bitdefender(
        {"module": "av", "computer_name": "PC-01", "malware_name": "Trojan.X", "final_status": "present"}, NOW
    )
    assert (ev.outcome, ev.severity) == ("failure", 4)
    assert ev.host_name == "PC-01"


def test_bitdefender_ransomware():
    ev = parse_bitdefender({"module": "ransomware-mitigation", "computer_name": "SRV-FICHIERS"}, NOW)
    assert ev.action == "ransomware_detected"
    assert ev.severity == 4


def test_harfanglab_alert():
    alert = {
        "id": "abc-123",
        "alert_time": "2026-10-01T10:00:00Z",
        "level": "high",
        "rule_name": "Mimikatz",
        "msg": "Credential dumping",
        "agent": {"hostname": "PC-RH", "ipaddress": "10.1.5.5"},
    }
    ev = parse_harfanglab(alert, NOW, "https://edr.example")
    assert (ev.module, ev.kind, ev.severity) == ("harfanglab", "alert", 3)
    assert ev.host_name == "PC-RH"
    assert ev.reference == "https://edr.example/security-event/abc-123/summary"


def test_hostile_content_is_bounded():
    line = 'device_name="X" log_type="Authentication" log_component="SSL VPN" status="Failed" user_name="'
    ev = syslog(line + "A" * 5000 + '\x00"')
    assert len(ev.user_name) <= 512
    assert "\x00" not in ev.raw
