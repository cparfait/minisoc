"""Corrélation par adresse IP : même IP publique en alerte sur plusieurs outils (UC-61), IP bannie par OGO puis
connexion réussie (UC-62)."""

from datetime import timedelta

from conftest import RULES_DIR
from test_detection_plus import NOW, alert

from minisoc.ecs import Event
from minisoc.risk import compute_risk, find_shared_ips, ips_of, public_ip
from minisoc.rules import load_rules
from minisoc.rules.engine import RuleSet, render_title
from minisoc.rules.sql import sequence_query

RULES = RuleSet(load_rules(RULES_DIR))


def ip_alert(alert_id, module, ip, hours=1, status="new", rule_id="NATIVE", category=None, how="entity"):
    a = alert(alert_id, rule_id=rule_id, hours=hours, status=status, category=category)
    a.modules = [module]
    if how == "entity":
        a.entity_key = f"source.ip={ip}"
    elif how == "sample":
        a.details = {**a.details, "sample": {"source.ip": ip}}
    else:
        a.details = {**a.details, "entities": {f"source.ip={ip}": 3}}
    return a


def test_public_ip_and_extraction():
    assert public_ip("203.0.113.9") == "" and public_ip("8.8.8.8") == "8.8.8.8"  # 203.0.113/24 : documentation
    assert public_ip("192.168.2.253") == "" and public_ip("10.1.2.3") == "" and public_ip("pas une ip") == ""
    a = ip_alert(1, "m365", "1.2.3.4", how="sample")
    a.details["sample_ips"] = ["5.6.7.8", "192.168.3.1"]
    assert ips_of(a) == {"1.2.3.4", "5.6.7.8"}


def test_same_ip_on_several_tools():
    alerts = [
        ip_alert(1, "sophos_xgs", "45.9.20.1", rule_id="UC-01"),
        ip_alert(2, "m365", "45.9.20.1", how="sample", rule_id="UC-36"),
        ip_alert(3, "ogo", "45.9.20.1", how="entities", rule_id="UC-17"),
        ip_alert(4, "sophos_xgs", "45.9.20.2"),  # un seul outil
        ip_alert(5, "sophos_xgs", "45.9.20.2", rule_id="UC-03a"),
        ip_alert(6, "sophos_xgs", "45.9.20.3"),
        ip_alert(7, "m365", "45.9.20.3", status="false_positive"),  # faux positif : ne compte pas
        ip_alert(8, "sophos_xgs", "45.9.20.4"),
        ip_alert(9, "m365", "45.9.20.4", hours=30),  # hors des 24 h
        ip_alert(10, "sophos_xgs", "192.168.2.50"),  # adresse interne : exclue
        ip_alert(11, "vectra", "192.168.2.50"),
        ip_alert(12, "sophos_xgs", "45.9.20.5"),
        ip_alert(13, "cyberwatch", "45.9.20.5", category="hygiene"),  # hygiène : pas une menace
    ]
    shared = find_shared_ips(alerts, now=NOW)
    assert [s.ip for s in shared] == ["45.9.20.1"]
    assert shared[0].tools == ["m365", "ogo", "sophos_xgs"] and shared[0].alert_ids == [1, 2, 3]

    derived = ip_alert(20, "sophos_xgs", "45.9.20.6", rule_id="UC-61")
    assert not find_shared_ips([derived, ip_alert(21, "m365", "45.9.20.6")], now=NOW)  # UC-61 ne s'auto-alimente pas
    assert compute_risk([derived], {}, now=NOW) == {}

    rule = RULES.by_id["UC-61"]
    assert rule.group_by == ["source.ip"] and rule.severity_level == 3
    assert render_title(rule.title, {"source.ip": "45.9.20.1", "value": 3}) == "45.9.20.1 en alerte sur 3 outils"


def test_ogo_banned_ip_then_success_rule():
    rule = RULES.by_id["UC-62"]
    assert rule.group_by == ["source.ip"] and rule.sequence.within == timedelta(hours=72)
    sql, params = sequence_query(rule)
    assert "INNER JOIN" in sql and "ogo" in params.values() and "new_ip_blocked" in str(params.values())
    banned = Event(ts=NOW, module="ogo", kind="event", category="intrusion_detection", action="new_ip_blocked",
                   source_ip="45.9.20.1")
    assert rule.sequence.first and not RULES.match(banned)  # seul : aucune alerte
