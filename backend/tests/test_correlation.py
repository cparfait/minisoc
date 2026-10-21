"""Croisement des données : catégories des règles, risque sans hygiène seule, alertes clôturées non recréées,
machines connues par leur adresse, premier relevé NinjaOne, IOC rattachés au bon type d'entité, identités
unifiées, événements en retard, corrélations entre sources, couverture antivirus et EDR, corroboration."""

from datetime import datetime, timedelta, timezone

import pytest
from conftest import RULES_DIR
from test_detection_plus import NOW, alert

from minisoc.alerts import Detection, _already_handled
from minisoc.assets import host_key
from minisoc.connectors.ninjaone import changes
from minisoc.identity import user_aliases
from minisoc.models import Alert
from minisoc.risk import compute_risk
from minisoc.rules import Rule, RuleError, load_rules
from minisoc.rules.engine import RuleSet, entity_key, render_title
from minisoc.rules.sql import LATE_SECONDS, sequence_query, threshold_query

RULES = RuleSet(load_rules(RULES_DIR))


# ---------- Catégorie des règles ----------

def test_hygiene_rules_are_categorized():
    by_id = RULES.by_id
    for rule_id in ("UC-11", "UC-15", "UC-48", "UC-49", "UC-50"):
        assert by_id[rule_id].category == "hygiene", rule_id
    assert by_id["UC-22"].category == "threat" and by_id["NATIVE"].category == "threat"
    with pytest.raises(RuleError):
        Rule.from_dict({"id": "X", "name": "x", "type": "match", "severity": "low", "category": "autre",
                        "filter": {"event.module": "x"}})


def test_hygiene_only_weighs_little_in_risk():
    hygiene_rules = {"UC-11": "hygiene", "UC-15": "hygiene"}
    alerts = [alert(1, host="SRV-WSUS", rule_id="UC-11", rule="Antivirus désactivé", severity=3),
              alert(2, host="SRV-WSUS", rule_id="UC-15", rule="Vulnérabilités critiques", severity=3)]
    risks = compute_risk(alerts, {}, now=NOW, rule_category=hygiene_rules)
    risk = next(iter(risks.values()))
    assert risk.score < 10  # 2 × 20 points × 0,2 : l'hygiène seule ne fait pas un risque d'attaque
    assert all(c["category"] == "hygiene" for c in risk.contributions.values())
    # Sans la catégorie de la règle (avant cette version), les mêmes alertes comptaient comme des menaces
    assert next(iter(compute_risk(alerts, {}, now=NOW).values())).score == 40


# ---------- Alertes clôturées : pas recréées pour la même activité ----------

def _det(first_minutes_ago, last_minutes_ago):
    now = datetime.now(timezone.utc)
    return Detection(rule=RULES.by_id["UC-01"], entity_key="source.ip=203.0.113.9", severity=3, title="x",
                     first_seen=now - timedelta(minutes=first_minutes_ago),
                     last_seen=now - timedelta(minutes=last_minutes_ago), accumulate=False)


def _closed(status, last_minutes_ago):
    return Alert(id=9, rule_id="UC-01", entity_key="source.ip=203.0.113.9", status=status, severity=3,
                 last_seen=datetime.now(timezone.utc) - timedelta(minutes=last_minutes_ago))


def test_closed_alert_not_recreated_for_the_same_events():
    assert _already_handled(_closed("resolved", 2), _det(10, 3))  # rien de plus récent que l'alerte close
    assert not _already_handled(_closed("resolved", 5), _det(10, 1))  # l'attaque continue : nouvelle alerte
    # Faux positif : même activité (fenêtre qui chevauche) → pas de nouvelle alerte
    assert _already_handled(_closed("false_positive", 5), _det(10, 1))
    # Faux positif mais activité nouvelle, commencée après : nouvelle alerte
    assert not _already_handled(_closed("false_positive", 30), _det(10, 1))


# ---------- Machines connues par leur adresse ----------

def test_host_key_keeps_ip_addresses():
    assert host_key("PTB-00100.mairie.local") == "ptb-00100"
    assert host_key("192.168.2.38") == "192.168.2.38"
    assert host_key("IP-192.168.2.38") == "192.168.2.38"  # nom d'entité Vectra
    assert host_key("10.1.2.3") != host_key("10.9.9.9")  # avant : « 10 » pour les deux


# ---------- NinjaOne : premier relevé = état des lieux ----------

STATE = {"antivirus": "inactive", "threats": 0, "critical": 12, "failed": 3}


def test_ninjaone_first_survey_is_a_baseline():
    assert changes(1, STATE, None, baseline=True) == []
    assert [c["kind"] for c in changes(1, {**STATE, "threats": 1}, None, baseline=True)] == ["active_threat"]
    # Machine apparue après le premier relevé : seulement ce qui est grave
    assert [c["kind"] for c in changes(2, STATE, None)] == ["antivirus_inactive"]
    # Ensuite : les aggravations
    before = {**STATE, "critical": 10, "failed": 3}
    assert [c["kind"] for c in changes(1, STATE, before)] == ["critical_vulnerabilities"]


# ---------- IOC : bon type d'entité ----------

def test_ioc_alert_keeps_the_entity_type():
    rule = RULES.by_id["UC-42"]
    values = {"threat.intel": "ip:198.51.100.7", "user.name": "j.dupont"}
    assert entity_key(rule.group_by, values) == ("threat.intel=ip:198.51.100.7 | host.name= | user.name=j.dupont"
                                                 " | source.ip=")
    assert render_title(rule.title, values) == "IOC trouvé : ip:198.51.100.7 (j.dupont)"


# ---------- Identités unifiées ----------

DIRECTORY = [
    {"sam": "JDupont", "upn": "jean.dupont@chatillon92.fr", "mail": "Jean.Dupont@chatillon92.fr",
     "display": "Jean  Dupont", "proxies": ["SMTP:jean.dupont@chatillon92.fr", "smtp:jdupont@mairie.local",
                                             "X500:/o=ExchangeLabs"]},
    {"sam": "mmartin", "upn": "marie.martin@chatillon92.fr", "display": "Marie Martin"},
    {"sam": "pmartin", "upn": "paul.martin@chatillon92.fr", "display": "Marie Martin"},  # homonyme d'affichage
    {"sam": "accueil", "upn": "mmartin@chatillon92.fr"},  # alias qui est l'identifiant d'un autre compte
]


@pytest.fixture
def aliases():
    from minisoc.identity import IDENTITIES

    saved = (IDENTITIES.users, IDENTITIES.hosts)
    IDENTITIES.users = user_aliases(DIRECTORY)
    IDENTITIES.hosts = {"192.168.2.38": "pc-00605"}
    yield IDENTITIES
    IDENTITIES.users, IDENTITIES.hosts = saved


def test_same_account_under_all_its_forms(aliases):
    from minisoc.identity import user_key

    for form in ("MAIRIE\\JDupont", "jdupont", "jean.dupont@chatillon92.fr", "Jean.Dupont@chatillon92.fr",
                 "jean dupont", "JDUPONT@mairie.local"):
        assert user_key(form) == "jdupont", form
    assert user_key("marie.martin@chatillon92.fr") == "mmartin"
    assert user_key("Marie Martin") == "marie martin"  # deux comptes portent ce nom : pas de rapprochement
    assert user_key("mmartin@chatillon92.fr") == "mmartin"  # jamais réécrit vers un autre compte
    assert user_key("inconnu@ailleurs.fr") == "inconnu"


def test_same_machine_by_name_fqdn_or_address(aliases):
    from minisoc.identity import host_aliases, same
    from minisoc.identity import host_key as unified_host

    assert (unified_host("PC-00605.mairie.local") == unified_host("IP-192.168.2.38")
            == unified_host("192.168.2.38") == host_key("192.168.2.38") == "pc-00605")
    assert unified_host("10.0.0.9") == "10.0.0.9"  # adresse inconnue : gardée
    assert same("host.name", "PC-00605", "192.168.2.38") and same("user.name", "Jean Dupont", "MAIRIE\\jdupont")
    assert not same("source.ip", "10.0.0.1", "10.0.0.2")
    old, new = datetime(2026, 10, 1, tzinfo=timezone.utc), datetime(2026, 10, 14, tzinfo=timezone.utc)
    table = host_aliases([("PC-OLD", "192.168.2.50", old), ("PC-NEW.mairie.local", "192.168.2.50", new),
                          ("IP-192.168.2.60", "192.168.2.60", new), ("PC-X", "127.0.0.1", new)])
    assert table == {"192.168.2.50": "pc-new"}  # bail DHCP : la plus récente ; jamais une adresse pour nom


def test_exceptions_and_roles_follow_aliases(aliases):
    from minisoc.accounts import SensitiveAccounts
    from minisoc.alerts import ExceptionCache
    from minisoc.models import RuleException

    cache = ExceptionCache(None)
    cache.items = [RuleException(rule_id="UC-34", field="user.name", value="MAIRIE\\jdupont",
                                 expires_at=datetime.now(timezone.utc) + timedelta(days=1))]
    assert cache.is_excepted("UC-34", {"user.name": "jean.dupont@chatillon92.fr"})
    assert not cache.is_excepted("UC-34", {"user.name": "marie.martin@chatillon92.fr"})
    accounts = SensitiveAccounts(None)
    accounts.known["admin"] = {"jdupont"}
    assert accounts.roles("Jean.Dupont@chatillon92.fr") == "admin"  # administrateur aussi dans Microsoft 365


def test_rules_group_on_identity_keys():
    from minisoc.rules.sql import HOST_KEY, USER_KEY, key_expr

    assert key_expr("user.name") == USER_KEY and key_expr("host.name") == HOST_KEY
    assert key_expr("source.ip") == "source_ip"
    seq, _ = sequence_query(RULES.by_id["UC-56"])
    assert f"{HOST_KEY} AS g0" in seq  # machine signalée par l'EDR ↔ connexions Windows depuis cette machine


# ---------- Événements en retard ----------

def test_scheduled_rules_follow_the_reception_watermark():
    sql, params = threshold_query(RULES.by_id["UC-37"], since=95)
    assert "ingest_ts >= now64(3) - toIntervalSecond(" in sql and 95 in params.values()
    assert 3600 + LATE_SECONDS in params.values()  # fenêtre + retard toléré (M365 : jusqu'à 90 min)
    seq, params = sequence_query(RULES.by_id["UC-54"], since=95)
    assert 95 in params.values() and "ingest_ts >=" in seq
    # Premier passage (redémarrage) : toute la période scrutée
    _, params = sequence_query(RULES.by_id["UC-54"])
    assert list(params.values()).count(900 + LATE_SECONDS) == 2


# ---------- Nouvelles corrélations entre sources ----------

def test_cross_source_rules():
    for rule_id, join in (("UC-54", "user.name"), ("UC-55", "user.name"), ("UC-56", "host.name"),
                          ("UC-57", "user.name")):
        rule = RULES.by_id[rule_id]
        assert rule.type == "sequence" and rule.sequence.join_on == join and rule.mitre, rule_id
    assert RULES.by_id["UC-55"].severity == "critical"
    assert RULES.by_id["UC-57"].sequence.first["event.module"] == "sophos_xgs"
    assert RULES.by_id["UC-57"].sequence.then["event.module"] == "m365"


# ---------- Couverture antivirus et EDR ----------

def _inventory():
    from minisoc.coverage import Inventory, add_gravityzone, add_harfanglab, add_ninjaone

    now = datetime(2026, 10, 14, 12, tzinfo=timezone.utc)
    recent, old = now.timestamp() - 3600, now.timestamp() - 30 * 86400
    inv = Inventory()
    pairs = add_ninjaone(inv, [
        {"name": "PC-00605", "class": "WINDOWS_WORKSTATION", "last_contact": recent, "ip": "192.168.2.38"},
        {"name": "SRV-WSUS", "class": "WINDOWS_SERVER", "last_contact": recent},
        {"name": "PC-RETIRE", "class": "WINDOWS_WORKSTATION", "last_contact": old},
        {"name": "ESX-01", "class": "VMWARE_VM_HOST", "last_contact": recent},
        {"name": "PC-NEUF", "class": "WINDOWS_WORKSTATION", "last_contact": recent},
    ], now)
    pairs += add_harfanglab(inv, [
        {"hostname": "PC-00605", "lastseen": "2026-10-14T11:00:00Z", "ostype": "windows",
         "ipaddress": "192.168.2.38"},
        {"hostname": "SRV-WSUS", "lastseen": "2026-09-20T08:00:00Z", "ostype": "windows"},  # agent muet
        {"hostname": "PC-HL-SEUL", "lastseen": "2026-10-14T10:00:00Z", "ostype": "windows"},
        {"hostname": "LNX-01", "lastseen": "2026-10-14T10:00:00Z", "ostype": "linux"},
    ], now)
    pairs += add_gravityzone(inv, [
        {"name": "PC-00605", "isManaged": True, "managedWithBest": True, "ip": "192.168.2.38"},
        {"name": "SRV-WSUS.mairie.local", "isManaged": True},
        {"name": "PC-NEUF", "isManaged": False},  # découvert, sans agent
    ])
    return inv, pairs, now


def test_machines_without_antivirus_or_edr():
    from minisoc.coverage import NO_AV_RULE, NO_EDR_RULE, gaps

    inv, pairs, now = _inventory()
    found = gaps(inv, now)
    assert set(inv.alive) == {"pc-00605", "srv-wsus", "pc-neuf", "pc-hl-seul"}  # ni retirée, ni ESX, ni Linux
    assert {k: g["reason"] for k, g in found[NO_AV_RULE].items()} == {
        "pc-neuf": "non géré dans GravityZone (machine découverte, agent Bitdefender absent)",
        "pc-hl-seul": "absente de GravityZone",
    }
    assert {k: g["reason"] for k, g in found[NO_EDR_RULE].items()} == {
        "srv-wsus": "agent HarfangLab muet depuis 24 jours",
        "pc-neuf": "aucun agent HarfangLab",
    }
    assert found[NO_EDR_RULE]["srv-wsus"]["server"]
    assert ("PC-00605", "192.168.2.38") in [(n, ip) for n, ip, _ in pairs]  # table adresse → machine


def test_coverage_without_a_complete_list_concludes_nothing():
    from minisoc.coverage import NO_AV_RULE, NO_EDR_RULE, gaps

    inv, _, now = _inventory()
    inv.antivirus = None  # GravityZone illisible (clé sans l'API Réseau)
    found = gaps(inv, now)
    assert found[NO_AV_RULE] == {} and found[NO_EDR_RULE]
    for rule_id in (NO_AV_RULE, NO_EDR_RULE):
        rule = RULES.by_id[rule_id]
        assert rule.category == "hygiene" and "{threat.name}" in rule.title


def test_ninjaone_unknown_antivirus_is_not_an_absence():
    from minisoc.connectors.ninjaone import antivirus_state

    assert antivirus_state([{"productName": "NONE", "productState": "OFF"}]) == "unknown"
    assert antivirus_state([{"productName": "Windows Defender", "productState": "OFF"}], server=True) == "unknown"
    assert antivirus_state([{"productName": "Windows Defender", "productState": "OFF"}]) == "inactive"


# ---------- Une machine signalée par plusieurs outils ----------

def _tool_alert(alert_id, module, host="PC-00605", category=None):
    a = alert(alert_id, host=host, rule=f"détection {module}", severity=3, category=category)
    a.modules = [module]
    a.entity_key = f"event.module={module} | host.name={host} | rule.name=détection {module}"
    return a


def test_machine_flagged_by_several_tools(aliases):
    from minisoc.detections import priority, tools_by_host

    alerts = [_tool_alert(1, "harfanglab"), _tool_alert(2, "vectra", host="IP-192.168.2.38"),
              _tool_alert(3, "bitdefender", host="PC-00605.mairie.local"),
              _tool_alert(4, "ninjaone", category="hygiene"), _tool_alert(5, "harfanglab", host="PC-AUTRE")]
    tools = tools_by_host(alerts)
    assert tools["pc-00605"] == {"harfanglab", "vectra", "bitdefender"} and tools["pc-autre"] == {"harfanglab"}
    score, reasons = priority(alerts[0], {}, ["PC-00605"], now=NOW, tools=tools)
    assert {"label": "PC-00605 signalée par 3 outils (Bitdefender, HarfangLab, Vectra)", "points": 20} in reasons
    alone, _ = priority(alerts[4], {}, ["PC-AUTRE"], now=NOW, tools=tools)
    assert score - alone == 20
    machine = compute_risk(alerts, {}, now=NOW)[("host", "pc-00605")]
    assert machine.tools == {"harfanglab", "vectra", "bitdefender"}
    assert machine.to_dict()["corroboration"] == 20
    assert machine.score == 3 * 20 + 4 + 20  # trois menaces, l'hygiène (× 0,2), la corroboration
