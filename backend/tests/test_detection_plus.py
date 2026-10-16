"""Score de risque, chaînes d'attaque, leurres, DNS (analyseur et règles), exposition réelle."""

from datetime import datetime, timedelta, timezone

from minisoc.ecs import Event
from minisoc.models import Alert, Asset

NOW = datetime(2026, 10, 4, 12, 0, tzinfo=timezone.utc)


def alert(
    alert_id,
    host="PC-1",
    rule="Suspicious PowerShell script",
    severity=3,
    hours=1,
    category=None,
    tactics=(),
    rule_id="NATIVE",
    user=None,
    status="new",
):
    details = {"tactics": list(tactics)}
    if category:
        details["category"] = category
    if user:
        details["sample"] = {"user.name": user}
    return Alert(
        id=alert_id,
        rule_id=rule_id,
        entity_key=f"event.module=harfanglab | host.name={host} | rule.name={rule}",
        severity=severity,
        count=1,
        modules=["harfanglab"],
        status=status,
        details=details,
        first_seen=NOW - timedelta(hours=hours),
        last_seen=NOW - timedelta(hours=hours),
    )


# ---------- Score de risque ----------


def test_risk_counts_each_detection_once_and_weights_context():
    from minisoc.risk import compute_risk

    alerts = [
        alert(1, severity=3, tactics=["TA0002"]),
        alert(2, severity=3, tactics=["TA0002"], hours=30),  # même détection, autre jour : comptée une fois
        alert(3, rule="Registry Autorun Key Added", severity=2, tactics=["TA0003"]),
        alert(4, rule="Recommended driver block list", severity=4, category="hygiene"),
        alert(5, rule="Vieux", severity=4, hours=24 * 8),  # hors fenêtre de 7 jours
        alert(6, rule="FP", severity=4, status="false_positive"),
    ]
    risks = compute_risk(alerts, {}, now=NOW)
    risk = risks[("host", "pc-1")]
    # 20 (haute) + 8 (moyenne) + 40×0,2 (hygiène) + 10 (2 tactiques)
    assert round(risk.score) == 46 and len(risk.contributions) == 3
    assert {t["id"] for t in risk.to_dict()["tactics"]} == {"TA0002", "TA0003"}
    vital = compute_risk(alerts, {}, criticality=lambda k, n: "vital", now=NOW)[("host", "pc-1")]
    assert round(vital.score) == 69


def test_risk_halves_widespread_detections_and_follows_accounts():
    from minisoc.risk import compute_risk

    alerts = [alert(i, host=f"PC-{i}", rule="Recommended driver block list", severity=4) for i in range(25)]
    alerts.append(alert(99, host="SRV-1", rule="Kerberoasting", severity=3, rule_id="UC-30", user="MAIRIE\\j.dupont"))
    risks = compute_risk(alerts, {}, now=NOW)
    assert round(risks[("host", "pc-0")].score) == 20  # 40, répandue sur 25 machines : moitié
    assert ("user", "j.dupont") in risks and round(risks[("user", "j.dupont")].score) == 20


def test_attack_chain_needs_three_tactics_including_a_late_one():
    from minisoc.risk import find_chains

    early = [alert(1, rule="Scan", tactics=["TA0043"]), alert(2, rule="Phishing", tactics=["TA0001"])]
    assert find_chains(early, {}, now=NOW) == []
    chain_alerts = [
        *early,
        alert(3, rule="PowerShell", tactics=["TA0002"]),
        alert(4, rule="Hygiène", tactics=["TA0005"], category="hygiene"),  # catégorie ignorée
        alert(5, rule="Ancien", tactics=["TA0011"], hours=30),
    ]  # hors des 24 h
    [chain] = find_chains(chain_alerts, {}, now=NOW)
    assert chain.kind == "host" and chain.name == "PC-1" and chain.alert_ids == [1, 2, 3]
    assert chain.tactics == ["Reconnaissance", "Accès initial", "Exécution"]
    via_rules = find_chains(
        [
            alert(1, rule_id="UC-01", tactics=[]),
            alert(2, rule="b", tactics=["TA0002"]),
            alert(3, rule="c", tactics=["TA0011"]),
        ],
        {"UC-01": ["T1110"]},
        now=NOW,
    )
    assert via_rules and "Accès aux identifiants" in via_rules[0].tactics


def test_one_detection_counts_for_one_tactic():
    """UC-03 (T1110 + T1078.002 + T1133) couvre 5 tactiques à elle seule : des échecs d'authentification sur un même
    système ne sont pas une chaîne d'attaque, ni 5 tactiques au score de risque."""
    from minisoc.risk import compute_risk, distinct_tactics, find_chains

    mitre = {"UC-03a": ["T1110", "T1078.002", "T1133"], "UC-27": ["T1110"], "UC-26": ["T1110"]}
    auth = [
        alert(1, rule_id="UC-03a", rule="vpn"),
        alert(2, rule_id="UC-03a", rule="vpn", hours=2),
        alert(3, rule_id="UC-27", rule="admin"),
        alert(4, rule_id="UC-26", rule="service"),
        alert(5, rule_id="UC-27", rule="admin", hours=3),
    ]
    for a in auth:
        a.modules = ["windows"]
    assert find_chains(auth, mitre, now=NOW) == []
    assert len(compute_risk(auth, mitre, now=NOW)[("host", "pc-1")].tactics) == 2  # accès initial, identifiants
    # Trois détections différentes dont une étape avancée : chaîne, chaque étape annonce la tactique retenue
    [chain] = find_chains([*auth, alert(6, rule="PowerShell", tactics=["TA0002"])], mitre, now=NOW)
    assert len(chain.tactics) == 3 and "Exécution" in chain.tactics
    assert sum(1 for s in chain.steps if s["counted"]) == 3 and chain.steps[0]["rule_id"]
    # L'étape avancée est retenue même si un couplage plus grand sans elle existe
    assert set(distinct_tactics({"a": {"TA0001", "TA0006"}, "b": {"TA0001"}}, must={"TA0006"}).values()) == {
        "TA0001", "TA0006"}
    assert distinct_tactics({"a": {"TA0001"}, "b": {"TA0001"}}, must={"TA0006"}) == {}


def test_tactics_from_tool_tags():
    from minisoc.risk import tactics_from_raw, tactics_from_tags

    assert tactics_from_tags(["attack.discovery", "attack.t1087.002"]) == ["TA0007"]
    assert tactics_from_tags(["attack.t1110"]) == ["TA0006"]  # technique connue sans tactique explicite
    assert tactics_from_raw('{"tags": ["attack.persistence"]}') == ["TA0003"]
    assert tactics_from_raw("{tronqué") == []


# ---------- Leurres ----------


def test_decoys_match_accounts_paths_hosts_tokens():
    from minisoc.decoys import Decoys

    decoys = Decoys.from_cfg(
        {
            "decoy_accounts": ["adm-sauvegarde"],
            "decoy_paths": ["\\\\SRV-FS\\Paie_2026\\"],
            "decoy_hosts": ["10.0.0.99", "PC-LEURRE"],
            "decoy_tokens": ["Xk9!pAssLeurre", "court"],
        }
    )
    ev = lambda **kw: Event(ts=NOW, module="windows", **kw)  # noqa: E731
    assert decoys.match(ev(user_name="MAIRIE\\ADM-Sauvegarde")) == ("compte", "adm-sauvegarde")
    assert decoys.match(ev(file_path="\\\\srv-fs\\paie_2026\\salaires.xlsx")) == ("dossier", "srv-fs\\paie_2026")
    assert decoys.match(ev(destination_ip="10.0.0.99")) == ("machine", "10.0.0.99")
    assert decoys.match(ev(host_name="pc-leurre.mairie.local")) == ("machine", "pc-leurre")
    hit = decoys.match(ev(message="échec de connexion avec Xk9!pAssLeurre"))
    assert hit == ("chaîne", "Xk9!…")  # la valeur complète n'est jamais recopiée
    assert decoys.match(ev(message="mot court")) is None  # chaîne trop courte ignorée
    assert decoys.match(ev(user_name="j.dupont")) is None
    assert not Decoys.from_cfg({}).active


# ---------- DNS ----------


def test_dns_debug_and_etw_parsing():
    from minisoc.parsers.dispatch import parse_syslog
    from minisoc.parsers.dns import parse_dns_json, registered_domain

    line = (
        "4/10/2026 9:15:01 AM 0E1C PACKET  000001D2C3A4B5C6 UDP Rcv 192.168.10.21   1a2b   Q [0001   D   NOERROR] A"
        "      (3)www(7)exemple(4)gouv(2)fr(0)"
    )
    ev = parse_syslog({"message": line, "peer": "dc1", "received_at": NOW.isoformat()})
    assert ev.module == "dns" and ev.source_ip == "192.168.10.21" and ev.dns_query == "www.exemple.gouv.fr"
    assert ev.dns_domain == "exemple.gouv.fr" and ev.rule_name == "DNS A"
    response = line.replace("Rcv 192.168.10.21   1a2b   Q", "Snd 192.168.10.21   1a2b R Q")
    assert parse_syslog({"message": response, "peer": "dc1"}).action == "dns_other"
    etw = parse_dns_json(
        {
            "EventID": 256,
            "ProviderName": "Microsoft-Windows-DNSServer",
            "QNAME": "xk2q9vz7mw4tjp.top.",
            "Source": "10.1.1.5",
            "QTYPE": "1",
            "Hostname": "DC1",
        },
        NOW,
    )
    assert etw.dns_query == "xk2q9vz7mw4tjp.top" and etw.threat_name == "dga_suspect"
    assert registered_domain("a.b.example.co.uk") == "example.co.uk"
    assert registered_domain("10.1.168.192.in-addr.arpa") == "in-addr.arpa"


def test_dga_heuristic_spares_normal_names():
    from minisoc.parsers.dns import looks_generated

    assert looks_generated("qx7zk2vbn9wp4r.com")
    for name in ("mairie-exemple.fr", "microsoftonline.com", "service-public.fr", "cloudflare.com"):
        assert not looks_generated(name), name


def test_dns_rules_load_with_trusted_domains():
    from conftest import RULES_DIR

    from minisoc.rules import load_rules
    from minisoc.rules.filters import matches

    rules = {
        r.id: r
        for r in load_rules(
            RULES_DIR, strict=True, variables={"home_countries": ["FR"], "dns_trusted_domains": ["microsoft.com"]}
        )
    }
    dga = rules["UC-47"]
    base = dict(ts=NOW, module="dns", threat_name="dga_suspect", source_ip="10.1.1.5")
    assert matches(dga.filter, Event(**base, dns_domain="qx7zk2vbn9wp4r.com"))
    assert not matches(dga.filter, Event(**base, dns_domain="microsoft.com"))
    assert rules["UC-46"].condition.field == "dns.question.name"
    for template in ("UC-42", "UC-43", "UC-44", "UC-45"):  # modèles : jamais déclenchés par un événement
        assert not matches(rules[template].filter, Event(ts=NOW, module="windows"))


def test_ioc_domain_matches_subdomains_only():
    from minisoc.ioc import match_rows

    hits = match_rows(
        [(1, "domain", "evil.com")],
        [{"message": "10.1.1.5 → cdn.evil.com (A)", "raw": ""}, {"message": "10.1.1.5 → notevil.com (A)", "raw": ""}],
    )
    assert len(hits[1].events) == 1 and "cdn.evil.com" in hits[1].events[0]["message"]


# ---------- Exposition ----------


def test_exposure_ranks_and_explains():
    from minisoc.exposure import ranking

    postures = {
        "1": {
            "name": "PC-RH",
            "critical": 3,
            "high": 2,
            "antivirus": "inactive",
            "threats": 0,
            "failed": 1,
            "pending": 2,
        },
        "2": {"name": "PC-OK", "critical": 0, "high": 0, "antivirus": "ok", "threats": 0},
    }
    assets = [
        Asset(
            kind="host",
            name="pc-rh",
            display_name="PC-RH",
            criticality="vital",
            internet_exposed=True,
            owner="DRH",
            service="RH",
        )
    ]
    alerts = [alert(1, host="PC-RH", severity=4)]
    rows = ranking(postures, assets, alerts)
    assert [r["name"] for r in rows] == ["PC-RH"]  # PC-OK : rien à corriger
    top = rows[0]
    # (30 vulnérabilités critiques + 4 élevées + 5 en échec + 25 antivirus + 20 alerte critique) × 1,5 × 1,5
    assert top["score"] == round(84 * 1.5 * 1.5)
    assert "Réactiver la protection antivirus" in top["actions"] and top["internet_exposed"]


def test_risk_ignores_domains_builtin_accounts_and_storm_tactics():
    from minisoc.risk import compute_risk, find_chains

    alerts = [
        alert(1, user=r"MAIRIE\j.dupont"),
        alert(2, host="PC-2", rule="Pilote", user="MAIRIE"),  # ancienne alerte : le domaine à la place du compte
        alert(3, host="PC-3", rule="Script", user=r"NT AUTHORITY\SYSTEM"),
    ]
    risks = compute_risk(alerts, {}, now=NOW)
    assert ("user", "j.dupont") in risks
    assert ("user", "chatillon") not in risks and ("user", "system") not in risks
    storm = Alert(
        id=9,
        rule_id="NATIVE",
        entity_key="*regroupement*",
        severity=4,
        count=3,
        modules=["harfanglab"],
        status="new",
        first_seen=NOW,
        last_seen=NOW,
        details={
            "storm": True,
            "tactics": ["TA0002", "TA0003", "TA0011"],
            "entities": {
                "event.module=harfanglab | host.name=SRV-AUDIT | rule.name=PingCastle Execution": 1,
                "event.module=harfanglab | host.name=PC-9 | rule.name=Malware": 2,
            },
        },
    )
    assert find_chains([storm], {}, now=NOW) == []
    assert compute_risk([storm], {}, now=NOW)[("host", "srv-audit")].tactics == set()


def test_storm_alert_merges_with_the_same_detection_per_host():
    from minisoc.risk import compute_risk

    single = alert(1, host="PC-7", rule="Recommended driver block list", severity=4)
    storm = Alert(
        id=9,
        rule_id="NATIVE",
        entity_key="*regroupement*",
        severity=4,
        count=3,
        modules=["harfanglab"],
        status="new",
        first_seen=NOW,
        last_seen=NOW,
        details={
            "storm": True,
            "entities": {"event.module=harfanglab | host.name=PC-7 | rule.name=Recommended driver block list": 2},
        },
    )
    risk = compute_risk([single, storm], {}, now=NOW)[("host", "pc-7")]
    assert len(risk.contributions) == 1 and round(risk.score) == 40
