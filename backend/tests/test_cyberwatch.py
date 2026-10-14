"""Cyberwatch : CVE par actif croisées avec le catalogue KEV, changements seulement, règles UC-48/49/50, clôture."""

import base64
import json
from datetime import datetime, timezone

import httpx
import pytest
from conftest import RULES_DIR

from minisoc import cve
from minisoc.connectors import cyberwatch as cw
from minisoc.exposure import ranking
from minisoc.parsers import parse_message
from minisoc.rules import load_rules
from minisoc.rules.engine import RuleSet
from minisoc.source_sync import cyberwatch_closure
from minisoc.threat_feeds import KEV_KEY

CFG = {"cyberwatch_url": "https://cyberwatch.mairie.local/", "cyberwatch_access_key": "id",
       "cyberwatch_secret_key": "secret", "src_cyberwatch_enabled": True}
NOW = datetime(2026, 10, 7, 9, 0, tzinfo=timezone.utc)
SERVERS = [
    {"id": 4, "hostname": "SRV-WEB", "category": "server", "addresses": [{"value": "10.0.0.8"}],
     "os": {"name": "Ubuntu 20.04 LTS", "eol": "2025-04-01T02:00:00.000+02:00"},
     "cve_announcements_count": 3, "prioritized_cve_announcements_count": 2, "reboot_required": True,
     "analyzed_at": "2026-10-07T08:00:00.000+02:00", "groups": [{"name": "DMZ"}]},
    {"id": 7, "hostname": "PC-00100", "category": "server",
     "os": {"name": "Windows 11 Professionnel", "eol": "2031-10-14T00:00:00.000+02:00"},
     "cve_announcements_count": 1, "prioritized_cve_announcements_count": 1,
     "analyzed_at": "2026-10-07T08:00:00.000+02:00"},
]
DETAILS = {
    "4": {"cve_announcements": [
        {"cve_code": "CVE-2025-55182", "prioritized": True, "fixed_at": None, "ignored": False, "score": 10.0},
        {"cve_code": "CVE-2024-0001", "prioritized": True, "fixed_at": None, "ignored": False, "score": 7.5,
         "epss": 0.4},
        {"cve_code": "CVE-2023-1111", "prioritized": False, "fixed_at": "2026-01-01T00:00:00Z", "ignored": False},
        {"cve_code": "CVE-2023-2222", "prioritized": True, "fixed_at": None, "ignored": True},
    ]},
    "7": {"cve_announcements": [{"cve_code": "CVE-2025-55182", "prioritized": True, "fixed_at": None}]},
}


class FakeRedis:
    def __init__(self, kev=()):
        self.kv, self.hashes, self.stream = {}, {KEV_KEY: dict.fromkeys(kev, "{}")}, []

    async def hkeys(self, key):
        return list(self.hashes.get(key, {}))

    async def hgetall(self, key):
        return dict(self.hashes.get(key, {}))

    async def get(self, key):
        return self.kv.get(key)

    def pipeline(self, transaction=False):
        redis = self

        class Pipe:
            def delete(self, key):
                redis.hashes.pop(key, None)

            def hset(self, key, mapping):
                redis.hashes[key] = dict(mapping)

            def set(self, key, value):
                redis.kv[key] = value

            def xadd(self, stream, fields, **kw):
                redis.stream.append(fields)

            async def execute(self):
                return []

        return Pipe()


def handler(state):
    expected = "Basic " + base64.b64encode(b"id:secret").decode()

    def handle(request: httpx.Request) -> httpx.Response:
        assert request.method == "GET"  # lecture seule
        assert request.headers["authorization"] == expected
        path = request.url.path
        state.setdefault("calls", []).append(path)
        if path == "/api/v3/ping":
            return httpx.Response(200, json={"uuid": "x"})
        if path == "/api/v3/vulnerabilities/servers":
            items = state.get("servers", SERVERS)
            return httpx.Response(200, json=items, headers={"X-Total": str(len(items))})
        if path.startswith("/api/v3/vulnerabilities/servers/"):
            return httpx.Response(200, json=state.get("details", DETAILS)[path.rsplit("/", 1)[1]])
        return httpx.Response(404)

    return handle


def client(state):
    return httpx.AsyncClient(base_url=cw.base_url(CFG), auth=("id", "secret"),
                             transport=httpx.MockTransport(handler(state)))


def enrich_state(item, detail, kev):
    state = cw.asset_state(CFG, item, NOW)
    state["cves"], state["ignored"] = cw.active_cves(detail)
    return cw.enrich(state, kev)


def events(redis):
    return [parse_message("cyberwatch", f["payload"]) for f in redis.stream]


def test_asset_state_and_active_cves():
    state = cw.asset_state(CFG, SERVERS[0], NOW)
    assert (state["name"], state["server"], state["ip"], state["eol_passed"]) == ("SRV-WEB", True, "10.0.0.8", True)
    assert state["console"] == "https://cyberwatch.mairie.local/servers/4" and state["groups"] == ["DMZ"]
    assert not cw.asset_state(CFG, SERVERS[1], NOW)["server"]  # Windows client : poste malgré la catégorie
    active, ignored = cw.active_cves(DETAILS["4"])
    assert set(active) == {"CVE-2025-55182", "CVE-2024-0001"} and ignored == ["CVE-2023-2222"]
    assert active["CVE-2024-0001"] == [7.5, 0.4, 1]


async def test_first_pass_is_a_silent_baseline_then_changes_alert():
    redis, state = FakeRedis(kev=["CVE-2025-55182"]), {}
    connector = cw.CyberwatchConnector(None, redis)
    async with client(state) as http:
        assert await connector.poll(http, CFG) == 0  # état des lieux : aucune alerte
    summary = json.loads(redis.kv[cw.SUMMARY_KEY])
    assert (summary["assets"], summary["with_kev"], summary["kev_cves"], summary["eol"]) == (2, 2, 1, 1)
    assert summary["exposed"][0]["name"] == "SRV-WEB" and "cves" not in summary["exposed"][0]

    # Rien n'a changé : pas d'événement, et les CVE ne sont pas relues
    state["calls"].clear()
    async with client(state) as http:
        assert await connector.poll(http, CFG) == 0
    assert state["calls"] == ["/api/v3/vulnerabilities/servers"]

    # Réanalyse : nouvelle faille KEV sur le poste et sur le serveur, nouvelle prioritaire sur les deux
    state["servers"] = [
        {**SERVERS[0], "cve_announcements_count": 4, "analyzed_at": "2026-10-07T10:00:00.000+02:00"},
        {**SERVERS[1], "cve_announcements_count": 3, "analyzed_at": "2026-10-07T10:00:00.000+02:00"},
    ]
    state["details"] = {
        "4": {"cve_announcements": DETAILS["4"]["cve_announcements"] + [
            {"cve_code": "CVE-2026-9999", "prioritized": True}, {"cve_code": "CVE-2026-1000", "prioritized": True}]},
        "7": {"cve_announcements": [{"cve_code": "CVE-2025-55182", "prioritized": True},
                                    {"cve_code": "CVE-2026-9999", "prioritized": False},
                                    {"cve_code": "CVE-2026-1000", "prioritized": True}]},
    }
    redis.hashes[KEV_KEY]["CVE-2026-9999"] = "{}"
    async with client(state) as http:
        assert await connector.poll(http, CFG) == 3
    got = {(e.host_name, e.action, e.severity, e.threat_name) for e in events(redis)}
    assert got == {
        ("SRV-WEB", "kev_vulnerabilities", 3, "CVE-2026-9999"),
        ("SRV-WEB", "prioritized_vulnerabilities", 2, "CVE-2026-1000"),
        ("PC-00100", "kev_vulnerabilities", 2, "CVE-2026-9999"),  # poste : KEV oui, prioritaires non
    }
    kev = next(e for e in events(redis) if e.host_name == "SRV-WEB" and e.action == "kev_vulnerabilities")
    assert kev.reference.endswith("/servers/4")


def test_triaged_cves_are_not_present():
    active, ignored = cw.active_cves({"cve_announcements": [
        {"cve_code": "CVE-2026-0001", "active": True, "triage_status": "untriaged"},
        {"cve_code": "CVE-2026-0002", "active": True, "triage_status": "ignored"},
        {"cve_code": "CVE-2026-0003", "active": True, "triage_status": "risk_accepted"},
        {"cve_code": "CVE-2026-0004", "active": False, "fixed_at": "2026-01-01T00:00:00Z"},
    ]})
    assert list(active) == ["CVE-2026-0001"] and ignored == ["CVE-2026-0002", "CVE-2026-0003"]


async def test_kev_catalog_update_is_applied_without_rereading_cves():
    redis, state = FakeRedis(), {}
    connector = cw.CyberwatchConnector(None, redis)
    async with client(state) as http:
        await connector.poll(http, CFG)
    redis.hashes[KEV_KEY] = {"CVE-2024-0001": "{}"}  # la CVE entre au catalogue KEV
    state["calls"].clear()
    async with client(state) as http:
        await connector.poll(http, CFG)
    assert state["calls"] == ["/api/v3/vulnerabilities/servers"]
    assert [(e.host_name, e.threat_name) for e in events(redis) if e.action == "kev_vulnerabilities"] == [
        ("SRV-WEB", "CVE-2024-0001")]


async def test_rules_and_connection_test(monkeypatch):
    rs = RuleSet(load_rules(RULES_DIR))
    state = enrich_state(SERVERS[0], DETAILS["4"], {"CVE-2025-55182"})
    records = [{"type": "posture", "kind": k, "asset_id": "4", "cves": c, "asset": state}
               for k, c in (("kev_vulnerabilities", ["CVE-2025-55182"]),
                            ("prioritized_vulnerabilities", ["CVE-2024-0001"]), ("os_end_of_life", []))]
    evs = [parse_message("cyberwatch", json.dumps(r)) for r in records]
    matched = {e.action: {r.id for r in rs.match(e)} for e in evs}
    assert "UC-48" in matched["kev_vulnerabilities"] and "UC-22" not in matched["kev_vulnerabilities"]
    assert "UC-49" in matched["prioritized_vulnerabilities"] and "UC-50" in matched["os_end_of_life"]

    real = httpx.AsyncClient

    def mocked(**kw):
        kw.pop("verify", None)
        return real(**kw, transport=httpx.MockTransport(handler({})))

    monkeypatch.setattr(cw.httpx, "AsyncClient", mocked)
    ok, detail = await cw.test(CFG)
    assert ok and "2 actif(s)" in detail
    assert (await cw.test({}))[0] is False


def test_closure_when_cves_fixed_or_ignored():
    record = {"type": "posture", "kind": "kev_vulnerabilities", "asset_id": "4", "cves": ["CVE-2025-55182"]}
    still = {"4": {"cves": {"CVE-2025-55182": [10.0, None, 1]}, "ignored": []}}
    assert cyberwatch_closure([record], "kev_vulnerabilities", still) is None
    assert cyberwatch_closure([record], "kev_vulnerabilities", {}) is None  # actif absent : on ne conclut pas
    assert cyberwatch_closure([record], "kev_vulnerabilities", None) is None
    fixed = cyberwatch_closure([record], "kev_vulnerabilities", {"4": {"cves": {}, "ignored": []}})
    assert fixed.tool == "Cyberwatch" and fixed.status == "resolved" and "1 CVE corrigée" in fixed.label
    ignored = cyberwatch_closure([record], "kev_vulnerabilities", {"4": {"cves": {}, "ignored": ["CVE-2025-55182"]}})
    assert "ignorée" in ignored.label and "risque accepté" in ignored.label
    eol = {"type": "posture", "kind": "os_end_of_life", "asset_id": "4", "cves": []}
    assert cyberwatch_closure([eol, record], "os_end_of_life", {"4": {"cves": {}, "eol_passed": True}}) is None
    upgraded = {"4": {"cves": {}, "eol_passed": False, "os": "Ubuntu 24.04"}}
    upgraded = cyberwatch_closure([eol], "os_end_of_life", upgraded)
    assert "Ubuntu 24.04" in upgraded.label


def test_exposure_counts_present_kev_once():
    states = {"4": cw.enrich({**cw.asset_state(CFG, SERVERS[0], NOW), "cves": cw.active_cves(DETAILS["4"])[0],
                              "ignored": []}, {"CVE-2025-55182"})}
    [row] = ranking({}, [], [], 10, states)
    labels = " | ".join(r["label"] for r in row["reasons"])
    assert row["name"] == "SRV-WEB" and row["has_posture"] and row["console"].endswith("/servers/4")
    assert "1 faille(s) activement exploitée(s) présente(s)" in labels and "fin de support" in labels
    assert "Corriger en urgence les failles KEV présentes (Cyberwatch)" in row["actions"]
    assert row["score"] == 20 + 3 + 10 + 2


# ---------- Recherche par CVE ----------


def test_cve_normalize_and_fleet():
    assert cve.normalize(" cve-2024-3400 ") == "CVE-2024-3400"
    with pytest.raises(ValueError):
        cve.normalize("CVE-24-1")
    states = {
        "4": enrich_state(SERVERS[0], DETAILS["4"], {"CVE-2025-55182"}),
        "7": enrich_state(SERVERS[1], DETAILS["7"], {"CVE-2025-55182"}),
    }
    rows = cve.fleet(states, {"CVE-2025-55182"})
    assert rows[0] == {"cve": "CVE-2025-55182", "machines": 2, "servers": 1, "prioritized": 2, "score": 10.0,
                       "kev": True, "sample": ["PC-00100", "SRV-WEB"]}
    found = {m["name"]: m["status"] for m in cve.from_states(states, "CVE-2023-2222")}
    assert found == {"SRV-WEB": "ignored"}


async def test_cve_lookup_live_then_fallback(monkeypatch):
    live = {"cve_code": "CVE-2025-55182", "content": "RCE React Server Components", "score": 10.0,
            "level": "level_critical", "epss": 0.9, "catalogs": [],
            "security_announcements": [{"sa_code": "CERTFR-2025-ALE-015", "type": "SecurityAnnouncements::Anssi",
                                        "link": "https://www.cert.ssi.gouv.fr/alerte/CERTFR-2025-ALE-015/"}],
            "servers": [
                {"id": 4, "hostname": "SRV-WEB", "os": {"name": "Ubuntu 20.04 LTS"}, "active": True,
                 "triage_status": "untriaged", "fixed_at": None, "detected_at": "2026-10-01T10:00:00+02:00",
                 "prioritized": True, "environmental_score": 9.5},
                {"id": 9, "hostname": "SRV-OLD", "os": {"name": "Windows Server 2019"}, "active": False,
                 "fixed_at": "2026-10-05T10:00:00+02:00", "triage_status": "untriaged"},
                {"id": 7, "hostname": "PC-00100", "os": {"name": "Windows 11"}, "active": True,
                 "triage_status": "risk_accepted"},
            ]}

    def handle(request):
        if request.url.path.endswith("/CVE-2025-55182"):
            return httpx.Response(200, json=live)
        return httpx.Response(404)

    real = httpx.AsyncClient

    def mocked(**kw):
        kw.pop("verify", None)
        return real(**kw, transport=httpx.MockTransport(handle))

    monkeypatch.setattr(cw.httpx, "AsyncClient", mocked)
    result = await cve.cyberwatch_lookup(CFG, {}, "CVE-2025-55182")
    assert result["live"] and result["info"]["level"] == "critique"
    assert result["info"]["certfr"][0]["code"] == "CERTFR-2025-ALE-015"
    status = {m["name"]: (m["status"], m["server"]) for m in result["machines"]}
    assert status == {"SRV-WEB": ("vulnerable", True), "SRV-OLD": ("fixed", True), "PC-00100": ("ignored", False)}
    unknown = await cve.cyberwatch_lookup(CFG, {}, "CVE-2020-0001")
    assert unknown["live"] and unknown["known"] is False

    def down(**kw):
        kw.pop("verify", None)
        return real(**kw, transport=httpx.MockTransport(lambda r: (_ for _ in ()).throw(httpx.ConnectError("x"))))

    monkeypatch.setattr(cw.httpx, "AsyncClient", down)
    states = {"4": enrich_state(SERVERS[0], DETAILS["4"], set())}
    fallback = await cve.cyberwatch_lookup(CFG, states, "CVE-2025-55182")
    assert not fallback["live"] and [m["name"] for m in fallback["machines"]] == ["SRV-WEB"]
    assert (await cve.cyberwatch_lookup({}, states, "CVE-2025-55182"))["configured"] is False


def test_merge_inventory_orders_vulnerable_critical_servers_first():
    machines = [
        {"name": "PC-1", "server": False, "status": "vulnerable"},
        {"name": "SRV-B", "server": True, "status": "fixed"},
        {"name": "SRV-A", "server": True, "status": "vulnerable"},
    ]
    assert [m["name"] for m in cve.merge_inventory(machines, None)] == ["SRV-A", "PC-1", "SRV-B"]


def test_pending_updates_ranked_and_listed_per_host():
    detail = {
        "updates": [
            {"ignored": False, "patchable": False,
             "current": {"product": "linux-image-generic", "version": "6.8.0-134.^"},
             "target": {"product": "linux-image-generic", "version": "6.8.0-142.142"},
             "cve_announcements": ["CVE-2025-0001", "CVE-2025-0002", "CVE-2020-9999"]},
            {"ignored": False, "patchable": True,
             "current": {"vendor": "apache", "product": "httpd", "version": "2.4.49"},
             "target": {"vendor": "apache", "product": "httpd", "version": "2.4.51"},
             "cve_announcements": [{"cve_code": "cve-2021-41773"}]},
            {"ignored": True, "current": {"product": "écarté"}, "target": {}, "cve_announcements": []},
        ]
    }
    active = {"CVE-2025-0001": [7.8, 0.01, 0], "CVE-2025-0002": [5.5, 0.01, 1], "CVE-2021-41773": [7.5, 0.9, 1]}
    updates = cw.pending_updates(detail, active)
    assert [u["product"] for u in updates] == ["linux-image-generic", "apache httpd"]
    assert updates[0]["from"] == "6.8.0-134" and updates[0]["cves"] == ["CVE-2025-0001", "CVE-2025-0002"]

    state = {"name": "SRV-REVERSE", "cves": active, "updates": updates, "os": "Ubuntu", "reboot_required": True}
    ranked = cw.patches(state, kev={"CVE-2021-41773"})
    assert ranked[0]["product"] == "apache httpd" and ranked[0]["kev"] == ["CVE-2021-41773"]
    assert ranked[1]["cves"] == 2 and ranked[1]["prioritized"] == 1 and ranked[1]["max_score"] == 7.8

    state["patches"] = ranked
    hosts = cw.hosts_patches({"52": state}, ["srv-reverse.chatillon.lan", "inconnue"])
    assert list(hosts) == ["srv-reverse.chatillon.lan"]
    assert hosts["srv-reverse.chatillon.lan"]["known"] and hosts["srv-reverse.chatillon.lan"]["patches_total"] == 2
    assert "updates" not in cw._public(state)


def test_mentioned_hosts_found_in_question():
    from minisoc.ai.context import mentioned_hosts

    known = {"ptb-00612", "srv-reverse", "srv-rds01"}
    question = "que faire sur le PTB-00612 ? et srv-reverse.chatillon.lan, puis PTB-00612 encore"
    assert mentioned_hosts(question, known) == ["ptb-00612", "srv-reverse"]
    assert mentioned_hosts("rien à voir", known) == []
