"""OGO Security (WAF) lu par l'API v2 (flux sortant seulement) : signature, journal, état des sites, règles, test."""

import hashlib
import json
from datetime import datetime, timezone

import httpx
from conftest import RULES_DIR
from test_saas_connectors import FakeRedis, events

from minisoc.connectors import ogo
from minisoc.parsers.ogo import action_name
from minisoc.rules import load_rules
from minisoc.rules.engine import RuleSet

NOW = datetime(2026, 10, 16, 12, 0, tzinfo=timezone.utc)
RULES = RuleSet(load_rules(RULES_DIR))
CFG = {"ogo_email": "soc@mairie.fr", "ogo_api_key": "cle-ogo"}

JOURNAL = [
    {"id": 501, "type": "SECURITY", "subtype": "highBannedVolume", "subtypeLabel": "High banned volume",
     "severity": 3, "date": "2026-10-16T11:40:00Z", "site": "www.mairie.fr", "clusterUid": "c1",
     "event": {"bannedCount": 1840, "topIps": [{"ip": "203.0.113.7", "count": 900}]}},
    {"id": 502, "type": "SECURITY", "subtype": "newIpBlocked", "severity": 1, "date": "2026-10-16T11:41:00Z",
     "site": "www.mairie.fr", "event": {"ip": "198.51.100.4"}},
    {"id": 503, "type": "ACTIVITY", "subtype": "userRoleChange", "severity": 2, "date": "2026-10-16T11:45:00Z",
     "site": None, "event": {"user": {"email": "prestataire@agence.fr"}, "role": "OWNER"}},
    {"id": 504, "type": "MONITORING", "subtype": "customerCertificateExpiresSoon", "severity": 2,
     "date": "2026-10-16T11:50:00Z", "site": "extranet.mairie.fr", "event": {"daysLeft": 7}},
    {"id": 505, "type": "ACTIVITY", "subtype": "sitePurgeCache", "severity": 1, "date": "2026-10-16T11:55:00Z",
     "site": "www.mairie.fr", "event": {}},
]
SITES = {
    "www.mairie.fr": {"domainName": "www.mairie.fr", "status": "ONLINE", "auditMode": False,
                      "passthroughMode": False, "mode": "BASIC", "cluster": {"uid": "c1", "name": ".OGO EUW2"}},
    "extranet.mairie.fr": {"domainName": "extranet.mairie.fr", "status": "CUST_CERT", "auditMode": False,
                           "passthroughMode": True, "mode": "BASIC", "cluster": {"uid": "c1", "name": ".OGO EUW2"}},
}


def handler(state):
    state.setdefault("calls", [])

    def handle(request: httpx.Request):
        path = request.url.path
        state["calls"].append((path, dict(request.url.params)))
        expected = hashlib.md5(f"{path}-cle-ogo".encode()).hexdigest()  # noqa: S324 - schéma imposé par OGO
        if request.headers.get("x-ogo-auth") != f"soc@mairie.fr;{expected}":
            return httpx.Response(401, json={"message": "User not authenticated"})
        assert request.method == "GET" and request.url.host == "api.ogosecurity.com"
        assert "cle-ogo" not in str(request.url) and "cle-ogo" not in str(request.headers)
        if path == "/v2/organizations":
            return httpx.Response(200, json={"content": [{"organization": {"code": "mairie", "name": "Mairie"},
                                                          "role": "VIEWER"}], "last": True})
        assert path.startswith("/v2/organizations/mairie/")
        if path.endswith("/journal"):
            after = datetime.fromisoformat(request.url.params["after"].replace("Z", "+00:00"))
            rows = [e for e in JOURNAL if datetime.fromisoformat(e["date"].replace("Z", "+00:00")) >= after]
            page, size = int(request.url.params["page"]), int(request.url.params["size"])
            chunk = rows[page * size:(page + 1) * size]
            return httpx.Response(200, json={"content": chunk, "totalElements": len(rows),
                                             "last": (page + 1) * size >= len(rows)})
        if path.endswith("/clusters"):
            return httpx.Response(200, json=[{"cluster": {"uid": "c1", "name": ".OGO EUW2"}, "role": "USE"},
                                             {"cluster": {"uid": "c2", "name": ".OGO EUW1"}, "role": "USE"}])
        if "/metrics/" in path:
            params = request.url.params
            assert params["cluster"] in ("c1", "c2") and params["fromDate"].endswith("Z")
            state.setdefault("metrics", []).append((path.split("/metrics/")[1], dict(params)))
            if params["cluster"] == "c2":
                return httpx.Response(200, json={} if path.endswith("count") else {"datas": [], "total": 0})
            if params.get("ip.in") == "45.9.20.9":  # adresse inconnue des sites
                return httpx.Response(200, json={"traffic": {"total": 0, "bySite": {}}} if path.endswith("count")
                                      else {"datas": [], "total": 0})
            if path.endswith("traffic/count"):
                return httpx.Response(200, json={
                    "traffic": {"total": 1200, "bySite": {"www.mairie.fr": 1000, "extranet.mairie.fr": 200}},
                    "blocked": {"total": 150, "bySite": {"www.mairie.fr": 30, "extranet.mairie.fr": 120}},
                    "banned": {"total": 40, "bySite": {"extranet.mairie.fr": 40}},
                    "suspect": {"total": 5, "bySite": {"www.mairie.fr": 5}}})
            return httpx.Response(200, json={"datas": [{"uid": "sqli", "name": "SQL injection", "value": 90},
                                                       {"uid": "scan", "name": "Scanner", "value": 60}], "total": 150})
        if path.endswith("/sites"):
            return httpx.Response(200, json={"content": [{"domainName": d} for d in SITES], "last": True})
        domain = path.rsplit("/", 1)[-1]
        return httpx.Response(200, json=state.get("sites", SITES)[domain])

    return handle


def client(state, cfg=CFG):
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler(state)))
    return http, ogo.OgoClient(cfg, http)


def test_action_names():
    assert action_name("highBannedVolume") == "high_banned_volume"
    assert action_name("tlsOptions.create") == "tls_options.create"
    assert action_name("increased5xxRate") == "increased5xx_rate" and action_name("4XX") == "4xx"


async def test_ogo_journal_cursor_parse_and_rules():
    redis, state = FakeRedis(), {}
    http, api = client(state)
    async with http:
        connector = ogo.OgoConnector(None, redis)
        assert await connector.poll(api, now=NOW) == 5
        assert await connector.poll(api, now=NOW) == 0  # déjà lus (marge de relecture écartée)
    journal = [c for c in state["calls"] if c[0].endswith("/journal")]
    assert journal[0][1]["after"] == "2026-10-09T12:00:00Z" and journal[0][1]["sort"] == "date,asc"
    assert journal[-1][1]["after"] == "2026-10-16T11:50:00Z"  # dernier lu moins 5 min
    assert redis.kv[ogo.CURSOR_KEY] == "2026-10-16T11:55:00+00:00"

    attack, banned, role, cert, purge = events(redis, "ogo")
    assert (attack.kind, attack.severity, attack.action, attack.host_name, attack.source_ip) == (
        "alert", 3, "high_banned_volume", "www.mairie.fr", "203.0.113.7")
    assert {r.id for r in RULES.match(attack)} >= {"UC-17"}
    assert (banned.kind, banned.source_ip) == ("event", "198.51.100.4") and not RULES.match(banned)
    assert (role.kind, role.user_name, role.category) == ("event", "prestataire", "configuration")
    assert "UC-60" in {r.id for r in RULES.match(role)}
    assert (cert.kind, cert.severity, cert.host_name) == ("alert", 2, "extranet.mairie.fr")
    assert "NATIVE" in {r.id for r in RULES.match(cert)}
    assert (purge.kind, purge.severity) == ("event", 0) and not RULES.match(purge)


async def test_ogo_sites_published_on_change_only():
    redis, state = FakeRedis(), {}
    http, api = client(state)
    async with http:
        connector = ogo.OgoConnector(None, redis)
        assert await connector.check_sites(api, now=NOW) == 2
        assert await connector.check_sites(api, now=NOW) == 0  # moins d'une heure : pas relu
        assert await connector.check_sites(api, now=NOW, force=True) == 0  # inchangés
        state["sites"] = {**SITES, "extranet.mairie.fr": {**SITES["extranet.mairie.fr"], "passthroughMode": False}}
        assert await connector.check_sites(api, now=NOW, force=True) == 1
    www, passthrough, restored = events(redis, "ogo")
    assert (www.kind, www.action) == ("event", "site_state") and not RULES.match(www)
    assert (passthrough.kind, passthrough.action, passthrough.severity) == ("alert", "site_passthrough", 3)
    assert "UC-60" in {r.id for r in RULES.match(passthrough)} and ".OGO EUW2" in passthrough.message
    assert restored.action == "site_state" and "protection rétablie" in restored.message


async def test_ogo_connection_test(monkeypatch):
    real = httpx.AsyncClient
    monkeypatch.setattr(ogo, "make_http", lambda cfg: real(transport=httpx.MockTransport(handler({}))))
    ok, detail = await ogo.test(CFG)
    assert ok and "organisation mairie" in detail and "2 site(s)" in detail
    assert (await ogo.test({}))[0] is False
    ok, detail = await ogo.test({**CFG, "ogo_api_key": "mauvaise"})
    assert not ok and "refusés" in detail


async def test_ogo_several_organizations_need_a_code():
    def handle(request):
        return httpx.Response(200, json={"content": [{"organization": {"code": "a"}},
                                                     {"organization": {"code": "b"}}]})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        try:
            await ogo.OgoClient(CFG, http).org()
        except ogo.OgoError as exc:
            assert "a, b" in str(exc)
        else:
            raise AssertionError("organisation choisie au hasard")
        assert await ogo.OgoClient({**CFG, "ogo_organization": "b"}, http).org() == "b"


def test_ogo_settings_validation():
    from minisoc.settings_store import SettingsError, validate

    assert validate("ogo_api_url", "https://api.ogosecurity.com") == "https://api.ogosecurity.com"
    try:
        validate("ogo_api_url", "http://api.ogosecurity.com")
    except SettingsError:
        pass
    else:
        raise AssertionError("adresse en clair acceptée")
    assert json.dumps(ogo.site_state(SITES["www.mairie.fr"]))  # sérialisable (comparaison des états)


async def test_ogo_summary_by_site_and_cache():
    redis, state = FakeRedis(), {}
    http, api = client(state)
    async with http:
        connector = ogo.OgoConnector(None, redis)
        await connector.check_sites(api, now=NOW)
        summary = await connector.refresh_summary(api, now=NOW)
        assert await connector.refresh_summary(api, now=NOW) is None  # moins d'un quart d'heure : pas relu
    assert summary["totals"] == {"traffic": 1200, "blocked": 150, "banned": 40, "suspect": 5, "robot": 0, "analyzed": 0}
    first = summary["sites"][0]
    assert first["site"] == "extranet.mairie.fr" and first["blocked"] == 120 and first["state"]["passthroughMode"]
    assert summary["categories"][0] == {"name": "SQL injection", "count": 90}
    assert json.loads(redis.kv[ogo.SUMMARY_KEY])["organization"] == "mairie"
    assert all("ip.in" not in p for _, p in state["metrics"])


async def test_ogo_ip_activity(monkeypatch):
    real = httpx.AsyncClient
    state = {}
    monkeypatch.setattr(ogo, "make_http", lambda cfg: real(transport=httpx.MockTransport(handler(state))))
    redis = FakeRedis()
    seen = await ogo.ip_activity(CFG, redis, "45.9.20.1", now=NOW)
    assert seen["totals"]["blocked"] == 150 and seen["days"] == 7 and seen["ip"] == "45.9.20.1"
    assert {p["ip.in"] for _, p in state["metrics"]} == {"45.9.20.1"}
    assert {p["fromDate"] for _, p in state["metrics"]} == {"2026-10-09T12:00:00Z"}
    calls = len(state["metrics"])
    assert (await ogo.ip_activity(CFG, redis, "45.9.20.1", now=NOW))["totals"]["traffic"] == 1200
    assert len(state["metrics"]) == calls  # en cache
    unknown = await ogo.ip_activity(CFG, redis, "45.9.20.9", now=NOW)
    assert unknown["totals"]["traffic"] == 0 and unknown["sites"] == []
