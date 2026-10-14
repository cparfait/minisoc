"""Varonis SaaS et GravityZone lus par l'API (flux sortants seulement) : relevé, analyse, règles, clôture."""

import json
from datetime import datetime, timedelta, timezone

import httpx
from conftest import RULES_DIR

from minisoc.connectors import gravityzone as gz
from minisoc.connectors import varonis as vr
from minisoc.parsers import parse_message
from minisoc.rules import load_rules
from minisoc.rules.engine import RuleSet
from minisoc.source_sync import gravityzone_closure, gravityzone_ids, varonis_closure, varonis_ids

NOW = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)
RULES = RuleSet(load_rules(RULES_DIR))


class FakeRedis:
    def __init__(self):
        self.kv, self.stream = {}, []

    async def get(self, key):
        return self.kv.get(key)

    async def set(self, key, value, nx=False, ex=None):
        if nx and key in self.kv:
            return None
        self.kv[key] = value
        return True

    def pipeline(self, transaction=False):
        redis = self

        class Pipe:
            def xadd(self, stream, fields, **kw):
                redis.stream.append(fields)

            async def execute(self):
                return []

        return Pipe()


def events(redis, kind):
    return [parse_message(kind, f["payload"]) for f in redis.stream]


# ---------- Varonis ----------

VCFG = {"varonis_url": "mairie.varonis.io", "varonis_api_key": "k"}
COLUMNS = ["Alert.ID", "Alert.Rule.Name", "Alert.Rule.Severity.Name", "Alert.Rule.Category.Name", "Alert.TimeUTC",
           "Alert.IngestTime", "Alert.Status.Name", "Alert.CloseReason.Name", "Alert.EventsCount",
           "Alert.User.SamAccountName", "Alert.Device.HostName", "Alert.Filer.Name", "Alert.Filer.Platform.Name",
           "Alert.Asset.Path", "Alert.Data.IsSensitive", "Alert.MitreTactic.Name"]
ALERTS = [
    ["A1", "Abnormal service ticket requests (Kerberoasting)", "High", "Credential Access", "2026-10-07T10:00:00",
     "2026-10-07T10:42:00", "New", "None", "12", "j.dupont", "PTB-00100", "DC01", "Active Directory", "", "No",
     "Credential Access"],
    ["A2", "Encryption of multiple files (ransomware)", "High", "Impact", "2026-10-07T11:00:00",
     "2026-10-07T11:03:00", "Under Investigation", "None", "540", "a.martin", "PTB-00200", "FS01", "Windows",
     "\\\\FS01\\Partages\\RH", "Yes", "Impact"],
]


def varonis_handler(state):
    def handle(request: httpx.Request) -> httpx.Response:
        state.setdefault("calls", []).append((request.method, request.url.path))
        path = request.url.path
        if path == "/api/authentication/api_keys/token":
            assert request.headers["x-api-key"] == "k" and request.content == b"grant_type=varonis_custom"
            return httpx.Response(200, json={"access_token": "t", "token_type": "Bearer", "expires_in": 3600})
        assert request.headers["authorization"] == "Bearer t"
        if path == "/app/dataquery/api/search/v2/search":
            body = json.loads(request.content)
            state.setdefault("bodies", []).append(body)
            return httpx.Response(200, json=[{"location": "abc"}])
        if path == "/app/dataquery/api/search/abc":
            state["polls"] = state.get("polls", 0) + 1
            if state["polls"] == 1:
                return httpx.Response(206)  # calcul en cours
            rows = state.get("rows", ALERTS)
            return httpx.Response(200, json={"columns": COLUMNS, "rows": rows})
        return httpx.Response(404)

    return handle


def varonis_api(state):
    http = httpx.AsyncClient(transport=httpx.MockTransport(varonis_handler(state)))
    return http, vr.VaronisClient(VCFG, http)


async def test_varonis_poll_parse_and_rules(monkeypatch):
    monkeypatch.setattr(vr.asyncio, "sleep", lambda s: _noop())
    redis, state = FakeRedis(), {}
    http, api = varonis_api(state)
    async with http:
        assert await vr.VaronisConnector(None, redis).poll(api, VCFG, now=NOW) == 2
        assert await vr.VaronisConnector(None, redis).poll(api, VCFG, now=NOW) == 0  # déjà lues
    assert all(method in ("GET", "POST") for method, _ in state["calls"])  # recherches seulement
    body = state["bodies"][0]
    assert body["query"]["entityName"] == "Alert"
    window = body["query"]["filter"]["filters"][1]
    assert window["path"] == "Alert.IngestTime" and window["operator"] == "Between"
    assert window["values"][0]["Alert.IngestTime"] == "2026-09-30T12:00:00"  # premier passage : 7 jours
    assert redis.kv[vr.CURSOR_KEY] == "2026-10-07T11:59:00"
    kerb, ransom = events(redis, "varonis")
    assert (kerb.module, kerb.kind, kerb.severity, kerb.user_name, kerb.host_name) == (
        "varonis", "alert", 3, "j.dupont", "PTB-00100")
    assert kerb.category == "iam" and "42 min après l'activité" in kerb.message
    assert kerb.reference == "https://mairie.varonis.io/analytics/entity/Alert/A1"
    assert json.loads(kerb.raw)["tags"] == ["attack.credential_access"]
    assert (ransom.action, ransom.severity, ransom.file_path) == ("ransomware_detected", 4, "\\\\FS01\\Partages\\RH")
    assert "UC-06" in {r.id for r in RULES.match(ransom)}
    assert "NATIVE" in {r.id for r in RULES.match(kerb)}


async def _noop():
    return None


def test_varonis_closure():
    records = [json.loads(json.dumps(vr.record(VCFG, dict(zip(COLUMNS, row, strict=False))))) for row in ALERTS]
    ids = varonis_ids(records)
    assert ids == ["A1", "A2"]
    rows = {r[0]: dict(zip(COLUMNS, r, strict=False)) for r in ALERTS}
    assert varonis_closure(ids, rows) is None  # encore ouvertes
    rows["A1"].update({"Alert.Status.Name": "Closed", "Alert.CloseReason.Name": "Authorized Activity"})
    assert varonis_closure(ids, rows) is None  # A2 encore en investigation
    rows["A2"].update({"Alert.Status.Name": "Closed", "Alert.CloseReason.Name": "True Positive"})
    closure = varonis_closure(ids, rows)
    assert closure.tool == "Varonis" and closure.status == "resolved" and "True Positive" in closure.label
    benign = varonis_closure(["A1"], rows)
    assert benign.status == "false_positive"
    assert varonis_closure(["A1", "A3"], rows) is None  # alerte introuvable : on ne conclut pas
    assert varonis_ids([{"type": "alert", "alert": {}}]) == []


async def test_varonis_connection_test(monkeypatch):
    real = httpx.AsyncClient
    monkeypatch.setattr(vr, "make_http", lambda cfg: real(transport=httpx.MockTransport(varonis_handler({"rows": []}))))
    monkeypatch.setattr(vr.asyncio, "sleep", lambda s: _noop())
    ok, detail = await vr.test(VCFG)
    assert ok and "0 alerte" in detail and "https://mairie.varonis.io" in detail
    assert (await vr.test({}))[0] is False


# ---------- GravityZone ----------

GCFG = {"bitdefender_read_api_key": "key", "bitdefender_api_url": "https://cloudgz.gravityzone.bitdefender.com/api"}
INCIDENT = {
    "incidentId": "67dd30dd4a842ebbbb0b6af4", "incidentNumber": 412, "incidentType": "incident", "status": "open",
    "mainAction": "reported", "created": "2026-10-07T09:58:00+00:00", "lastUpdated": "2026-10-07T10:00:00+00:00",
    "severityScore": 86, "priority": "high", "attackTypes": ["Credential Access"],
    "incidentLink": "https://cloudgz.gravityzone.bitdefender.com/#!/incidents/view/67dd30dd4a842ebbbb0b6af4",
    "details": {"detectionName": "ATC.Mimikatz", "computerName": "PTB-00300", "computerIp": "10.1.4.30"},
}
QUARANTINED = {"id": "5d3968e0f23f730ecb0f68c2", "quarantinedOn": "2026-10-07T10:05:00", "endpointName": "PTB-00301",
               "endpointIP": "10.1.4.31", "threatName": "Trojan.GenericKD.1234",
               "details": {"filePath": "C:\\Users\\x\\Downloads\\facture.exe", "fileSha256": "ab" * 32}}


def gz_handler(state):
    def handle(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST" and request.headers["authorization"].startswith("Basic ")
        body = json.loads(request.content)
        state.setdefault("calls", []).append((request.url.path, body["method"], body["params"]))
        if body["method"] == "getIncidentsList":
            if state.get("old_console") and "changeStartDate" in body["params"]["filters"]:
                return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"],
                                                 "error": {"code": -32602, "message": "Invalid params"}})
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": {
                "page": 1, "pagesCount": 1, "total": 1, "items": state.get("incidents", [INCIDENT])}})
        if body["method"] == "getQuarantineItemsList":
            if state.get("no_quarantine"):
                return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "error": {
                    "code": -32001, "message": "API Key is not allowed to access the selected API: Quarantine"}})
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": {
                "page": 1, "pagesCount": 1, "total": 1, "items": [QUARANTINED]}})
        if body["method"] == "getIncidentsByIds":
            return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "result": [
                {"incidentId": i, "status": state.get("status", "open")} for i in body["params"]["ids"]]})
        return httpx.Response(200, json={"jsonrpc": "2.0", "id": body["id"], "error": {"code": -32601,
                                                                                      "message": "Method not found"}})

    return handle


async def test_gravityzone_poll_parse_and_rules():
    redis, state = FakeRedis(), {}
    async with httpx.AsyncClient(transport=httpx.MockTransport(gz_handler(state))) as http:
        connector = gz.GravityZoneConnector(None, redis)
        assert await connector.poll(gz.GravityZoneClient(GCFG, http), now=NOW) == 2
        assert await connector.poll(gz.GravityZoneClient(GCFG, http), now=NOW) == 0  # déjà lus
        # Nouvelle activité sur l'incident (lastUpdated) : un nouvel événement
        state["incidents"] = [{**INCIDENT, "lastUpdated": "2026-10-07T11:00:00+00:00"}]
        assert await connector.poll(gz.GravityZoneClient(GCFG, http), now=NOW) == 1
    paths = {(p, m) for p, m, _ in state["calls"]}
    assert paths == {("/api/v1.2/jsonrpc/incidents", "getIncidentsList"),
                     ("/api/v1.0/jsonrpc/quarantine/computers", "getQuarantineItemsList")}
    first = state["calls"][0][2]
    # Raccordement : un an d'historique, rattrapé par tranches de 30 jours (une par passage)
    assert first["filters"]["changeStartDate"] == "2025-10-07T12:00:00+00:00"
    assert first["filters"]["changeEndDate"] == "2025-11-06T12:00:00+00:00" and first["perPage"] == 1000
    second = [p for _, m, p in state["calls"] if m == "getIncidentsList"][1]
    assert second["filters"]["changeStartDate"] == "2025-11-06T12:00:00+00:00"
    incident, quarantine = events(redis, "bitdefender")[:2]
    assert (incident.module, incident.kind, incident.severity, incident.host_name) == (
        "bitdefender", "alert", 4, "PTB-00300")
    assert "n° 412" in incident.message and incident.reference.endswith("/67dd30dd4a842ebbbb0b6af4")
    assert (incident.rule_name, incident.threat_name) == ("ATC.Mimikatz", "Credential Access")
    assert quarantine.rule_name == "Fichier mis en quarantaine" and "facture.exe" in quarantine.message
    assert (quarantine.action, quarantine.outcome, quarantine.severity, quarantine.threat_name) == (
        "malware_detected", "success", 2, "Trojan.GenericKD.1234")
    assert "NATIVE" in {r.id for r in RULES.match(incident)}


async def test_gravityzone_fallbacks_and_partial_rights():
    redis, state = FakeRedis(), {"old_console": True, "no_quarantine": True}
    async with httpx.AsyncClient(transport=httpx.MockTransport(gz_handler(state))) as http:
        assert await gz.GravityZoneConnector(None, redis).poll(gz.GravityZoneClient(GCFG, http), now=NOW) == 1
    filters = [p["filters"] for _, m, p in state["calls"] if m == "getIncidentsList"]
    assert "changeStartDate" in filters[0] and "startDate" in filters[1]  # console antérieure à la 6.77
    assert gz.QUARANTINE_CURSOR not in redis.kv  # quarantaine refusée : rien n'est sauté


def test_gravityzone_organization_incident_is_not_a_duplicate_alert():
    org = {**INCIDENT, "incidentType": "extendedIncident", "details": {"counters": {"endpoints": 1}}}
    single = parse_message("bitdefender", json.dumps(gz.incident_record(org)))
    assert single.rule_name == "Incident d'organisation (corrélation)" and single.severity == 1
    assert "NATIVE" not in {r.id for r in RULES.match(single)}  # le poste a déjà son alerte
    wide = {**org, "details": {"counters": {"endpoints": 3, "servers": 1}}}
    spread = parse_message("bitdefender", json.dumps(gz.incident_record(wide)))
    assert spread.severity == 4 and "4 machine(s)" in spread.message


def test_gravityzone_closure():
    record = gz.incident_record(INCIDENT)
    ids = gravityzone_ids([record])
    assert ids == ["67dd30dd4a842ebbbb0b6af4"]
    assert gravityzone_ids([record, gz.quarantine_record(QUARANTINED)]) == []  # quarantaine : à clôturer ici
    assert gravityzone_closure(ids, {ids[0]: "in_progress"}) is None
    assert gravityzone_closure(ids, {}) is None
    fp = gravityzone_closure(ids, {ids[0]: "false_positive"})
    assert fp.tool == "GravityZone" and fp.status == "false_positive"
    assert gravityzone_closure(ids, {ids[0]: "closed"}).status == "resolved"


async def test_gravityzone_connection_test(monkeypatch):
    real = httpx.AsyncClient
    monkeypatch.setattr(gz.httpx, "AsyncClient",
                        lambda **kw: real(transport=httpx.MockTransport(gz_handler({"no_quarantine": True}))))
    ok, detail = await gz.test(GCFG)
    assert ok and "incidents : lecture possible (1 sur 24 h)" in detail
    assert "quarantaine : API Key is not allowed" in detail
    assert (await gz.test({}))[0] is False


async def test_gravityzone_requests_are_paced(monkeypatch):
    waits = []

    async def fake_sleep(seconds):
        waits.append(seconds)

    monkeypatch.setattr(gz.asyncio, "sleep", fake_sleep)
    async with httpx.AsyncClient(transport=httpx.MockTransport(gz_handler({}))) as http:
        api = gz.GravityZoneClient(GCFG, http)
        await api.incidents_by_ids([f"{i:024x}" for i in range(25)])  # 3 appels (10 identifiants au plus)
    assert len(waits) == 2 and all(0 < w <= gz.MIN_INTERVAL for w in waits)  # 5 requêtes par seconde au plus


def test_gravityzone_access_url_is_normalized():
    for value in ("https://cloudgz.gravityzone.bitdefender.com", "https://cloudgz.gravityzone.bitdefender.com/",
                  "cloudgz.gravityzone.bitdefender.com/api", "https://cloudgz.gravityzone.bitdefender.com/api/",
                  "https://cloudgz.gravityzone.bitdefender.com/api/v1.0/jsonrpc/network", ""):
        assert gz.api_url({"bitdefender_api_url": value}) == "https://cloudgz.gravityzone.bitdefender.com/api"


def test_cursor_windows_are_bounded():
    assert gz.DEFAULT_HISTORY_DAYS == 365 and gz.WINDOW == timedelta(days=30)
    assert vr.FIRST_DAYS == 7 and vr.MAX_WINDOW == timedelta(days=7)


async def test_gravityzone_history_catches_up_to_now():
    redis = FakeRedis()
    async with httpx.AsyncClient(transport=httpx.MockTransport(gz_handler({"incidents": []}))) as http:
        connector = gz.GravityZoneConnector(None, redis)
        for _ in range(4):
            await connector.poll(gz.GravityZoneClient(GCFG, http), now=NOW, history_days=90)
    assert redis.kv[gz.INCIDENTS_CURSOR] == "2026-10-07T11:59:00+00:00"  # rattrapé : présent moins une minute


def test_retry_after_header():
    assert gz.retry_after("60, 60") == 60 and gz.retry_after("2.5") == 2.5 and gz.retry_after(None) == 2


async def test_gravityzone_long_rate_limit_pauses_the_pass():
    def handle(request):
        return httpx.Response(429, headers={"Retry-After": "60, 60"})

    redis = FakeRedis()
    async with httpx.AsyncClient(transport=httpx.MockTransport(handle)) as http:
        try:
            await gz.GravityZoneConnector(None, redis).poll(gz.GravityZoneClient(GCFG, http), now=NOW)
        except gz.RateLimited as exc:
            assert exc.seconds == 60 and "reprise dans 60 s" in str(exc)
        else:
            raise AssertionError("pause attendue")
    assert gz.INCIDENTS_CURSOR not in redis.kv  # rien n'est sauté
