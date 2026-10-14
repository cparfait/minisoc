"""Vectra AI lu par l'API v3.4 (flux sortant seulement) : jeton, points de reprise, analyse, règles, test."""

import base64
import json
from datetime import datetime, timezone

import httpx
from conftest import RULES_DIR
from test_saas_connectors import FakeRedis, events

from minisoc.connectors import vectra as vc
from minisoc.rules import load_rules
from minisoc.rules.engine import RuleSet

NOW = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)
RULES = RuleSet(load_rules(RULES_DIR))
CFG = {"vectra_url": "brain.mairie.local", "vectra_client_id": "minisoc", "vectra_client_secret": "s3cret"}

DETECTIONS = [
    {"id": 101, "category": "lateral_movement", "certainty": 60, "threat": 80, "d_type_vname": "Brute-Force",
     "detection_type": "Brute-Force", "detection_href": "https://brain.mairie.local/detections/7",
     "detection_id": 7, "entity_name": "PTB-00100", "entity_uid": "PTB-00100", "type": "host",
     "event_timestamp": "2026-10-07T11:50:00Z", "mitre": ["T1110"], "severity": 5, "triaged": False,
     "detail": {"dst_ips": "10.1.0.5", "app_protocol": "ssh"}},
    {"id": 102, "category": "command_and_control", "certainty": 30, "threat": 20, "d_type_vname": "Suspicious Admin",
     "entity_name": "Jean Dupont", "entity_uid": "O365:j.dupont@mairie.fr", "type": "account",
     "event_timestamp": "2026-10-07T11:55:00Z", "mitre": [], "url": "https://brain.mairie.local/accounts/3"},
]
HOSTS = [{"id": 11, "category": "HOST_SCORING", "name": "PTB-00100", "type": "host", "severity": "Critical",
          "urgency_score": 92, "is_prioritized": True, "active_detection_types": ["brute_force_i2i"],
          "event_timestamp": "2026-10-07T11:51:00Z", "url": "https://brain.mairie.local/hosts/1"}]
ACCOUNTS = [{"id": 21, "category": "ACCOUNT_SCORING", "name": "O365:j.dupont@mairie.fr", "type": "account",
             "severity": "Medium", "urgency_score": 40, "event_timestamp": "2026-10-07T11:56:00Z",
             "url": "https://brain.mairie.local/accounts/3"}]


def handler(state):
    state.setdefault("calls", [])
    state.setdefault("tokens", 0)

    def handle(request: httpx.Request):
        state["calls"].append((request.method, request.url.path, dict(request.url.params)))
        if request.url.path == "/oauth2/token":
            assert request.method == "POST"
            assert request.headers["authorization"] == "Basic " + base64.b64encode(b"minisoc:s3cret").decode()
            assert b"grant_type=client_credentials" in request.content
            state["tokens"] += 1
            return httpx.Response(200, json={"access_token": f"jeton-{state['tokens']}", "expires_in": 3600})
        assert request.method == "GET" and request.url.host == "brain.mairie.local"
        if state.pop("expire_once", False):
            return httpx.Response(401)
        assert request.headers["authorization"].startswith("Bearer jeton-")
        kind = request.url.params.get("type", "detections")
        rows = {"detections": DETECTIONS, "host": HOSTS, "account": ACCOUNTS}[kind]
        assert request.url.path == ("/api/v3.4/events/detections" if kind == "detections"
                                    else "/api/v3.4/events/entity_scoring")
        start = int(request.url.params.get("from", 0))
        page = [r for r in rows if r["id"] >= start]  # « from » inclus, comme l'API
        return httpx.Response(200, json={"next_checkpoint": max(r["id"] for r in rows) + 1,
                                         "remaining_count": 0, "events": page})

    return handle


def client(state):
    http = httpx.AsyncClient(transport=httpx.MockTransport(handler(state)))
    return http, vc.VectraClient(CFG, http)


async def test_vectra_poll_checkpoints_parse_and_rules():
    redis, state = FakeRedis(), {}
    http, api = client(state)
    async with http:
        assert await vc.VectraConnector(None, redis).poll(api, now=NOW) == 4
        assert await vc.VectraConnector(None, redis).poll(api, now=NOW) == 0  # déjà lus
    first = [c for c in state["calls"] if c[0] == "GET"][:3]
    assert all(c[2].get("event_timestamp_gte") == "2026-09-30T12:00:00Z" for c in first)  # premier passage : 7 j
    assert [c[2].get("type") for c in first] == [None, "host", "account"]
    assert redis.kv[vc.CURSOR_PREFIX + "detections"] == "103"
    assert redis.kv[vc.CURSOR_PREFIX + "host"] == "12" and redis.kv[vc.CURSOR_PREFIX + "account"] == "22"
    later = [c for c in state["calls"] if c[0] == "GET"][3:]
    assert [c[2].get("from") for c in later] == ["103", "12", "22"]  # reprise au point enregistré
    assert state["tokens"] == 1  # jeton réutilisé tant qu'il est valide

    brute, admin, host, account = events(redis, "vectra")
    assert (brute.module, brute.kind, brute.severity, brute.host_name, brute.destination_ip) == (
        "vectra", "alert", 4, "PTB-00100", "10.1.0.5")
    assert brute.rule_name == "Brute-Force" and brute.threat_name == "LATERAL MOVEMENT"
    assert brute.reference == "https://brain.mairie.local/detections/7"
    assert "menace 80, certitude 60" in brute.message and "T1110" in brute.message
    assert json.loads(brute.raw)["tags"] == ["attack.t1110"]
    assert "NATIVE" in {r.id for r in RULES.match(brute)}
    assert (admin.user_name, admin.host_name, admin.severity) == ("j.dupont", "", 1)
    assert (host.action, host.severity, host.host_name) == ("host_scoring", 4, "PTB-00100")
    assert "urgence 92" in host.message and "prioritaire" in host.message
    assert "UC-19" in {r.id for r in RULES.match(host)}
    assert (account.action, account.severity, account.user_name) == ("account_scoring", 2, "j.dupont")
    assert "UC-19" not in {r.id for r in RULES.match(account)}  # gravité moyenne : pas une entité critique


async def test_vectra_token_renewed_once_on_401():
    redis, state = FakeRedis(), {"expire_once": True}
    http, api = client(state)
    async with http:
        assert await vc.VectraConnector(None, redis).poll(api, now=NOW) == 4
    assert state["tokens"] == 2


async def test_vectra_connection_test(monkeypatch):
    real = httpx.AsyncClient
    monkeypatch.setattr(vc, "make_http", lambda cfg: real(transport=httpx.MockTransport(handler({}))))
    ok, detail = await vc.test(CFG)
    assert ok and "https://brain.mairie.local" in detail
    assert "2 événement(s) de détection, 1 score(s) d'hôte, 1 score(s) de compte" in detail
    assert (await vc.test({}))[0] is False

    refused = lambda request: httpx.Response(401)  # noqa: E731
    monkeypatch.setattr(vc, "make_http", lambda cfg: real(transport=httpx.MockTransport(refused)))
    ok, detail = await vc.test(CFG)
    assert not ok and "refusés" in detail


def test_vectra_settings_validation():
    from minisoc.settings_store import SettingsError, validate

    assert validate("vectra_url", "https://brain.mairie.local") == "https://brain.mairie.local"
    try:
        validate("vectra_url", "brain.mairie.local/api")
    except SettingsError:
        pass
    else:
        raise AssertionError("adresse sans https:// acceptée")
