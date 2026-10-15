"""NinjaOne : jeton « monitoring », alertes, état de sécurité du parc (changements seulement), règles UC-05/11/15."""

import json

import httpx
from conftest import RULES_DIR

from minisoc.connectors.ninjaone import NinjaClient, NinjaOneConnector, antivirus_state, changes, posture
from minisoc.parsers import parse_message
from minisoc.rules import load_rules
from minisoc.rules.engine import RuleSet

CFG = {"ninjaone_instance": "eu", "ninjaone_client_id": "app", "ninjaone_client_secret": "s"}
DEVICES = [
    {
        "id": 101,
        "systemName": "PC-ACCUEIL-01",
        "nodeClass": "WINDOWS_WORKSTATION",
        "offline": False,
        "ipAddresses": ["10.0.1.21"],
    },
    {
        "id": 201,
        "systemName": "SRV-FICHIERS-01",
        "nodeClass": "WINDOWS_SERVER",
        "offline": False,
        "ipAddresses": ["10.0.0.5"],
    },
]
HEALTH = [
    {"deviceId": 101, "criticalVulnerabilityCount": 0, "highVulnerabilityCount": 1, "pendingOSPatchesCount": 2},
    {
        "deviceId": 201,
        "criticalVulnerabilityCount": 3,
        "highVulnerabilityCount": 2,
        "pendingOSPatchesCount": 4,
        "failedOSPatchesCount": 1,
        "activeThreatsCount": 0,
    },
]
ANTIVIRUS = [
    {
        "deviceId": 101,
        "productName": "Antivirus Microsoft Defender",
        "productState": "OFF",
        "definitionStatus": "Up-to-Date",
    },
    {
        "deviceId": 201,
        "productName": "Antivirus Microsoft Defender",
        "productState": "ON",
        "definitionStatus": "Up-to-Date",
    },
]


class FakeRedis:
    def __init__(self):
        self.kv, self.hashes, self.stream = {}, {}, []

    async def set(self, key, value, nx=False, ex=None):
        if nx and key in self.kv:
            return None
        self.kv[key] = value
        return True

    async def hgetall(self, key):
        return dict(self.hashes.get(key, {}))

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
    def handle(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/ws/oauth/token":
            assert b"scope=monitoring" in request.content
            return httpx.Response(200, json={"access_token": "t", "expires_in": 3600})
        assert request.headers["authorization"] == "Bearer t"
        if path == "/v2/alerts":
            return httpx.Response(200, json=state.get("alerts", []))
        if path == "/v2/devices-detailed":
            return httpx.Response(200, json=DEVICES)
        if path == "/v2/queries/device-health":
            return httpx.Response(
                200, json={"results": state.get("health", HEALTH), "cursor": {"name": None, "count": 2}}
            )
        if path == "/v2/queries/antivirus-status":
            return httpx.Response(200, json={"results": state.get("antivirus", ANTIVIRUS), "cursor": {"count": 2}})
        return httpx.Response(404)

    return handle


def parse(payload):
    return parse_message("ninjaone", json.dumps(payload))


def test_antivirus_state_and_posture():
    assert antivirus_state([]) == "unknown"
    assert antivirus_state([{"productState": "OFF"}]) == "inactive"
    assert antivirus_state([{"productState": "ON", "definitionStatus": "Out-of-Date"}]) == "outdated"
    assert antivirus_state([{"productState": "OFF"}, {"productState": "ON", "definitionStatus": "Up-to-Date"}]) == "ok"
    state = posture(DEVICES[1], HEALTH[1], [ANTIVIRUS[1]])
    assert (state["critical"], state["failed"], state["antivirus"]) == (3, 1, "ok")
    assert changes(201, state, state) == []  # rien n'a changé : aucun événement


async def test_connector_alerts_once_and_posture_changes_only():
    redis = FakeRedis()
    connector = NinjaOneConnector(None, redis)
    state = {
        "alerts": [
            {
                "uid": "a1",
                "deviceId": 101,
                "severity": "MAJOR",
                "createTime": 1791000000,
                "message": "Espace disque C: < 10 % de 2026-10-03T08:00:00Z à 2026-10-03T09:00:00Z",
                "device": {"systemName": "PC-ACCUEIL-01"},
            }
        ]
    }
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler(state))) as http:
        api = NinjaClient(CFG, http)
        assert await connector.poll_alerts(api, CFG) == 1
        assert await connector.poll_alerts(api, CFG) == 0  # déjà vue
        first = await connector.poll_posture(api, CFG)
        second = await connector.poll_posture(api, CFG)
        state["health"] = [HEALTH[0], {**HEALTH[1], "criticalVulnerabilityCount": 5, "activeThreatsCount": 1}]
        third = await connector.poll_posture(api, CFG)
    kinds = [
        json.loads(m["payload"]).get("kind") for m in redis.stream if json.loads(m["payload"])["type"] == "posture"
    ]
    # Premier relevé : état des lieux sans alerte ; ensuite seulement les aggravations
    assert first == 0 and second == 0 and third == 2
    assert kinds == ["active_threat", "critical_vulnerabilities"]
    summary = json.loads(redis.kv["minisoc:ninjaone:summary"])
    assert summary["devices"] == 2 and summary["critical"] == 5 and summary["exposed"][0]["name"] == "SRV-FICHIERS-01"
    assert summary["exposed"][0]["console"] == "https://eu.ninjarmm.com/#/deviceDashboard/201/overview"


def test_events_trigger_cahier_rules():
    rs = RuleSet(load_rules(RULES_DIR))
    av = parse(
        {
            "type": "posture",
            "kind": "antivirus_inactive",
            "device_id": 101,
            "device": posture(DEVICES[0], HEALTH[0], [ANTIVIRUS[0]]),
            "console": "https://x",
        }
    )
    assert (av.action, av.severity, av.host_name) == ("antivirus_disabled", 3, "PC-ACCUEIL-01")
    assert "UC-11" in {r.id for r in rs.match(av)}
    vuln = parse(
        {
            "type": "posture",
            "kind": "critical_vulnerabilities",
            "device_id": 201,
            "previous": 0,
            "device": posture(DEVICES[1], HEALTH[1], [ANTIVIRUS[1]]),
        }
    )
    assert vuln.severity == 3  # serveur : haute
    assert "UC-15" in {r.id for r in rs.match(vuln)}
    threat = parse(
        {
            "type": "posture",
            "kind": "active_threat",
            "device_id": 201,
            "device": {**posture(DEVICES[1], HEALTH[1], [ANTIVIRUS[1]]), "threats": 1},
        }
    )
    assert "UC-05" in {r.id for r in rs.match(threat)}
    alert = parse(
        {
            "type": "alert",
            "alert": {
                "severity": "MAJOR",
                "message": "Disque C: plein de 2026-10-03T08:00:00Z",
                "device": {"systemName": "PC-01"},
                "createTime": 1791000000000,
            },
        }
    )
    assert (alert.kind, alert.severity, alert.message) == ("alert", 3, "Disque C: plein")
