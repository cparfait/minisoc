"""Isolation de poste (F-27) : postes isolables lus dans les événements EDR, appels HarfangLab et Bitdefender."""

import json

import httpx
import pytest

from minisoc.response import isolation
from minisoc.response.isolation import IsolationError, Target, isolate, targets_from_events

CFG = {"isolation_enabled": True, "harfanglab_url": "https://hl.example:8443", "harfanglab_isolation_token": "iso",
       "bitdefender_api_url": "https://cloudgz.gravityzone.bitdefender.com/api", "bitdefender_api_key": "bdkey"}


def test_targets_come_from_edr_raw_logs_only():
    events = [
        {"module": "harfanglab", "host_name": "SRV-WEB",
         "raw": json.dumps({"agent": {"agentid": "345d33e4", "hostname": "SRV-WEB"}})},
        {"module": "harfanglab", "raw": json.dumps({"agent": {"agentid": "345d33e4", "hostname": "SRV-WEB"}})},
        {"module": "bitdefender", "raw": json.dumps({"computer_id": "5f1a", "computer_name": "PC-RH-01"})},
        {"module": "sophos_xgs", "raw": json.dumps({"agent": {"agentid": "x"}})},
        {"module": "harfanglab", "raw": "pas du json"},
    ]
    targets = [t.as_dict() for t in targets_from_events(events)]
    assert targets == [{"edr": "harfanglab", "agent_id": "345d33e4", "host": "SRV-WEB"},
                       {"edr": "bitdefender", "agent_id": "5f1a", "host": "PC-RH-01"}]


@pytest.fixture
def http(monkeypatch):
    state = {"handler": None, "requests": []}
    real = httpx.AsyncClient

    def factory(*args, **kwargs):
        def handle(request):
            state["requests"].append(request)
            return state["handler"](request)

        kwargs["transport"] = httpx.MockTransport(handle)
        return real(*args, **kwargs)

    monkeypatch.setattr(isolation.httpx, "AsyncClient", factory)
    return state


async def test_harfanglab_isolate_and_policy_refusal(http):
    http["handler"] = lambda r: httpx.Response(200, json={"requested": ["345d33e4"], "policy_not_allowed": []})
    message = await isolate(CFG, Target("harfanglab", "345d33e4", "SRV-WEB"))
    request = http["requests"][0]
    assert request.url.path == "/api/data/endpoint/Agent/isolate/" and request.headers["authorization"] == "Token iso"
    assert json.loads(request.content) == {"agent_ids": ["345d33e4"]} and "SRV-WEB" in message
    await isolate(CFG, Target("harfanglab", "345d33e4", "SRV-WEB"), release=True)
    assert http["requests"][1].url.path == "/api/data/endpoint/Agent/deisolate/"
    http["handler"] = lambda r: httpx.Response(200, json={"requested": [], "policy_not_allowed": ["345d33e4"]})
    with pytest.raises(IsolationError, match="politique"):
        await isolate(CFG, Target("harfanglab", "345d33e4", "SRV-WEB"))


async def test_bitdefender_isolation_task(http):
    http["handler"] = lambda r: httpx.Response(200, json={"jsonrpc": "2.0", "id": "1", "result": True})
    await isolate(CFG, Target("bitdefender", "5f1a", "PC-RH-01"))
    request = http["requests"][0]
    body = json.loads(request.content)
    assert request.url.path == "/api/v1.0/jsonrpc/incidents" and request.headers["authorization"].startswith("Basic ")
    assert (body["method"], body["params"]) == ("createIsolateEndpointTask", {"endpointId": "5f1a"})
    http["handler"] = lambda r: httpx.Response(200, json={"error": {"message": "Endpoint not found"}})
    with pytest.raises(IsolationError, match="Endpoint not found"):
        await isolate(CFG, Target("bitdefender", "5f1a", "PC-RH-01"), release=True)


async def test_disabled_by_default():
    with pytest.raises(IsolationError, match="désactivée"):
        await isolate({**CFG, "isolation_enabled": False}, Target("harfanglab", "a", "b"))
