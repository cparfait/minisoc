"""Connecteur CrowdSec : durées, application des décisions, renseignement, règle UC-18."""

import json
import time
from datetime import datetime, timezone

from conftest import RULES_DIR

from minisoc.connectors.crowdsec import INTEL_KEY, RANGES_KEY, CrowdSecConnector, ThreatIntel, duration_seconds
from minisoc.ecs import Event
from minisoc.parsers import parse_message
from minisoc.rules import load_rules
from minisoc.rules.engine import RuleSet


class FakeRedis:
    def __init__(self):
        self.hashes: dict[str, dict[str, str]] = {}
        self.stream: list[dict] = []

    def pipeline(self, transaction=False):
        return FakePipe(self)

    async def hgetall(self, key):
        return dict(self.hashes.get(key, {}))

    async def delete(self, *keys):
        for k in keys:
            self.hashes.pop(k, None)


class FakePipe:
    def __init__(self, redis):
        self.redis, self.ops = redis, []

    def hset(self, key, field, value):
        self.ops.append(lambda: self.redis.hashes.setdefault(key, {}).__setitem__(field, value))

    def hdel(self, key, field):
        self.ops.append(lambda: self.redis.hashes.get(key, {}).pop(field, None))

    def xadd(self, stream, fields, **kw):
        self.ops.append(lambda: self.redis.stream.append(fields))

    async def execute(self):
        for op in self.ops:
            op()


def test_go_durations():
    assert duration_seconds("3h59m58.5s") == 3 * 3600 + 59 * 60 + 58.5
    assert duration_seconds("150ms") == 0.15
    assert duration_seconds("-2s") == 0


async def test_decisions_feed_intel_and_local_events():
    redis = FakeRedis()
    connector = CrowdSecConnector(sessions=None, redis=redis)
    new = [
        {"origin": "crowdsec", "scope": "Ip", "value": "192.0.2.7", "duration": "4h",
         "scenario": "crowdsecurity/ssh-bf", "type": "ban"},
        {"origin": "CAPI", "scope": "Ip", "value": "198.51.100.9", "duration": "24h", "scenario": "http-probing",
         "type": "ban"},
        {"origin": "lists", "scope": "Range", "value": "203.0.113.0/24", "duration": "24h", "scenario": "tor",
         "type": "ban"},
    ]
    count = await connector.apply(new, deleted=[])
    assert count == 1  # seule la décision locale devient un événement (la liste communautaire sert à l'enrichissement)
    assert json.loads(redis.stream[0]["payload"])["value"] == "192.0.2.7"
    assert redis.stream[0]["kind"] == "crowdsec"
    assert set(redis.hashes[INTEL_KEY]) == {"192.0.2.7", "198.51.100.9"}
    assert set(redis.hashes[RANGES_KEY]) == {"203.0.113.0/24"}

    intel = ThreatIntel(redis)
    await intel.refresh()
    assert intel.lookup("192.0.2.7") == "crowdsec:crowdsecurity/ssh-bf"
    assert intel.lookup("203.0.113.44") == "crowdsec:tor"
    assert intel.lookup("10.0.0.1") == ""

    await connector.apply([], deleted=[{"scope": "Ip", "value": "192.0.2.7"}])
    await intel.refresh()
    assert intel.lookup("192.0.2.7") == ""


async def test_expired_decision_is_ignored():
    redis = FakeRedis()
    redis.hashes[INTEL_KEY] = {"192.0.2.8": json.dumps({"scenario": "x", "until": time.time() - 10})}
    intel = ThreatIntel(redis)
    await intel.refresh()
    assert intel.lookup("192.0.2.8") == ""


def test_local_decision_parsed_as_alert():
    ev = parse_message("crowdsec", json.dumps({"origin": "crowdsec", "scope": "Ip", "value": "192.0.2.7",
                                               "duration": "4h", "scenario": "crowdsecurity/ssh-bf",
                                               "type": "ban"}))
    assert (ev.module, ev.kind, ev.source_ip, ev.rule_name) == ("crowdsec", "alert", "192.0.2.7",
                                                               "crowdsecurity/ssh-bf")


def test_uc18_success_from_banned_ip():
    rs = RuleSet(load_rules(RULES_DIR))
    ok = Event(ts=datetime.now(timezone.utc), module="sophos_xgs", category="authentication", outcome="success",
               source_ip="192.0.2.7", user_name="j.dupont", intel="crowdsec:crowdsecurity/ssh-bf")
    assert [r.id for r in rs.match(ok)] == ["UC-18"]
    clean = Event(**{**ok.__dict__, "intel": ""})
    assert rs.match(clean) == []
