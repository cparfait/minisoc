"""Qualification des alertes d'authentification, avec un faux magasin d'événements."""

import pytest
from conftest import RULES_DIR

from minisoc.parsers.sophos import auth_failure_reason
from minisoc.qualify import AuthQualifier
from minisoc.rules import load_rules


class FakeStore:
    def __init__(self, failures: dict, history: dict, context: list[dict] | None = None) -> None:
        self.context = context or []
        self.failures = {"failures": 0, "users": 0, "ips": 0, "unknown_user": 0, "account_issue": 0,
                         "sample_users": [], "sample_ips": [], **failures}
        self.history = {"successes": 0, "users": [], "ips": [], **history}
        self.queries: list[tuple[str, dict]] = []

    async def query(self, sql: str, params: dict) -> list[dict]:
        self.queries.append((sql, params))
        if "anyIf(intel" in sql:
            return self.context
        return [self.history if "outcome = 'success'" in sql else self.failures]


def rule(rule_id: str):
    return next(r for r in load_rules(RULES_DIR) if r.id == rule_id)


@pytest.mark.parametrize(
    "text,expected",
    [
        ("User x failed to login to SSL VPN because of wrong credentials", "invalid_credentials"),
        ("User does not exist", "unknown_user"),
        ("Password expired", "password_expired"),
        ("Account locked", "account_locked"),
        ("quelque chose d'inattendu", "other"),
    ],
)
def test_failure_reason(text, expected):
    assert auth_failure_reason(text) == expected


async def test_password_spraying_is_an_attack():
    store = FakeStore({"failures": 60, "users": 12, "sample_users": ["admin", "rh"]}, {})
    q = await AuthQualifier(store).qualify(rule("UC-01"), {"source.ip": "192.0.2.9"}, {})
    assert q.verdict == "attack" and q.severity is None


async def test_usual_ip_with_old_password_is_benign():
    store = FakeStore({"failures": 25, "users": 1, "sample_users": ["c.bernard"]}, {"successes": 4})
    q = await AuthQualifier(store).qualify(rule("UC-01"), {"source.ip": "198.51.100.200"}, {})
    assert q.verdict == "benign" and q.severity == 1
    assert any("IP habituelle" in r for r in q.reasons)


async def test_expired_password_from_new_ip_is_benign():
    store = FakeStore({"failures": 22, "users": 1, "account_issue": 22, "sample_users": ["l.moreau"]}, {})
    q = await AuthQualifier(store).qualify(rule("UC-01"), {"source.ip": "192.0.2.230"}, {})
    assert q.verdict == "benign"


async def test_single_account_from_unknown_ip_must_be_checked():
    store = FakeStore({"failures": 30, "users": 1, "sample_users": ["m.martin"]}, {})
    q = await AuthQualifier(store).qualify(rule("UC-01"), {"source.ip": "192.0.2.77"}, {})
    assert q.verdict == "suspicious"


async def test_success_from_attacking_ip_is_critical():
    store = FakeStore({"failures": 50, "users": 9}, {})
    q = await AuthQualifier(store).qualify(rule("UC-03a"), {"source.ip": "198.51.100.3"},
                                           {"sample_users": ["j.dupont"]})
    assert (q.verdict, q.severity) == ("attack", 4)


async def test_typo_then_success_from_usual_ip_is_benign():
    store = FakeStore({"failures": 6, "users": 1, "ips": 1, "sample_ips": ["203.0.113.200"]}, {"successes": 3})
    q = await AuthQualifier(store).qualify(rule("UC-03b"), {"user.name": "s.petit"}, {"sample_ips": ["203.0.113.200"]})
    assert (q.verdict, q.severity) == ("benign", 1)


async def test_attacked_account_but_success_from_usual_ip():
    store = FakeStore({"failures": 300, "users": 1, "ips": 150, "sample_ips": ["192.0.2.1"]}, {"successes": 10})
    q = await AuthQualifier(store).qualify(rule("UC-03b"), {"user.name": "j.dupont"}, {"sample_ips": ["90.1.2.3"]})
    assert (q.verdict, q.severity) == ("suspicious", 2)


async def test_queries_use_bound_parameters():
    store = FakeStore({"users": 1, "sample_users": ["x' OR 1=1 --"]}, {})
    await AuthQualifier(store).qualify(rule("UC-01"), {"source.ip": "1.2.3.4' --"}, {})
    for sql, params in store.queries:
        assert "1=1" not in sql and "1.2.3.4" not in sql
        assert params.get("ip", (params.get("ips") or [None])[0]) == "1.2.3.4' --"


async def test_success_on_attacked_account_from_attacking_ip_is_critical():
    store = FakeStore({"failures": 300, "users": 9, "ips": 150}, {})
    q = await AuthQualifier(store).qualify(rule("UC-03b"), {"user.name": "j.dupont"}, {"sample_ips": ["198.51.100.3"]})
    assert (q.verdict, q.severity) == ("attack", 4)


def test_hosting_detection():
    from minisoc.qualify import is_hosting
    assert is_hosting("AS16276 OVH SAS") and is_hosting("AS60729 Stiftung Erneuerbare Freiheit")
    assert not is_hosting("AS3215 Orange") and not is_hosting("AS12322 Free SAS")


async def test_usual_ip_but_banned_by_crowdsec_is_not_benign():
    ctx = [{"ip": "198.51.100.200", "country": "FR", "asn": "AS3215 Orange", "intel": "crowdsec:ssh-bf"}]
    store = FakeStore({"failures": 25, "users": 1, "sample_users": ["c.bernard"]}, {"successes": 4}, ctx)
    q = await AuthQualifier(store).qualify(rule("UC-01"), {"source.ip": "198.51.100.200"}, {})
    assert q.verdict == "suspicious" and q.severity is None
    assert any("CrowdSec" in r for r in q.reasons)


async def test_single_account_from_hosting_abroad_is_an_attack():
    ctx = [{"ip": "185.220.101.45", "country": "DE", "asn": "AS60729 Stiftung Erneuerbare Freiheit", "intel": ""}]
    store = FakeStore({"failures": 30, "users": 1, "sample_users": ["m.martin"]}, {}, ctx)
    q = await AuthQualifier(store).qualify(rule("UC-01"), {"source.ip": "185.220.101.45"}, {}, ("FR",))
    assert q.verdict == "attack"
    assert any("hors des pays habituels : DE" in r for r in q.reasons)
