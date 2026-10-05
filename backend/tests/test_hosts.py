"""Machines concernées par une alerte, statut HarfangLab, import d'historique (ni tempête, ni notification)."""

from datetime import datetime, timedelta, timezone

from minisoc.alerts import HISTORICAL_AFTER, STORM_ENTITY
from minisoc.api.alerts import entity_parts, impacted_hosts
from minisoc.models import Alert
from minisoc.parsers.harfanglab import parse_harfanglab

NOW = datetime(2026, 10, 3, 9, 0, tzinfo=timezone.utc)


def test_entity_parts():
    assert entity_parts("event.module=harfanglab | host.name=PC-01 | rule.name=A=B") == {
        "event.module": "harfanglab",
        "host.name": "PC-01",
        "rule.name": "A=B",
    }


def test_hosts_from_entity_grouped_entities_and_sample():
    single = Alert(
        entity_key="event.module=harfanglab | host.name=SRV-WEB | rule.name=React RCE",
        count=3,
        details={"sample": {"host.name": "SRV-WEB"}},
    )
    assert impacted_hosts(single) == [{"name": "SRV-WEB", "count": 3, "rules": ["React RCE"]}]
    storm = Alert(
        entity_key=STORM_ENTITY,
        count=56,
        details={
            "entities": {
                "event.module=harfanglab | host.name=PTB-00543 | rule.name=Edge headless": 20,
                "event.module=harfanglab | host.name=PC-00747 | rule.name=Driver block list": 5,
                "event.module=harfanglab | host.name=PC-00747 | rule.name=Autre": 1,
            }
        },
    )
    hosts = impacted_hosts(storm)
    assert [h["name"] for h in hosts] == ["PTB-00543", "PC-00747"]
    assert hosts[1] == {"name": "PC-00747", "count": 6, "rules": ["Driver block list", "Autre"]}
    vpn = Alert(entity_key="source.ip=203.0.113.7", count=40, details={"sample_users": ["a"]})
    assert impacted_hosts(vpn) == []


def test_harfanglab_closed_alert_is_an_event_not_an_alert():
    base = {"id": "x1", "level": "high", "rule_name": "Suspicious", "agent": {"hostname": "PC-01"}, "msg": "détection"}
    assert parse_harfanglab({**base, "status": "new"}, NOW).kind == "alert"
    closed = parse_harfanglab({**base, "status": "false_positive"}, NOW)
    assert closed.kind == "event" and closed.message.startswith("[faux positif dans HarfangLab]")


def test_historical_threshold():
    assert HISTORICAL_AFTER == timedelta(hours=24)


class _Redis:
    def __init__(self):
        self.values, self.stream = {}, []

    async def get(self, key):
        return self.values.get(key)

    async def set(self, key, value, nx=False, ex=None):
        if nx and key in self.values:
            return None
        self.values[key] = value
        return True

    def pipeline(self, transaction=False):
        redis, ops = self, []

        class Pipe:
            def xadd(self, stream, fields, **kw):
                ops.append(fields)

            async def execute(self):
                redis.stream.extend(ops)

        return Pipe()


class _Client:
    def __init__(self, alerts):
        self.alerts, self.calls = alerts, []

    async def get(self, path, params):
        self.calls.append(dict(params))
        since = params.get("alert_time__gte", "")
        page = [a for a in self.alerts if a["alert_time"] >= since]

        class Response:
            def raise_for_status(self):
                pass

            def json(self):
                return {"results": page, "next": None}

        return Response()


async def test_harfanglab_full_history_then_cursor():
    from minisoc.connectors.harfanglab import CURSOR_KEY, DEFAULT_HISTORY_DAYS, HarfangLabConnector

    assert DEFAULT_HISTORY_DAYS == 0  # tout l'historique par défaut
    alerts = [
        {"id": "old", "alert_time": "2025-07-25T07:17:44Z"},
        {"id": "new", "alert_time": "2026-10-03T13:30:01Z"},
    ]
    redis, client = _Redis(), _Client(alerts)
    connector = HarfangLabConnector(sessions=None, redis=redis)
    assert await connector.poll(client, 0) == 2
    assert "alert_time__gte" not in client.calls[0]  # aucune limite de date
    assert redis.values[CURSOR_KEY] == "2026-10-03T13:30:01Z"
    # Relecture complète (curseur effacé) : les alertes déjà lues ne sont pas réimportées
    del redis.values[CURSOR_KEY]
    assert await connector.poll(client, 0) == 0
    assert await connector.poll(_Client(alerts), 30) == 0


def test_host_kind_patterns():
    import re

    from minisoc.api.alerts import HAS_HOST, HAS_SERVER

    def kind(text):
        if re.search(HAS_SERVER, text, re.I):
            return "server"
        return "workstation" if re.search(HAS_HOST, text, re.I) else None

    assert kind("event.module=harfanglab | host.name=SRV-AUDIT | rule.name=PingCastle {}") == "server"
    assert kind('user.name=ad-admin {"sample": {"host.name": "PC-00747"}}') == "workstation"
    assert kind('*regroupement* {"entities": {"event.module=harfanglab | host.name=PTB-1 | rule.name=A": 2}}') == (
        "workstation"
    )
    assert kind('x {"sample_hosts": ["PC-1", "srv-fichiers"]}') == "server"
    assert kind('source.ip=203.0.113.7 {"sample_users": ["a"]}') is None


def test_older_detection_moves_first_seen_back():
    from minisoc.alerts import Detection, _update

    class Session:
        def add(self, _):
            pass

    existing = Alert(first_seen=NOW, last_seen=NOW, count=1, metric=1, event_ids=[], modules=[], details={},
                     severity=3, entity_key="e")
    det = Detection(rule=None, entity_key="e", severity=3, title="t", first_seen=NOW - timedelta(days=60),
                    last_seen=NOW - timedelta(days=60))
    _update(Session(), existing, det)
    assert existing.first_seen == NOW - timedelta(days=60) and existing.last_seen == NOW and existing.count == 2
