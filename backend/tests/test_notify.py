"""Notifications : messages, canaux (requêtes simulées), routage, résumé quotidien."""

import json
from datetime import datetime, timezone
from zoneinfo import ZoneInfo

import httpx
import pytest

from minisoc.config import Settings
from minisoc.notify import channels as channels_mod
from minisoc.notify.channels import AlertMessage, NtfyChannel, TeamsChannel
from minisoc.notify.router import Notifier

MSG = AlertMessage(alert_id=7, severity="critical", title="Botnet sur le VPN <script>", rule="UC-02b – Botnet",
                   entity="global", count=10000, first_seen="03/10 00:00", last_seen="03/10 00:05",
                   url="https://minisoc.local/alerts/7")


def test_subject_prefixes():
    assert MSG.subject.startswith("[Mini-SOC][Critique]")
    reminder = AlertMessage(**{**MSG.__dict__, "unhandled_minutes": 35})
    assert reminder.subject.startswith("[NON PRISE EN CHARGE depuis 35 min]")


def test_html_escapes_alert_content():
    html = MSG.html()
    assert "<script>" not in html and "&lt;script&gt;" in html


@pytest.fixture
def captured(monkeypatch):
    sent = []

    def handler(request: httpx.Request) -> httpx.Response:
        sent.append({"url": str(request.url), "headers": dict(request.headers), "body": json.loads(request.content)})
        return httpx.Response(200, json={"ok": True})

    real = httpx.AsyncClient
    monkeypatch.setattr(channels_mod.httpx, "AsyncClient", lambda **kw: real(transport=httpx.MockTransport(handler)))
    return sent


async def test_ntfy_payload_and_reminder_priority(captured):
    ch = NtfyChannel(Settings())
    ch.cfg = {"ntfy_url": "https://ntfy.example/", "ntfy_topic": "minisoc", "ntfy_token": "tk"}
    assert ch.configured
    await ch.send(MSG)
    await ch.send(AlertMessage(**{**MSG.__dict__, "unhandled_minutes": 30}), topic="astreinte")
    first, second = captured
    assert first["url"] == "https://ntfy.example" and first["body"]["topic"] == "minisoc"
    assert first["headers"]["authorization"] == "Bearer tk"
    assert second["body"]["topic"] == "astreinte" and second["body"]["priority"] == 5


async def test_teams_adaptive_card(captured):
    ch = TeamsChannel(Settings())
    ch.cfg = {"teams_webhook_url": "https://example.webhook.office.com/x"}
    await ch.send(MSG)
    card = captured[0]["body"]["attachments"][0]["content"]
    assert card["type"] == "AdaptiveCard" and card["actions"][0]["url"] == MSG.url


def test_business_hours_and_routes():
    n = Notifier(Settings(), sessions=None)
    tuesday_10h = datetime(2026, 10, 6, 8, 0, tzinfo=timezone.utc)  # 10 h à Paris
    saturday = datetime(2026, 10, 3, 9, 0, tzinfo=timezone.utc)
    assert n.in_business_hours({}, tuesday_10h) and not n.in_business_hours({}, saturday)
    # Réglages de l'interface (Paramètres › Notifications) : priment sur le fichier .env
    weekend_duty = {"business_days": ["6", "7"], "business_hours_start": 9, "business_hours_end": 12}
    assert n.in_business_hours(weekend_duty, saturday) and not n.in_business_hours(weekend_duty, tuesday_10h)
    assert n.channels_for("critical", {}) == ["ntfy", "teams", "email"]  # repli : .env
    assert n.channels_for("low", {}) == []
    assert n.channels_for("high", {"route_high": ["email", "sms"]}) == ["email"]  # canal inconnu ignoré


async def test_digest_content():
    from minisoc.notify.digest import build_digest

    class FakeResult:
        def __init__(self, rows):
            self.rows = rows

        def all(self):
            return self.rows

    class FakeSession:
        def __init__(self):
            self.calls = 0

        async def execute(self, stmt):
            return FakeResult([(4, 2), (3, 5), (1, 3)])

        async def scalars(self, stmt):
            self.calls += 1
            return FakeResult([])

    digest = await build_digest(
        FakeSession(), [{"module": "sophos_xgs", "status": "silent"}],
        [{"ip": "203.0.113.12", "failures": 67, "users": 15}], "https://minisoc.local", ZoneInfo("Europe/Paris"),
        now=datetime(2026, 10, 3, 6, 0, tzinfo=timezone.utc),
    )
    assert "2 critique(s), 5 haute(s)" in digest.subject and "silencieuse" in digest.subject
    assert "sophos_xgs SILENCIEUSE" in digest.text and "203.0.113.12" in digest.text
    assert "Point de sécurité du 03/10/2026" in digest.html
