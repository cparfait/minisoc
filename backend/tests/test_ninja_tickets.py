"""Tickets NinjaOne : création, suivi de l'état, garde-fous, test de connexion (API simulée)."""

import json

import httpx
import pytest
from sqlalchemy.dialects import postgresql

from minisoc.response import ninja_tickets as tickets
from minisoc.response.ninja_tickets import TicketClient, TicketError
from minisoc.source_sync import sync_tickets

CFG = {"ninjaone_instance": "eu", "ninjaone_tickets_enabled": True, "ninjaone_tickets_client_id": "app",
       "ninjaone_tickets_client_secret": "s", "ninjaone_tickets_org_id": "7", "ninjaone_tickets_form_id": "3"}


def with_token(handler):
    def wrapped(request):
        if request.url.path == "/ws/oauth/token":
            assert "monitoring+management" in request.content.decode()
            return httpx.Response(200, json={"access_token": "t", "expires_in": 3600})
        return handler(request)

    return wrapped


def client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(with_token(handler)))


def patch_http(monkeypatch, handler):
    real = httpx.AsyncClient
    monkeypatch.setattr(httpx, "AsyncClient",
                        lambda *a, **k: real(*a, **{**k, "transport": httpx.MockTransport(with_token(handler))}))


def test_enabled_only_when_switched_on_and_complete():
    assert tickets.enabled(CFG)
    assert not tickets.enabled({**CFG, "ninjaone_tickets_enabled": False})
    assert not tickets.enabled({**CFG, "ninjaone_tickets_form_id": ""})


async def test_create_sends_org_form_subject_and_device():
    sent = {}

    def handler(request):
        sent.update(json.loads(request.content), path=request.url.path, auth=request.headers["authorization"])
        return httpx.Response(200, json={"id": 123, "status": {"name": "OPEN", "displayName": "Ouvert"}})

    async with client(handler) as http:
        data = await TicketClient(CFG, http).create("Sujet", "Texte", 42)
    assert data["id"] == 123
    assert sent["path"] == "/v2/ticketing/ticket" and sent["auth"] == "Bearer t"
    assert (sent["clientId"], sent["ticketFormId"], sent["subject"], sent["nodeId"]) == (7, 3, "Sujet", 42)
    assert sent["description"] == {"public": False, "body": "Texte"}


@pytest.mark.parametrize("status, expected", [(403, "accès refusé"), (400, "champ manquant")])
async def test_create_refusal_is_explained(status, expected):
    async with client(lambda r: httpx.Response(status, text="champ manquant")) as http:
        with pytest.raises(TicketError, match=expected):
            await TicketClient(CFG, http).create("Sujet", "Texte")


async def test_create_without_ticket_number_is_an_error():
    async with client(lambda r: httpx.Response(200, json={})) as http:
        with pytest.raises(TicketError, match="sans numéro"):
            await TicketClient(CFG, http).create("Sujet", "Texte")


def test_state_change_is_reported_once():
    ticket = {"id": 5, "status": "OPEN", "label": "Ouvert"}
    same, note = tickets.updated(ticket, {"status": {"name": "OPEN", "displayName": "Ouvert"}}, "t1")
    assert note == "" and same["checked_at"] == "t1"
    fresh, note = tickets.updated(ticket, {"status": {"name": "IN_PROGRESS", "displayName": "En cours"}})
    assert fresh["status"] == "IN_PROGRESS" and note == "Ticket NinjaOne n° 5 : En cours."


def test_closed_or_missing_tickets_are_no_longer_followed():
    assert tickets.is_followed({"id": 5, "status": "RESOLVED"})  # peut être rouvert
    assert not tickets.is_followed({"id": 5, "status": "CLOSED"})
    gone, note = tickets.updated({"id": 5, "status": "OPEN"}, None)
    assert not tickets.is_followed(gone) and "introuvable" in note


def test_open_filter_excludes_closed_and_missing_tickets():
    sql = str(tickets.open_filter().compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))
    assert "ninja_ticket" in sql and "IS NOT NULL" in sql and "NOT IN ('CLOSED', 'MISSING')" in sql


def test_draft_has_the_essentials_and_no_raw_logs():
    text = tickets.draft({"id": 9, "title": "Force brute", "severity": "high", "rule_id": "UC-01", "rule_name": "VPN",
                          "count": 3, "first_seen": "2026-11-05T08:00:00+00:00", "last_seen": None,
                          "hosts": [{"name": "PC-1"}],
                          "details": {"qualification": {"label": "Attaque probable"}, "sample_users": ["a.martin"],
                                      "sample_ips": ["1.2.3.4"], "sample": {"event.original": "SECRET-BRUT"}}})
    assert text["subject"] == "[Mini-SOC] Force brute"
    for part in ("n° 9", "Attaque probable", "PC-1", "a.martin", "1.2.3.4", "2026-11-05 08:00 UTC"):
        assert part in text["body"]
    assert "SECRET-BRUT" not in text["body"]


async def test_node_only_for_a_single_machine():
    class Redis:
        async def hgetall(self, _key):
            return {"101": json.dumps({"name": "PC-Accueil"})}

    assert await tickets.node_for(Redis(), ["pc-accueil"]) == 101
    assert await tickets.node_for(Redis(), ["pc-accueil", "PC-2"]) is None
    assert await tickets.node_for(Redis(), ["inconnu"]) is None


async def test_connection_test_lists_numbers_and_creates_nothing(monkeypatch):
    methods = []

    def handler(request):
        methods.append(request.method)
        rows = [{"id": 3, "name": "Défaut"}] if "ticket-form" in request.url.path else [{"id": 7, "name": "Mairie"}]
        return httpx.Response(200, json=rows)

    patch_http(monkeypatch, handler)
    ok, detail = await tickets.test(CFG)
    assert ok and "Mairie" in detail and "Défaut" in detail
    ok, detail = await tickets.test({**CFG, "ninjaone_tickets_form_id": ""})
    assert not ok and "3 (Défaut)" in detail and "7 (Mairie)" in detail
    assert set(methods) == {"GET"}


class FakeAlert:
    def __init__(self, ticket):
        self.details = {"ninja_ticket": ticket, "category": "threat"}
        self.status = "new"


class FakeSession:
    def __init__(self, alerts):
        self.alerts = alerts
        self.added = []

    async def execute(self, _stmt):
        rows = [(alert_id, a.details["ninja_ticket"]) for alert_id, a in self.alerts.items()]
        return type("Rows", (), {"all": lambda _self: rows})()

    async def get(self, _model, alert_id, **_kwargs):
        return self.alerts.get(alert_id)

    def add(self, item):
        self.added.append(item)

    async def commit(self):
        pass

    async def rollback(self):
        pass


async def test_sync_traces_changes_and_never_closes_the_alert(monkeypatch):
    read = []

    def handler(request):
        read.append(request.url.path)
        return httpx.Response(200, json={"id": 1, "status": {"name": "CLOSED", "displayName": "Fermé"}})

    patch_http(monkeypatch, handler)
    alerts = {1: FakeAlert({"id": 1, "status": "OPEN", "label": "Ouvert"}),
              2: FakeAlert({"id": 2, "status": "CLOSED", "label": "Fermé"})}
    session = FakeSession(alerts)
    assert await sync_tickets(session, CFG) == 1
    assert read == ["/v2/ticketing/ticket/1"]  # le ticket fermé n'est plus relu
    assert alerts[1].details["ninja_ticket"]["status"] == "CLOSED"
    assert alerts[1].details["category"] == "threat" and alerts[1].status == "new"
    assert session.added[0].detail == "Ticket NinjaOne n° 1 : Fermé."
