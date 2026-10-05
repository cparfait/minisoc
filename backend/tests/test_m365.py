"""Microsoft 365 / Entra ID : analyse du journal d'audit unifié, connecteur (API simulée), règles UC-34 à UC-41."""

import json
from datetime import datetime, timezone

import httpx
from conftest import RULES_DIR

from minisoc.connectors.m365 import M365Client, M365Connector
from minisoc.parsers import parse_message
from minisoc.parsers.m365 import interesting
from minisoc.rules import load_rules
from minisoc.rules.engine import RuleSet

CFG = {"m365_tenant_id": "11111111-2222-3333-4444-555555555555", "m365_client_id": "app", "m365_client_secret": "s",
       "m365_exchange": True}


def login(operation="UserLoggedIn", error="0", ip="203.0.113.7", user="J.Dupont@mairie.fr"):
    return {"Id": "x", "CreationTime": "2026-10-03T08:00:00", "Operation": operation,
            "Workload": "AzureActiveDirectory", "UserId": user, "ClientIP": ip, "ErrorNumber": error,
            "ResultStatus": "Success",
            "ExtendedProperties": [{"Name": "UserAgent", "Value": "Mozilla/5.0"}],
            "DeviceProperties": [{"Name": "OS", "Value": "Windows 10"}, {"Name": "BrowserType", "Value": "Edge"}]}


def parse(record):
    return parse_message("m365", json.dumps(record))


def test_login_success_failure_and_interrupt():
    ok = parse(login())
    assert (ok.module, ok.category, ok.action, ok.outcome) == ("m365", "authentication", "logon", "success")
    assert (ok.user_name, ok.source_ip) == ("j.dupont@mairie.fr", "203.0.113.7")
    bad = parse(login("UserLoginFailed", "50126"))
    assert (bad.outcome, bad.reason, bad.threat_name) == ("failure", "invalid_credentials", "AADSTS50126")
    mfa_prompt = parse(login("UserLoginFailed", "50074"))  # MFA demandée : étape normale, pas un échec
    assert (mfa_prompt.action, mfa_prompt.outcome) == ("logon_interrupted", "")
    assert parse(login("UserLoginFailed", "500121")).reason == "mfa_failed"


def test_client_ip_with_port_and_ipv6():
    assert parse(login(ip="203.0.113.7:51234")).source_ip == "203.0.113.7"
    assert parse(login(ip="[2001:db8::1]:443")).source_ip == "2001:db8::1"
    assert parse(login(ip="2001:db8::2")).source_ip == "2001:db8::2"


def test_inbox_forwarding_rule_and_admin_role():
    rule = {"CreationTime": "2026-10-03T08:00:00", "Operation": "New-InboxRule", "Workload": "Exchange",
            "UserId": "j.dupont@mairie.fr", "ClientIP": "203.0.113.7:4444", "ObjectId": "j.dupont",
            "Parameters": [{"Name": "Name", "Value": "."}, {"Name": "ForwardTo", "Value": "pirate@example.com"}]}
    assert interesting(rule)
    ev = parse(rule)
    assert (ev.action, ev.threat_name, ev.rule_name) == ("mail_forwarding_rule", "pirate@example.com", ".")
    quiet = {**rule, "Parameters": [{"Name": "Name", "Value": "Factures"}, {"Name": "MoveToFolder", "Value": "Compta"}]}
    assert not interesting(quiet)
    role = {"CreationTime": "2026-10-03T08:00:00", "Operation": "Add member to role.",
            "Workload": "AzureActiveDirectory", "UserId": "admin@mairie.fr",
            "Target": [{"Type": 5, "ID": "Stagiaire@mairie.fr"}],
            "ModifiedProperties": [{"Name": "Role.DisplayName", "NewValue": "Global Administrator"}]}
    ev = parse(role)
    assert (ev.action, ev.user_name, ev.rule_name) == ("role_member_added", "stagiaire@mairie.fr",
                                                       "Global Administrator")
    assert not interesting({"Operation": "MailItemsAccessed"})


def test_foreign_login_rule_uses_home_countries_setting():
    rs = RuleSet(load_rules(RULES_DIR, variables={"home_countries": ["FR", "BE"]}))
    ev = parse(login())
    ev.source_country, ev.source_as = "NG", "Some ISP"
    assert "UC-34" in {r.id for r in rs.match(ev)}
    ev.source_country = "BE"
    assert "UC-34" not in {r.id for r in rs.match(ev)}
    ev.source_country, ev.source_as = "IE", "Microsoft Corporation"  # centre de données Microsoft
    assert "UC-34" not in {r.id for r in rs.match(ev)}
    ev.source_country = ""  # pays inconnu (pas de base GeoIP) : pas d'alerte
    assert "UC-34" not in {r.id for r in rs.match(ev)}


class FakeRedis:
    def __init__(self):
        self.kv, self.stream = {}, []

    async def get(self, key):
        return self.kv.get(key)

    async def set(self, key, value, nx=False, ex=None):
        if nx and key in self.kv:
            return None
        self.kv[key] = str(value)
        return True

    async def delete(self, *keys):
        for k in keys:
            self.kv.pop(k, None)

    def pipeline(self, transaction=False):
        redis = self

        class Pipe:
            def xadd(self, stream, fields, **kw):
                redis.stream.append(fields)

            async def execute(self):
                return []

        return Pipe()


async def test_connector_subscribes_reads_blobs_once_and_filters():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.path)
        if "oauth2" in request.url.path:
            return httpx.Response(200, json={"access_token": "t", "expires_in": 3600})
        assert request.headers["Authorization"] == "Bearer t"
        if request.url.path.endswith("/subscriptions/start"):
            return httpx.Response(400, json={"error": {"code": "AF20024", "message": "already enabled"}})
        if request.url.path.endswith("/subscriptions/content"):
            kind = request.url.params["contentType"]
            return httpx.Response(200, json=[{"contentId": f"{kind}-1", "contentUri": f"https://manage.office.com/blob/{kind}"}])
        if "/blob/Audit.AzureActiveDirectory" in request.url.path:
            return httpx.Response(200, json=[login(), {"Operation": "UserLoginFailed", "ErrorNumber": "50126"},
                                             {"Operation": "Update user."}])
        if "/blob/Audit.Exchange" in request.url.path:
            return httpx.Response(200, json=[{"Operation": "MailItemsAccessed"}])
        return httpx.Response(404)

    redis = FakeRedis()
    connector = M365Connector(None, redis)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        first = await connector.poll(M365Client(CFG, http), CFG)
        second = await connector.poll(M365Client(CFG, http), CFG)
    assert first == 2 and second == 0  # opérations utiles seulement ; blocs déjà lus ignorés
    assert all(f["kind"] == "m365" for f in redis.stream)
    assert sum(p.endswith("/subscriptions/start") for p in calls) == 2  # une fois par flux, pas à chaque passage
    assert redis.kv["minisoc:cursor:m365:Audit.AzureActiveDirectory"].startswith(str(datetime.now(timezone.utc).year))


async def test_token_refused_is_reported_clearly():
    def handler(request):
        return httpx.Response(401, json={"error_description": "AADSTS7000215: Invalid client secret provided."})

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
        try:
            await M365Client(CFG, http).token()
        except Exception as exc:  # noqa: BLE001
            assert "Invalid client secret" in str(exc)
        else:
            raise AssertionError("jeton accepté à tort")
