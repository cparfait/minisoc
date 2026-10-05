"""Blocage d'IP : contrôles de sécurité et dialogue avec l'API XML du Sophos XGS (simulée)."""

from urllib.parse import parse_qs

import httpx
import pytest

from minisoc.response import xgs as xgs_mod
from minisoc.response.blocking import check_ip
from minisoc.response.xgs import XGSClient, XGSError, host_name

CFG = {"xgs_url": "https://xgs.mairie.local:4444", "xgs_user": "api-minisoc", "xgs_password": "s3cr<et>",
       "xgs_block_group": "MiniSOC-Blocages", "xgs_verify_tls": False}
OK = ('<Response APIVersion="2000.1"><Login><status>Authentication Successful</status></Login>'
      '<IPHost transactionid=""><Status code="200">Configuration applied successfully.</Status></IPHost></Response>')
BAD_LOGIN = '<Response><Login><status>Authentication Failure</status></Login></Response>'


@pytest.mark.parametrize("ip,refused", [
    ("185.220.101.45", False),
    ("192.0.2.10", False),          # documentation (tests)
    ("10.1.4.22", True),            # interne
    ("192.168.1.1", True),
    ("127.0.0.1", True),
    ("pas-une-ip", True),
    ("8.8.8.8", True),              # liste « jamais bloquer »
])
def test_check_ip(ip, refused):
    assert (check_ip(ip, ["8.8.8.0/24"]) is not None) is refused


@pytest.fixture
def fake_xgs(monkeypatch):
    requests = []
    reply = {"body": OK}

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, text=reply["body"])

    real = httpx.AsyncClient
    monkeypatch.setattr(xgs_mod.httpx, "AsyncClient",
                        lambda **kw: real(transport=httpx.MockTransport(handler), timeout=kw.get("timeout")))
    return requests, reply


async def test_block_sends_escaped_xml_by_post(fake_xgs):
    requests, _ = fake_xgs
    await XGSClient(CFG).block("185.220.101.45")
    req = requests[0]
    assert req.method == "POST" and "s3cr" not in str(req.url)  # mot de passe jamais dans l'URL
    xml = parse_qs(req.content.decode())["reqxml"][0]
    assert "<Password passwordform=\"plain\">s3cr&lt;et&gt;</Password>" in xml
    assert "<Name>MSOC_185.220.101.45</Name>" in xml and "<HostGroup>MiniSOC-Blocages</HostGroup>" in xml
    assert '<Set operation="add">' in xml


async def test_unblock_removes_host(fake_xgs):
    requests, _ = fake_xgs
    await XGSClient(CFG).unblock("185.220.101.45")
    assert "<Remove><IPHost><Name>MSOC_185.220.101.45</Name>" in parse_qs(requests[0].content.decode())["reqxml"][0]


async def test_login_failure_is_explained(fake_xgs):
    _, reply = fake_xgs
    reply["body"] = BAD_LOGIN
    with pytest.raises(XGSError, match="Connexion à l'API refusée"):
        await XGSClient(CFG).block("185.220.101.45")


async def test_missing_configuration():
    with pytest.raises(XGSError, match="non configuré"):
        XGSClient({})


def test_ipv6_host_name():
    assert host_name("2001:db8::1") == "MSOC_2001-db8--1"


RULES = ('<Response><Login><status>Authentication Successful</status></Login>'
         '<FirewallRule transactionid=""><Name>VPN vers LAN</Name><Position>Top</Position><Status>Enable</Status>'
         '<PolicyType>Network</PolicyType><NetworkPolicy><Action>Accept</Action><LogTraffic>Enable</LogTraffic>'
         '<SourceZones><Zone>VPN</Zone></SourceZones><DestinationZones><Zone>LAN</Zone></DestinationZones>'
         '<Services><Service>HTTPS</Service><Service>RDP</Service></Services></NetworkPolicy></FirewallRule>'
         '<FirewallRule transactionid=""><Name>Bloquer MiniSOC</Name><Status>Disable</Status>'
         '<NetworkPolicy><Action>Drop</Action><SourceNetworks><Network>MiniSOC-Blocages</Network></SourceNetworks>'
         '</NetworkPolicy></FirewallRule></Response>')


async def test_read_firewall_rules(fake_xgs):
    requests, reply = fake_xgs
    reply["body"] = RULES
    rules = await XGSClient(CFG).firewall_rules()
    xml = parse_qs(requests[0].content.decode())["reqxml"][0]
    assert "<Get><FirewallRule></FirewallRule></Get>" in xml and "<Set" not in xml and "<Remove" not in xml
    assert rules[0]["name"] == "VPN vers LAN" and rules[0]["action"] == "Accept"
    assert rules[0]["source_zones"] == ["VPN"] and rules[0]["services"] == ["HTTPS", "RDP"]
    assert rules[1]["sources"] == ["MiniSOC-Blocages"] and rules[1]["status"] == "Disable"
