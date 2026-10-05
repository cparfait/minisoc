"""Veille : flux RSS du CERT-FR, index KEV, marquage des détections, règle UC-22."""

import json
from datetime import datetime, timezone

from conftest import RULES_DIR

from minisoc.ecs import Event
from minisoc.rules import load_rules
from minisoc.rules.engine import RuleSet
from minisoc.threat_feeds import KevIndex, parse_rss

RSS = """<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel><title>CERT-FR</title>
<item><title>Multiples vulnérabilités dans Sophos Firewall (CVE-2026-1234)</title>
<link>https://www.cert.ssi.gouv.fr/avis/CERTFR-2026-AVI-0999/</link>
<pubDate>Fri, 02 Oct 2026 14:00:00 +0000</pubDate>
<description>&lt;p&gt;Une vulnérabilité CVE-2026-1234 permet une exécution de code.&lt;/p&gt;</description></item>
</channel></rss>"""


def test_parse_certfr_rss():
    items = parse_rss(RSS, "avis")
    assert items[0]["cves"] == ["CVE-2026-1234"]
    assert items[0]["date"].startswith("2026-10-02T14:00")
    assert "<p>" not in items[0]["summary"]


def test_rss_entity_expansion_is_refused():
    import pytest
    from defusedxml import EntitiesForbidden

    bomb = ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "aaaa">]>'
            "<rss><channel><item><title>&a;</title></item></channel></rss>")
    with pytest.raises(EntitiesForbidden):
        parse_rss(bomb, "alerte")


def test_kev_matching_and_uc22():
    index = KevIndex(redis=None)
    index.cves = {"CVE-2024-3400", "CVE-2023-4966"}
    assert index.match("IPS: Palo Alto GlobalProtect cve-2024-3400 exploit attempt") == ["CVE-2024-3400"]
    assert index.match("CVE-2099-0001 inconnue") == []
    ev = Event(ts=datetime.now(timezone.utc), module="sophos_xgs", kind="alert", category="intrusion_detection",
               severity=2, source_ip="185.220.101.45", destination_ip="203.0.113.10", intel="kev:CVE-2024-3400")
    assert [r.id for r in RuleSet(load_rules(RULES_DIR)).match(ev)] == ["UC-22"]


async def test_digest_includes_veille():
    from zoneinfo import ZoneInfo

    from minisoc.notify.digest import build_digest

    class R:
        def all(self):
            return []

    class S:
        async def execute(self, stmt):
            return R()

        async def scalars(self, stmt):
            return R()

    now = datetime(2026, 10, 3, 6, 0, tzinfo=timezone.utc)
    veille = {"kev": {"recent": [{"cve": "CVE-2026-1234", "vendor": "Sophos", "product": "Firewall", "name": "RCE",
                                  "added": "2026-10-02", "ransomware": True}]},
              "certfr": parse_rss(RSS, "avis")}
    digest = await build_digest(S(), [], [], "https://minisoc.local", ZoneInfo("Europe/Paris"), now=now, veille=veille)
    assert "CVE-2026-1234 Sophos Firewall (rançongiciels)" in digest.text
    assert "CERT-FR avis" in digest.text and json.dumps(digest.html)
