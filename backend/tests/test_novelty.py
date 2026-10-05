"""Règle de nouveauté (UC-04) et enrichissement GeoIP."""

import pytest
from conftest import RULES_DIR

from minisoc.geoip import GeoIP
from minisoc.rules import Rule, RuleError, load_rules
from minisoc.rules.sql import novelty_query


def test_uc04_definition():
    rule = next(r for r in load_rules(RULES_DIR) if r.id == "UC-04")
    assert rule.type == "novelty"
    assert rule.group_by == ["user.name", "source.geo.country_iso_code"]
    assert rule.novelty.min_history == 3


def test_novelty_query_shape():
    rule = next(r for r in load_rules(RULES_DIR) if r.id == "UC-04")
    sql, params = novelty_query(rule)
    assert "user_name AS g0, source_country AS g1" in sql
    assert "(user_name, source_country) NOT IN" in sql
    assert "HAVING count() >=" in sql
    assert 30 * 86400 in params.values() and 900 in params.values()


def test_novelty_requires_group_by():
    with pytest.raises(RuleError):
        Rule.from_dict({"id": "N", "name": "n", "type": "novelty", "severity": "high",
                        "filter": {"event.outcome": "success"}, "novelty": {"field": "source.ip"}})


def test_geoip_absent_is_harmless(tmp_path):
    geo = GeoIP(str(tmp_path / "inexistant"))
    assert not geo.available
    assert geo.lookup("185.220.101.45") == ("", "")


def test_geoip_ignores_private_addresses(tmp_path):
    geo = GeoIP(str(tmp_path))
    assert geo.lookup("10.1.2.3") == ("", "")
    assert geo.lookup("pas une ip") == ("", "")
