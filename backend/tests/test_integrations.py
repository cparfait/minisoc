"""Catalogue des intégrations : cohérence avec les paramètres, états, désactivation des sources."""

from datetime import datetime, timedelta, timezone

from minisoc.integrations import BY_ID, CATALOG, disabled_modules, monitored_sources, status
from minisoc.settings_store import FIELDS

NOW = datetime.now(timezone.utc)


def test_every_field_and_enable_key_exists_in_settings():
    for item in CATALOG:
        for f in item.fields:
            assert f.key in FIELDS, f"{item.id}: {f.key}"
            assert FIELDS[f.key].secret == (f.kind == "secret"), f"{item.id}: {f.key} (secret incohérent)"
        if item.enable_key:
            assert FIELDS[item.enable_key].kind == "bool", item.id


def test_states():
    sophos = BY_ID["sophos_xgs"]
    on = {"src_sophos_xgs_enabled": True}
    assert status(sophos, {}, {})["state"] == "disabled"  # aucune intégration active par défaut
    assert status(sophos, on, {})["state"] == "waiting"
    assert status(sophos, on, {"sophos_xgs": NOW})["state"] == "active"
    assert status(sophos, on, {"sophos_xgs": NOW - timedelta(hours=2)})["state"] == "silent"
    assert status(sophos, {"src_sophos_xgs_enabled": False}, {})["state"] == "disabled"
    harfang = status(BY_ID["harfanglab"], {"src_harfanglab_enabled": True}, {})
    assert harfang["state"] == "not_configured" and "Jeton d'API (lecture seule)" in harfang["missing"]
    ogo = status(BY_ID["ogo"], {"src_ogo_enabled": True}, {})
    assert ogo["state"] == "not_configured" and "Clé d'API" in ogo["missing"]


def test_disabled_sources_are_dropped_and_not_monitored():
    cfg = {"src_vectra_enabled": False, "src_sophos_xgs_enabled": True}
    assert "vectra" in disabled_modules(cfg) and "sophos_xgs" not in disabled_modules(cfg)
    monitored = monitored_sources({"src_harfanglab_enabled": False, "src_sophos_xgs_enabled": True})
    assert "harfanglab" not in monitored and monitored["sophos_xgs"] == timedelta(minutes=30)
    assert monitored_sources({}) == {} and "sophos_xgs" in disabled_modules({})  # désactivées par défaut


def test_integrations_disabled_by_default():
    for item in CATALOG:
        if item.enable_key:
            assert FIELDS[item.enable_key].default is False, item.id


def test_secrets_never_in_catalog_payload():
    entry = status(BY_ID["crowdsec"], {"crowdsec_api_key": "secret-value"}, {})
    assert "secret-value" not in str(entry)


def test_uc16_uses_catalog_and_skips_unconfigured():
    from conftest import RULES_DIR

    from minisoc.integrations import configured_missing
    from minisoc.rules import load_rules

    rule = next(r for r in load_rules(RULES_DIR) if r.id == "UC-16")
    assert rule.sources == {}
    assert "harfanglab" in configured_missing({}) and "sophos_xgs" not in configured_missing({})


def test_every_integration_has_an_installation_guide():
    from pathlib import Path

    from minisoc.integrations import CATALOG

    guides = Path(__file__).resolve().parent.parent / "minisoc" / "guides"
    for item in CATALOG:
        text = (guides / f"{item.id}.md").read_text(encoding="utf-8")
        assert text.startswith("# "), item.id
        assert text.count("```") % 2 == 0, item.id  # blocs de code fermés
