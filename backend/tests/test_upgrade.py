"""Mise à jour d'une installation existante : les intégrations en service restent actives."""

import json

from minisoc import upgrade
from minisoc.integrations import GEOIP_STATUS_KEY
from minisoc.models import Setting
from minisoc.threat_feeds import KEV_META


class FakeRedis:
    def __init__(self, seen=None, kev=None, geo=None):
        self.hashes = {"minisoc:sources:last_seen": seen or {}, KEV_META: kev or {}}
        self.kv = {GEOIP_STATUS_KEY: json.dumps(geo)} if geo else {}

    async def hgetall(self, key):
        return self.hashes.get(key, {})

    async def get(self, key):
        return self.kv.get(key)


class FakeSession:
    def __init__(self, keys):
        self.rows = [Setting(key=k, value="false") for k in keys]
        self.committed = False

    async def scalars(self, _query):
        rows = self.rows

        class Result:
            def all(self):
                return rows

        return Result()

    async def commit(self):
        self.committed = True


async def test_working_integrations_kept_and_explicit_choices_respected(monkeypatch):
    written, audited = {}, []

    async def update_keys(session, allowed, changes, actor):
        assert set(changes) <= allowed and actor == "mise à jour"
        written.update(changes)
        return list(changes)

    async def record(session, **kw):
        audited.append(kw)

    monkeypatch.setattr(upgrade.settings_store, "update_keys", update_keys)
    monkeypatch.setattr(upgrade.audit, "record", record)
    redis = FakeRedis(seen={"sophos_xgs": "2026-10-07T10:00:00+00:00", "vectra": "2026-10-07T10:00:00+00:00"},
                      kev={"updated": "2026-10-07"}, geo={"files": ["GeoLite2-City.mmdb"]})
    session = FakeSession(["src_vectra_enabled"])  # Vectra désactivée à la main : on n'y touche pas
    kept = await upgrade.keep_working_integrations(session, redis)
    assert kept == ["geoip_enabled", "src_sophos_xgs_enabled", "threat_feeds_enabled"]
    assert written == {k: True for k in kept} and session.committed and audited


async def test_fresh_install_untouched(monkeypatch):
    async def fail(*a, **kw):
        raise AssertionError("aucun réglage ne doit être écrit")

    monkeypatch.setattr(upgrade.settings_store, "update_keys", fail)
    session = FakeSession([])
    assert await upgrade.keep_working_integrations(session, FakeRedis()) == []
    assert not session.committed


async def test_dashboard_flags_silent_sources_like_the_integration_card():
    """Tableau de bord : délai de silence de l'intégration (30 min pour le pare-feu), comme sa fiche."""
    from datetime import datetime, timedelta, timezone

    from minisoc.stats import sources_status

    now = datetime.now(timezone.utc)
    redis = FakeRedis(seen={"sophos_xgs": (now - timedelta(hours=10)).isoformat(),
                            "m365": now.isoformat(), "harfanglab": now.isoformat()})
    cfg = {"src_sophos_xgs_enabled": True, "src_m365_enabled": True, "src_harfanglab_enabled": False}
    items = {s["module"]: s for s in await sources_status(redis, [], cfg)}
    assert items["sophos_xgs"]["status"] == "silent" and items["sophos_xgs"]["max_silence_minutes"] == 30
    assert items["m365"]["status"] == "ok"
    assert "harfanglab" not in items  # intégration désactivée : absente du bandeau
    # Sans réglages (ancien appel) : seules les sources de la règle UC-16 ont un délai
    assert {s["module"]: s["status"] for s in await sources_status(redis, [])}["sophos_xgs"] == "ok"
