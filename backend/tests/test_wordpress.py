"""WordPress : inventaire (API REST ou détection publique), mises à jour, failles WPScan, alerte UC-64."""

import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from conftest import RULES_DIR

from minisoc.connectors import wordpress
from minisoc.parsers.dispatch import parse_message
from minisoc.rules import load_rules
from minisoc.rules.engine import RuleSet
from minisoc.settings_store import SettingsError, validate

NOW = datetime(2026, 10, 20, 8, 0, tzinfo=timezone.utc)
RULES = RuleSet(load_rules(RULES_DIR))
SITE = {"url": "https://www.mairie.fr", "user": "minisoc", "password": "abcd efgh ijkl mnop"}
HOME = """<html><head><meta name="generator" content="WordPress 6.4.3" />
<link rel='stylesheet' href='https://www.mairie.fr/wp-content/plugins/contact-form-7/includes/css/styles.css?ver=5.8' />
<script src='https://www.mairie.fr/wp-content/plugins/elementor/assets/js/frontend.min.js?ver=3.18.0'></script>
<link rel='stylesheet' href='https://www.mairie.fr/wp-content/themes/astra/style.min.css?ver=4.5.2' /></head></html>"""
PLUGINS = [
    {"plugin": "contact-form-7/wp-contact-form-7", "status": "active", "name": "Contact Form 7", "version": "5.8"},
    {"plugin": "akismet/akismet", "status": "inactive", "name": "Akismet Anti-spam", "version": "5.3.1"},
    {"plugin": "maison/maison", "status": "active", "name": "Extension maison", "version": "1.0"},
]
THEMES = [{"stylesheet": "astra", "name": {"rendered": "Astra"}, "version": "4.5.2", "status": "active"}]
LATEST = {"contact-form-7": "5.9.8", "akismet": "5.3.1", "elementor": "3.24.0", "astra": "4.8.1"}
CF7_VULNS = {"contact-form-7": {"friendly_name": "Contact Form 7", "latest_version": "5.9.8", "vulnerabilities": [
    {"id": "v1", "title": "Contact Form 7 < 5.8.4 - Unrestricted File Upload", "vuln_type": "UPLOAD",
     "fixed_in": "5.8.4", "introduced_in": None, "references": {"cve": ["2023-6449"]}, "cvss": {"score": "9.8"}},
    {"id": "v0", "title": "Contact Form 7 < 5.3.2 - Unrestricted File Upload", "fixed_in": "5.3.2",
     "references": {"cve": ["2020-35489"]}},
]}}


class FakeRedis:
    def __init__(self):
        self.kv, self.hashes, self.stream = {}, {}, []

    async def get(self, key):
        return self.kv.get(key)

    async def set(self, key, value, nx=False, ex=None):
        self.kv[key] = value
        return True

    async def delete(self, key):
        self.kv.pop(key, None)

    async def incr(self, key):
        self.kv[key] = int(self.kv.get(key, 0)) + 1
        return self.kv[key]

    async def expire(self, key, seconds):
        return True

    async def hget(self, key, field):
        return self.hashes.get(key, {}).get(field)

    async def hset(self, key, field=None, value=None, mapping=None):
        self.hashes.setdefault(key, {}).update(mapping or {field: value})

    async def hmget(self, key, fields):
        return [self.hashes.get(key, {}).get(f) for f in fields]

    async def hgetall(self, key):
        return dict(self.hashes.get(key, {}))

    async def hkeys(self, key):
        return list(self.hashes.get(key, {}))

    async def hdel(self, key, field):
        self.hashes.get(key, {}).pop(field, None)

    def pipeline(self, transaction=False):
        redis = self

        class Pipe:
            def xadd(self, stream, fields, **kw):
                redis.stream.append(fields)

            async def execute(self):
                return []

        return Pipe()


def handler(state):
    state.setdefault("calls", [])

    def handle(request: httpx.Request) -> httpx.Response:
        url = request.url
        state["calls"].append(f"{url.host}{url.path}")
        if url.host == "api.wordpress.org":
            if url.path == "/core/version-check/1.7/":
                return httpx.Response(200, json={"offers": [{"response": "upgrade", "current": "6.6.2"}]})
            slug = url.params["request[slug]"]
            if slug in LATEST:
                return httpx.Response(200, json={"slug": slug, "version": LATEST[slug]})
            return httpx.Response(404, json={"error": "Plugin not found."})
        if url.host == "wpscan.com":
            assert request.headers["authorization"] == "Token token=jeton-wpscan"
            if url.path == "/api/v3/plugins/contact-form-7":
                return httpx.Response(200, json=CF7_VULNS)
            if url.path == "/api/v3/wordpresses/643":
                return httpx.Response(200, json={"6.4.3": {"status": "insecure", "vulnerabilities": [
                    {"id": "c1", "title": "WP < 6.4.4 - Contributor+ Stored XSS", "fixed_in": "6.4.4",
                     "references": {"cve": ["2024-4439"]}, "cvss": {"score": "6.4"}}]}})
            return httpx.Response(404, json={})
        assert url.host == "www.mairie.fr"
        assert "abcd" not in str(url)
        if url.path == "/":
            return httpx.Response(200, text=HOME)
        if url.path.startswith("/wp-json/wp/v2/"):
            if request.headers.get("authorization") != httpx.BasicAuth(SITE["user"], SITE["password"])._auth_header:
                return httpx.Response(401, json={"code": "rest_forbidden"})
            return httpx.Response(200, json=PLUGINS if url.path.endswith("plugins") else THEMES)
        if url.path == "/wp-content/plugins/elementor/readme.txt":
            return httpx.Response(200, text="=== Elementor ===\nStable tag: 3.18.3\n")
        return httpx.Response(404, text="introuvable")

    return handle


def client(state) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler(state)), follow_redirects=True)


@pytest.fixture
def patched(monkeypatch):
    state: dict = {}
    monkeypatch.setattr(wordpress, "make_http", lambda cfg: client(state))
    return state


def cfg(**extra) -> dict:
    return {"src_wordpress_enabled": True, "wordpress_sites": json.dumps([SITE]), **extra}


def test_versions_and_affected_vulnerabilities():
    assert wordpress.newer("5.9.8", "5.8") and not wordpress.newer("5.3.1", "5.3.1")
    assert wordpress.update_kind("6.4.5", "6.4.3") == "correctif"
    assert wordpress.update_kind("6.6.2", "6.4.3") == "version"
    assert wordpress.affected({"fixed_in": "5.8.4"}, "5.8") and not wordpress.affected({"fixed_in": "5.3.2"}, "5.8")
    assert wordpress.affected({"fixed_in": ""}, "1.0")  # pas encore de correctif
    assert not wordpress.affected({"fixed_in": "2.0", "introduced_in": "1.5"}, "1.2")


async def test_authenticated_inventory_updates_and_vulnerabilities(patched):
    redis = FakeRedis()
    status = await wordpress.WordPressJob(None, redis).scan(cfg(wordpress_wpscan_token="jeton-wpscan"), NOW)
    assert status["state"] == "ok" and status["errors"] == []
    st = json.loads(redis.hashes[wordpress.STATE_KEY][SITE["url"]])
    comps = {c["slug"]: c for c in st["components"]}
    assert st["mode"] == "api"
    assert comps["wordpress"]["installed"] == "6.4.3" and comps["wordpress"]["update"] == "version"
    assert comps["contact-form-7"]["latest"] == "5.9.8" and comps["contact-form-7"]["update"] == "version"
    assert [v["id"] for v in comps["contact-form-7"]["vulns"]] == ["v1"]  # v0 corrigée avant 5.8
    assert comps["akismet"]["update"] == "" and comps["akismet"]["active"] is False
    assert comps["maison"]["latest"] == ""  # absente de wordpress.org
    assert comps["astra"]["name"] == "Astra" and comps["astra"]["update"] == "version"
    assert wordpress.counts(st) == {"core": "6.4.3", "core_latest": "6.6.2", "updates": 3, "plugins": 3,
                                    "themes": 1, "vulnerable": 2, "vulns": 2}

    events = [parse_message(f["kind"], f["payload"]) for f in redis.stream]
    assert len(events) == 1
    event = events[0]
    assert (event.module, event.action, event.host_name, event.severity) == (
        "wordpress", "vulnerable_component", "www.mairie.fr", 4)
    assert "CVE-2023-6449" in event.threat_name and "Contact Form 7 5.8 → 5.8.4" in event.message
    assert {r.id for r in RULES.match(event)} == {"UC-64"}

    # Inventaire suivant identique : aucune nouvelle alerte ; les réponses WPScan viennent du cache
    redis.stream.clear()
    calls = len([c for c in patched["calls"] if c.startswith("wpscan.com")])
    await wordpress.WordPressJob(None, redis).scan(cfg(wordpress_wpscan_token="jeton-wpscan"), NOW + timedelta(days=1))
    assert redis.stream == []
    assert len([c for c in patched["calls"] if c.startswith("wpscan.com")]) == calls


async def test_public_detection_without_credentials(patched):
    redis = FakeRedis()
    public = {"url": SITE["url"], "user": "", "password": ""}
    await wordpress.WordPressJob(None, redis).scan(cfg(wordpress_sites=json.dumps([public])), NOW)
    st = json.loads(redis.hashes[wordpress.STATE_KEY][SITE["url"]])
    comps = {c["slug"]: c for c in st["components"]}
    assert st["mode"] == "public" and not any(c.startswith("www.mairie.fr/wp-json") for c in patched["calls"])
    assert comps["elementor"]["installed"] == "3.18.3"  # readme.txt prime sur ?ver=
    assert comps["contact-form-7"]["installed"] == "5.8"  # pas de readme : paramètre ver
    assert comps["astra"]["installed"] == "4.5.2" and comps["elementor"]["update"] == "version"
    assert comps["wordpress"]["vulns"] is None  # pas de jeton WPScan : failles non vérifiées
    assert redis.stream == []


async def test_bad_credentials_keep_previous_inventory_and_report_error(patched):
    redis = FakeRedis()
    await wordpress.WordPressJob(None, redis).scan(cfg(), NOW)
    bad = {**SITE, "password": "revoque"}
    status = await wordpress.WordPressJob(None, redis).scan(cfg(wordpress_sites=json.dumps([bad])), NOW)
    st = json.loads(redis.hashes[wordpress.STATE_KEY][SITE["url"]])
    assert status["state"] == "error" and "mot de passe d'application refusé" in status["errors"][0]
    assert "refusé" in st["error"] and st["components"]  # inventaire précédent conservé


async def test_wpscan_daily_quota(patched):
    redis = FakeRedis()
    status = await wordpress.WordPressJob(None, redis).scan(
        cfg(wordpress_wpscan_token="jeton-wpscan", wordpress_wpscan_daily=1), NOW)
    st = json.loads(redis.hashes[wordpress.STATE_KEY][SITE["url"]])
    assert status["quota_reached"] is True
    assert sum(1 for c in st["components"] if c["vulns"] is not None) == 1


async def test_removed_site_forgotten_and_due(patched):
    redis = FakeRedis()
    job = wordpress.WordPressJob(None, redis)
    assert await job.due(NOW)
    redis.hashes[wordpress.STATE_KEY] = {"https://ancien.mairie.fr": "{}"}
    await job.scan(cfg(), NOW)
    assert list(redis.hashes[wordpress.STATE_KEY]) == [SITE["url"]]
    assert not await job.due(datetime.now(timezone.utc))
    await redis.set(wordpress.SCAN_NOW_KEY, "1")
    assert await job.due(datetime.now(timezone.utc))


async def test_connection_test(patched):
    ok, detail = await wordpress.test(cfg(), FakeRedis())
    assert ok and "WordPress 6.4.3, 3 extension(s), 1 thème(s)" in detail and "API REST" in detail
    ok, detail = await wordpress.test({"wordpress_sites": "[]"}, FakeRedis())
    assert not ok and "Aucun site" in detail


def test_settings_validation_and_url_normalization():
    with pytest.raises(SettingsError):
        validate("wordpress_sites", "pas du json")
    with pytest.raises(SettingsError):
        validate("wordpress_sites", json.dumps([{"user": "x"}]))
    validate("wordpress_sites", json.dumps([SITE]))
    assert wordpress.normalize_url("WWW.Mairie.fr/") == "https://www.mairie.fr"
    assert wordpress.normalize_url("http://intranet.local/blog/") == "http://intranet.local/blog"
    assert wordpress.site_name("http://intranet.local/blog") == "intranet.local/blog"
