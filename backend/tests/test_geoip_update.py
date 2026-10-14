"""Bases GeoLite2 téléchargées depuis l'interface : identifiants, archive MaxMind, rythme, erreurs, test."""

import io
import json
import tarfile
from datetime import datetime, timedelta, timezone

import httpx

from minisoc import geoip_update as gu

NOW = datetime(2026, 10, 7, 12, 0, tzinfo=timezone.utc)
CFG = {"geoip_enabled": True, "maxmind_account_id": "123456", "maxmind_license_key": "cle"}


class FakeRedis:
    def __init__(self):
        self.kv = {}

    async def get(self, key):
        return self.kv.get(key)

    async def set(self, key, value, **kw):
        self.kv[key] = value


def archive(edition: str) -> bytes:
    data = f"base {edition}".encode()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        info = tarfile.TarInfo(f"{edition}_20261006/{edition}.mmdb")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def handler(state, status=200):
    state.setdefault("calls", [])

    def handle(request: httpx.Request):
        state["calls"].append((request.url.path, request.url.params.get("suffix")))
        assert request.headers["authorization"].startswith("Basic ")
        if status != 200:
            return httpx.Response(status)
        edition = request.url.path.split("/")[3]
        if request.url.params.get("suffix") == "tar.gz.sha256":
            return httpx.Response(200, text="abc  archive")
        return httpx.Response(200, content=archive(edition))

    return handle


def http(state, status=200):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler(state, status)))


async def test_download_writes_bases_and_waits_three_days(tmp_path):
    redis, state = FakeRedis(), {}
    async with http(state) as client:
        assert await gu.maybe_update(CFG, redis, str(tmp_path), client, NOW) is True
        assert (tmp_path / "GeoLite2-City.mmdb").read_bytes() == b"base GeoLite2-City"
        assert (tmp_path / "GeoLite2-ASN.mmdb").read_bytes() == b"base GeoLite2-ASN"
        assert not list(tmp_path.glob(".*.tmp"))
        assert [c[0] for c in state["calls"]] == ["/geoip/databases/GeoLite2-City/download",
                                                  "/geoip/databases/GeoLite2-ASN/download"]
        # Bases présentes et récentes : rien à faire
        assert await gu.maybe_update(CFG, redis, str(tmp_path), client, NOW + timedelta(days=2)) is False
        assert len(state["calls"]) == 2
        # Trois jours plus tard : mise à jour
        assert await gu.maybe_update(CFG, redis, str(tmp_path), client, NOW + timedelta(days=3)) is True
        # Nouvelle clé enregistrée : téléchargement immédiat
        assert await gu.maybe_update({**CFG, "maxmind_license_key": "autre"}, redis, str(tmp_path), client,
                                     NOW + timedelta(days=3, minutes=5)) is True
    assert json.loads(redis.kv[gu.STATE_KEY])["error"] == ""


async def test_nothing_without_credentials_or_when_disabled(tmp_path):
    redis = FakeRedis()
    assert await gu.maybe_update({**CFG, "maxmind_license_key": ""}, redis, str(tmp_path), None, NOW) is False
    assert await gu.maybe_update({**CFG, "geoip_enabled": False}, redis, str(tmp_path), None, NOW) is False
    assert redis.kv == {}


async def test_refused_key_recorded_and_retried_hourly(tmp_path):
    redis, state = FakeRedis(), {}
    async with http(state, status=401) as client:
        assert await gu.maybe_update(CFG, redis, str(tmp_path), client, NOW) is False
        assert "refusés" in json.loads(redis.kv[gu.STATE_KEY])["error"]
        assert await gu.maybe_update(CFG, redis, str(tmp_path), client, NOW + timedelta(minutes=30)) is False
        assert len(state["calls"]) == 1  # pas de nouvel essai avant une heure
        await gu.maybe_update(CFG, redis, str(tmp_path), client, NOW + timedelta(hours=1))
        assert len(state["calls"]) == 2


async def test_connection_test(monkeypatch):
    real = httpx.AsyncClient
    monkeypatch.setattr(gu, "make_http", lambda: real(transport=httpx.MockTransport(handler({}))))
    ok, detail = await gu.test(CFG)
    assert ok and "acceptés" in detail
    monkeypatch.setattr(gu, "make_http", lambda: real(transport=httpx.MockTransport(handler({}, 401))))
    ok, detail = await gu.test(CFG)
    assert not ok and "refusés" in detail
    assert (await gu.test({}))[0] is False
