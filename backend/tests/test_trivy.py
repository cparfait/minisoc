"""Trivy : rapports réduits, nouvelles failles seulement, règles UC-52/53, analyse de la VM, réception des serveurs."""

import gzip
import json
from contextlib import asynccontextmanager

import pytest
from conftest import RULES_DIR
from fastapi import HTTPException

from minisoc import bus, cve, trivy
from minisoc.api import trivy as trivy_api
from minisoc.parsers import parse_message
from minisoc.rules import load_rules
from minisoc.rules.engine import RuleSet
from minisoc.threat_feeds import KEV_KEY

KEV = "CVE-2026-0001"


def vuln(code, severity="HIGH", pkg="libssl3", installed="3.5.7-r0", fixed="3.5.8-r0", score=None):
    v = {"VulnerabilityID": code, "PkgName": pkg, "InstalledVersion": installed, "FixedVersion": fixed,
         "Severity": severity, "Title": f"faille {code}"}
    if score is not None:
        v["CVSS"] = {"nvd": {"V3Score": score}, "redhat": {"V3Score": 1.0}}
    return v


def report(name, *vulns):
    return {"ArtifactName": name, "Results": [{"Target": name, "Class": "os-pkgs", "Vulnerabilities": list(vulns)}]}


def bundle(*reports):
    return {"agent": "minisoc-trivy/1", "host": "minisoc", "scanned_at": "2026-10-15T04:30:00Z",
            "reports": list(reports)}


class FakeRedis:
    def __init__(self, kev=()):
        self.kv, self.hashes, self.stream = {}, {KEV_KEY: dict.fromkeys(kev, "{}")}, []

    async def get(self, key):
        return self.kv.get(key)

    async def set(self, key, value, ex=None):
        self.kv[key] = value

    async def delete(self, *keys):
        for k in keys:
            self.kv.pop(k, None)

    async def hget(self, key, field):
        return self.hashes.get(key, {}).get(field)

    async def hmget(self, key, fields):
        return [self.hashes.get(key, {}).get(f) for f in fields]

    async def hset(self, key, field=None, value=None, mapping=None):
        h = self.hashes.setdefault(key, {})
        if mapping:
            h.update(mapping)
        if field is not None:
            h[field] = value

    async def hdel(self, key, field):
        self.hashes.get(key, {}).pop(field, None)

    async def hkeys(self, key):
        return list(self.hashes.get(key, {}))

    async def hgetall(self, key):
        return dict(self.hashes.get(key, {}))

    def pipeline(self, transaction=False):
        redis = self

        class Pipe:
            def xadd(self, stream, fields, **kw):
                redis.stream.append(fields)

            async def execute(self):
                return []

        return Pipe()

    def records(self):
        return [json.loads(f["payload"]) for f in self.stream if f["kind"] == "trivy"]


def test_compact_merges_cves_across_images_and_keeps_worst():
    b = bundle(
        report("minisoc-vector:0.59.0", vuln("CVE-2026-1000", "MEDIUM", score=5.3),
               vuln("CVE-2026-1001", "CRITICAL", fixed="")),
        report("minisoc-web:latest", vuln("CVE-2026-1000", "HIGH", pkg="zlib", score=7.5), vuln("GHSA-xxxx", "HIGH")),
    )
    state = trivy.compact(b)
    assert state["targets"] == ["minisoc-vector:0.59.0", "minisoc-web:latest"]
    assert set(state["vulns"]) == {"CVE-2026-1000", "CVE-2026-1001"}  # identifiants non CVE écartés
    merged = state["vulns"]["CVE-2026-1000"]
    assert merged["severity"] == "HIGH" and merged["score"] == 7.5 and merged["fixed"]
    assert [p[0] for p in merged["pkgs"]] == ["minisoc-vector:0.59.0", "minisoc-web:latest"]
    assert not state["vulns"]["CVE-2026-1001"]["fixed"]
    with pytest.raises(trivy.TrivyError):
        trivy.compact({"host": "x"})


async def test_first_report_alerts_then_only_new_failures():
    redis = FakeRedis(kev=[KEV])
    first = bundle(report("minisoc-postgres:18", vuln(KEV, "HIGH"), vuln("CVE-2026-2000", "CRITICAL"),
                          vuln("CVE-2026-2001", "CRITICAL", fixed=""), vuln("CVE-2026-2002", "HIGH")))
    result = await trivy.ingest(redis, trivy.LOCAL, trivy.LOCAL_NAME, first)
    # CVE-2026-2001 sans correctif et CVE-2026-2002 haute : pas d'alerte
    assert sorted(result["new_alerts"]) == ["critical_fixable", "kev_vulnerabilities"]
    assert result["kev"] == 1 and result["critical_fixable"] == 1 and result["total"] == 4
    kinds = {r["kind"]: r for r in redis.records()}
    assert kinds["kev_vulnerabilities"]["cves"] == [KEV] and kinds["kev_vulnerabilities"]["local"]
    assert kinds["critical_fixable"]["detail"]["CVE-2026-2000"]["fix"] == "3.5.8-r0"

    redis.stream.clear()
    again = await trivy.ingest(redis, trivy.LOCAL, trivy.LOCAL_NAME, first)
    assert again["new_alerts"] == [] and redis.records() == []

    second = bundle(report("minisoc-postgres:18", vuln(KEV), vuln("CVE-2026-3000", "HIGH")))
    out = await trivy.ingest(redis, trivy.LOCAL, trivy.LOCAL_NAME, second, alert_high=True)
    assert out["new_alerts"] == ["high_fixable"] and redis.records()[0]["cves"] == ["CVE-2026-3000"]
    assert "trivy" in redis.hashes[bus.SOURCES_KEY]  # signe de vie (source silencieuse)


def test_events_match_rules_uc52_uc53():
    rs = RuleSet(load_rules(RULES_DIR))
    current = trivy.state("srv3", "SRV-DOCKER", trivy.compact(bundle(report("nginx:1.27", vuln(KEV, "HIGH"),
                                                                            vuln("CVE-2026-4000", "CRITICAL")))),
                          trivy.datetime.now(trivy.timezone.utc))
    records = trivy.findings(None, current, {KEV}, alert_high=False)
    events = {r["kind"]: parse_message("trivy", json.dumps(r)) for r in records}
    assert {r.id for r in rs.match(events["kev_vulnerabilities"])} >= {"UC-52"}
    assert {r.id for r in rs.match(events["critical_fixable"])} >= {"UC-53"}
    ev = events["critical_fixable"]
    assert ev.module == "trivy" and ev.host_name == "SRV-DOCKER" and "CVE-2026-4000 → 3.5.8-r0" in ev.message


def test_fleet_and_cve_detail_include_trivy_sources():
    st = trivy.state(trivy.LOCAL, trivy.LOCAL_NAME, trivy.compact(bundle(report("minisoc-redis:8", vuln(KEV)))),
                     trivy.datetime.now(trivy.timezone.utc))
    rows = cve.fleet({"trivy:local": st}, {KEV})
    assert rows[0]["cve"] == KEV and rows[0]["kev"] and rows[0]["sample"] == [trivy.LOCAL_NAME]
    detail = trivy.by_cve({"local": st}, KEV)
    assert detail[0]["local"] and detail[0]["pkgs"][0] == {"target": "minisoc-redis:8", "pkg": "libssl3",
                                                          "installed": "3.5.7-r0", "fix": "3.5.8-r0"}
    assert trivy.by_cve({"local": st}, "CVE-1999-0001") == []


class FakeSessions:
    def __init__(self):
        @asynccontextmanager
        async def session():
            yield None

        self.session = session

    def __call__(self):
        return self.session()


async def test_local_job_forwards_scan_request_and_reads_report(tmp_path, monkeypatch):
    cfg = {"src_trivy_enabled": True, "trivy_alert_high": False}

    async def load(session, force=False):
        return cfg

    monkeypatch.setattr(trivy.settings_store, "load", load)
    redis = FakeRedis(kev=[KEV])
    job = trivy.TrivyLocalJob(FakeSessions(), redis, str(tmp_path))

    await redis.set(trivy.SCAN_NOW_KEY, "1")
    await job.tick()
    assert (tmp_path / trivy.SCAN_FLAG).exists() and await redis.get(trivy.SCAN_NOW_KEY) is None
    assert json.loads(redis.kv[trivy.LOCAL_STATUS_KEY])["pending"] is True

    (tmp_path / trivy.SCAN_FLAG).unlink()  # le service de la VM l'efface en démarrant
    (tmp_path / trivy.STATUS_FILE).write_text(json.dumps({"state": "ok", "message": "8 cible(s) analysée(s)"}))
    (tmp_path / trivy.REPORT_FILE).write_text(json.dumps(bundle(report("minisoc-vector:0.59.0", vuln(KEV)))))
    await job.tick()
    assert not (tmp_path / trivy.REPORT_FILE).exists()
    local = json.loads(redis.kv[trivy.LOCAL_STATUS_KEY])
    assert local["service"]["state"] == "ok" and not local["pending"] and not local["problem"]
    assert json.loads(redis.hashes[trivy.STATE_KEY][trivy.LOCAL])["targets"] == ["minisoc-vector:0.59.0"]

    (tmp_path / trivy.REPORT_FILE).write_text("{pas du json")
    await job.tick()
    assert "illisible" in json.loads(redis.kv[trivy.LOCAL_STATUS_KEY])["problem"]
    assert not (tmp_path / trivy.REPORT_FILE).exists()

    cfg["src_trivy_enabled"] = False  # intégration désactivée : rapport écarté sans être enregistré
    await trivy.forget(redis, trivy.LOCAL)
    (tmp_path / trivy.REPORT_FILE).write_text(json.dumps(bundle(report("x:1", vuln(KEV)))))
    await job.tick()
    assert not (tmp_path / trivy.REPORT_FILE).exists() and trivy.LOCAL not in redis.hashes[trivy.STATE_KEY]


def test_ingest_helpers_gzip_limit_and_ip_filter(monkeypatch):
    body = json.dumps(bundle(report("a:1", vuln(KEV)))).encode()
    assert json.loads(trivy_api._inflate(gzip.compress(body)))["host"] == "minisoc"
    with pytest.raises(HTTPException) as bad:
        trivy_api._inflate(b"pas du gzip")
    assert bad.value.status_code == 400
    monkeypatch.setattr(trivy_api, "MAX_INFLATED", 1000)
    with pytest.raises(HTTPException) as big:
        trivy_api._inflate(gzip.compress(b" " * 5000))
    assert big.value.status_code == 413
    assert trivy_api._ip_allowed("10.1.2.3", [])
    assert trivy_api._ip_allowed("10.1.2.3", ["10.1.2.0/24"]) and not trivy_api._ip_allowed("10.1.3.3", ["10.1.2.0/24"])
    assert not trivy_api._ip_allowed("pas-une-ip", ["10.0.0.0/8"])
    assert trivy_api.AGENT.is_file() and "{{MINISOC_URL}}" in trivy_api.AGENT.read_text(encoding="utf-8")
