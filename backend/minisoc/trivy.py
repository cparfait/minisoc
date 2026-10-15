"""Trivy : vulnérabilités des images Docker et des systèmes, analysés par Trivy (Aqua Security, open source).

Deux provenances, même traitement :
- **locale** : le service minisoc-trivy de la VM (deploy/trivy) analyse les images du Mini-SOC et les paquets de
  la VM chaque semaine, après chaque mise à jour ou à la demande, et dépose le rapport dans le dossier d'échange
  (/var/lib/minisoc/trivy), lu par le worker (TrivyLocalJob). Le service tourne sur l'hôte : aucun conteneur
  n'a accès au socket Docker ;
- **serveurs** : le script minisoc-trivy-agent, installé sur un serveur, l'analyse chaque semaine et envoie le
  rapport à POST /api/ingest/trivy avec le jeton propre à ce serveur.

Paquet envoyé : {"agent": "minisoc-trivy/1", "host": "...", "scanned_at": "...", "reports": [<JSON Trivy>, ...]}.
Le rapport est réduit à l'essentiel (CVE, gravité, composant, version corrigée), gardé dans Redis à côté du relevé
Cyberwatch (même forme, même page Vulnérabilités), puis comparé au précédent : les nouvelles failles activement
exploitées (catalogue CISA KEV) et critiques corrigeables donnent une alerte (règles UC-52 et UC-53).
"""

from __future__ import annotations

import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import async_sessionmaker

from minisoc import bus
from minisoc.settings_store import store as settings_store

log = logging.getLogger(__name__)

MODULE = "trivy"
STATE_KEY = "minisoc:trivy:sources"  # clé de la source -> état JSON (dernier rapport réduit)
SCAN_NOW_KEY = "minisoc:trivy:scan_now"  # demande d'analyse locale (bouton « Analyser maintenant »)
LOCAL_STATUS_KEY = "minisoc:trivy:local"  # état du service minisoc-trivy de la VM, relu par le worker
LOCAL = "local"
LOCAL_NAME = "Mini-SOC (VM)"
# Dossier d'échange avec le service de la VM : rapport déposé, état de l'analyse, demande d'analyse
REPORT_FILE = "report.json"
STATUS_FILE = "status.json"
SCAN_FLAG = "scan-now"
MAX_REPORT_BYTES = 300 * 1024 * 1024
CHECK_SECONDS = 15
MAX_REPORTS = 300
MAX_VULNS = 30000
MAX_PKGS_PER_CVE = 20
SEVERITY_SCORE = {"CRITICAL": 9.5, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.0}
SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


class TrivyError(ValueError):
    pass


def _score(vuln: dict) -> float | None:
    """Score CVSS v3 (NVD d'abord, sinon l'éditeur) ; à défaut, une valeur selon la gravité Trivy."""
    cvss = vuln.get("CVSS") if isinstance(vuln.get("CVSS"), dict) else {}
    scores = [v.get("V3Score") for k, v in sorted(cvss.items(), key=lambda kv: kv[0] != "nvd") if isinstance(v, dict)]
    scores = [float(s) for s in scores if isinstance(s, (int, float))]
    if scores:
        return scores[0]
    return SEVERITY_SCORE.get(str(vuln.get("Severity") or "").upper())


def compact(bundle: dict) -> dict:
    """Paquet de rapports Trivy → état réduit (une entrée par CVE, composants touchés, version corrigée)."""
    if not isinstance(bundle, dict) or not isinstance(bundle.get("reports"), list):
        raise TrivyError("paquet Trivy attendu : {host, reports: [...]}")
    reports = bundle["reports"][:MAX_REPORTS]
    targets: list[str] = []
    vulns: dict[str, dict] = {}
    for report in reports:
        if not isinstance(report, dict):
            continue
        artifact = str(report.get("ArtifactName") or "?")[:200]
        targets.append(artifact)
        for result in report.get("Results") or []:
            for v in (result or {}).get("Vulnerabilities") or []:
                code = str(v.get("VulnerabilityID") or "").upper()
                if not code.startswith("CVE-") or len(vulns) >= MAX_VULNS and code not in vulns:
                    continue
                severity = str(v.get("Severity") or "UNKNOWN").upper()
                fixed_version = str(v.get("FixedVersion") or "")
                entry = vulns.setdefault(code, {"severity": severity, "score": _score(v), "fixed": False,
                                                "title": str(v.get("Title") or "")[:200], "pkgs": []})
                if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER.get(entry["severity"], 0):
                    entry["severity"] = severity
                score = _score(v)
                if score is not None and (entry["score"] is None or score > entry["score"]):
                    entry["score"] = score
                entry["fixed"] = entry["fixed"] or bool(fixed_version)
                if len(entry["pkgs"]) < MAX_PKGS_PER_CVE:
                    entry["pkgs"].append([artifact, str(v.get("PkgName") or "")[:100],
                                          str(v.get("InstalledVersion") or "")[:60], fixed_version[:60]])
    return {
        "host": str(bundle.get("host") or "")[:128],
        "scanned_at": str(bundle.get("scanned_at") or "")[:40] or datetime.now(timezone.utc).isoformat(),
        "targets": sorted(set(targets)),
        "vulns": vulns,
    }


def state(key: str, name: str, report: dict, received: datetime) -> dict:
    """État d'une source, de la même forme qu'un actif Cyberwatch (page Vulnérabilités, vue par CVE)."""
    vulns = report["vulns"]
    return {
        "id": f"trivy:{key}",
        "key": key,
        "name": name or report["host"] or key,
        "host": report["host"],
        "server": True,
        "os": f"Trivy : {len(report['targets'])} cible(s) analysée(s)",
        "ip": "",
        "console": "",
        "source": "trivy",
        "scanned_at": report["scanned_at"],
        "received_at": received.isoformat(),
        "targets": report["targets"],
        "cves": {code: [v["score"], None, 0] for code, v in vulns.items()},
        "vulns": vulns,
    }


def counts(st: dict, kev: set[str]) -> dict:
    vulns = st.get("vulns") or {}
    return {
        "total": len(vulns),
        "critical": sum(1 for v in vulns.values() if v["severity"] == "CRITICAL"),
        "high": sum(1 for v in vulns.values() if v["severity"] == "HIGH"),
        "critical_fixable": sum(1 for v in vulns.values() if v["severity"] == "CRITICAL" and v["fixed"]),
        "high_fixable": sum(1 for v in vulns.values() if v["severity"] == "HIGH" and v["fixed"]),
        "kev": sum(1 for code in vulns if code in kev),
    }


def findings(previous: dict | None, current: dict, kev: set[str], alert_high: bool) -> list[dict]:
    """Nouvelles failles depuis le rapport précédent, regroupées par nature (une alerte par source et nature)."""
    before = set((previous or {}).get("vulns") or {})
    new = {code: v for code, v in current["vulns"].items() if code not in before}
    groups = {
        "kev_vulnerabilities": sorted(c for c in new if c in kev),
        "critical_fixable": sorted(c for c, v in new.items()
                                   if c not in kev and v["severity"] == "CRITICAL" and v["fixed"]),
    }
    if alert_high:
        groups["high_fixable"] = sorted(c for c, v in new.items()
                                        if c not in kev and v["severity"] == "HIGH" and v["fixed"])
    records = []
    for kind, codes in groups.items():
        if not codes:
            continue
        records.append({
            "type": "findings",
            "kind": kind,
            "source": current["key"],
            "name": current["name"],
            "local": current["key"] == LOCAL,
            "targets": current["targets"],
            "cves": codes[:50],
            "count": len(codes),
            "detail": {c: {"severity": current["vulns"][c]["severity"],
                           "fix": next((p[3] for p in current["vulns"][c]["pkgs"] if p[3]), ""),
                           "where": sorted({p[0] for p in current["vulns"][c]["pkgs"]})[:5]}
                       for c in codes[:20]},
        })
    return records


def load_states(raw: dict) -> dict[str, dict]:
    out = {}
    for key, value in (raw or {}).items():
        try:
            out[key] = json.loads(value)
        except ValueError:
            continue
    return out


async def ingest(redis: aioredis.Redis, key: str, name: str, bundle: dict, *, alert_high: bool = False,
                 now: datetime | None = None) -> dict:
    """Enregistre le rapport d'une source et publie les nouvelles failles notables. Retourne un résumé."""
    from minisoc.threat_feeds import KEV_KEY

    now = now or datetime.now(timezone.utc)
    report = compact(bundle)
    current = state(key, name, report, now)
    raw = await redis.hget(STATE_KEY, key)
    previous = json.loads(raw) if raw else None
    kev = set(await redis.hkeys(KEV_KEY))
    records = findings(previous, current, kev, alert_high)
    await redis.hset(STATE_KEY, key, json.dumps(current, ensure_ascii=False))
    await bus.publish(redis, MODULE, [json.dumps(r, ensure_ascii=False) for r in records])
    await bus.heartbeat(redis, MODULE)
    return {"source": name, "targets": len(report["targets"]), **counts(current, kev),
            "new_alerts": [r["kind"] for r in records]}


async def forget(redis: aioredis.Redis, key: str) -> None:
    await redis.hdel(STATE_KEY, key)


def summary(st: dict, kev: set[str]) -> dict:
    """Une source pour l'interface : nom, dates, cibles analysées et nombres de failles."""
    return {"key": st.get("key"), "name": st.get("name"), "host": st.get("host"), "local": st.get("key") == LOCAL,
            "scanned_at": st.get("scanned_at"), "received_at": st.get("received_at"),
            "targets": st.get("targets") or [], **counts(st, kev)}


def by_cve(states: dict[str, dict], code: str) -> list[dict]:
    """Sources touchées par une CVE : composant, version installée et version corrigée, cible par cible."""
    out = []
    for st in states.values():
        v = (st.get("vulns") or {}).get(code)
        if not v:
            continue
        out.append({"key": st.get("key"), "name": st.get("name"), "local": st.get("key") == LOCAL,
                    "scanned_at": st.get("scanned_at"), "severity": v["severity"], "score": v["score"],
                    "fixed": v["fixed"], "title": v["title"],
                    "pkgs": [{"target": t, "pkg": p, "installed": i, "fix": f} for t, p, i, f in v["pkgs"]]})
    out.sort(key=lambda r: (not r["local"], r["name"] or ""))
    return out


def _read_json(path: Path) -> dict | None:
    try:
        if path.stat().st_size > MAX_REPORT_BYTES:
            raise TrivyError(f"{path.name} trop volumineux ({path.stat().st_size // 1048576} Mo)")
        data = json.loads(path.read_bytes())
    except FileNotFoundError:
        return None
    except ValueError as exc:
        raise TrivyError(f"{path.name} illisible : {exc}") from None
    return data if isinstance(data, dict) else None


class TrivyLocalJob:
    """Tâche du worker : transmet les demandes d'analyse au service de la VM, lit son état et ses rapports."""

    def __init__(self, sessions: async_sessionmaker, redis: aioredis.Redis, directory: str) -> None:
        self.sessions = sessions
        self.redis = redis
        self.directory = Path(directory)

    async def run(self) -> None:
        while True:
            try:
                await self.tick()
            except Exception:  # noqa: BLE001 - la tâche continue au passage suivant
                log.exception("Trivy : lecture du dossier d'échange en échec")
            await asyncio.sleep(CHECK_SECONDS)

    async def tick(self) -> None:
        async with self.sessions() as session:
            cfg = await settings_store.load(session)
        problem = ""
        if await self.redis.get(SCAN_NOW_KEY):
            try:
                (self.directory / SCAN_FLAG).write_text(datetime.now(timezone.utc).isoformat(), encoding="utf-8")
                await self.redis.delete(SCAN_NOW_KEY)
            except OSError as exc:
                problem = f"demande d'analyse non transmise au service de la VM ({exc.strerror or exc})"
        try:
            service = await asyncio.to_thread(_read_json, self.directory / STATUS_FILE) or {}
        except TrivyError as exc:
            service = {"state": "error", "message": str(exc)}
        try:
            bundle = await asyncio.to_thread(_read_json, self.directory / REPORT_FILE)
        except TrivyError as exc:
            bundle, problem = None, str(exc)
            (self.directory / REPORT_FILE).unlink(missing_ok=True)
        if bundle is not None:
            if cfg.get("src_trivy_enabled", True):
                try:
                    result = await ingest(self.redis, LOCAL, LOCAL_NAME, bundle,
                                          alert_high=bool(cfg.get("trivy_alert_high", False)))
                    log.info("Trivy : rapport de la VM lu (%s cible(s), %s CVE)", result["targets"], result["total"])
                except TrivyError as exc:
                    problem = f"rapport de la VM refusé : {exc}"
            try:
                (self.directory / REPORT_FILE).unlink(missing_ok=True)
            except OSError as exc:
                problem = f"rapport lu mais impossible à effacer ({exc.strerror or exc})"
        await self.redis.set(LOCAL_STATUS_KEY, json.dumps({
            "service": service,
            "pending": (self.directory / SCAN_FLAG).exists() or bool(await self.redis.get(SCAN_NOW_KEY)),
            "problem": problem,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        }, ensure_ascii=False))
