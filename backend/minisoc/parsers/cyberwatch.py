"""Cyberwatch : changements de l'état des vulnérabilités d'un actif (voir connectors/cyberwatch.py)."""

from __future__ import annotations

import json
from datetime import datetime

from minisoc.ecs import Event

MODULE = "cyberwatch"


def _list(cves: list[str], limit: int = 8) -> str:
    more = f" (+{len(cves) - limit})" if len(cves) > limit else ""
    return ", ".join(cves[:limit]) + more


def parse_cyberwatch(record: dict, received: datetime) -> Event:
    a = record.get("asset") or {}
    kind = str(record.get("kind") or "posture")
    cves = [str(c) for c in record.get("cves") or []]
    server = bool(a.get("server"))
    name = str(a.get("name") or "")
    what = "serveur" if server else "machine"
    base = dict(
        ts=received,
        module=MODULE,
        category="vulnerability",
        action=kind,
        host_name=name,
        host_ip=str(a.get("ip") or ""),
        observer="Cyberwatch",
        reference=str(a.get("console") or ""),
        raw=json.dumps(record, ensure_ascii=False, default=str),
    )
    if kind == "kev_vulnerabilities":
        return Event(
            **base,
            severity=3 if server else 2,
            rule_name="Faille activement exploitée présente (CISA KEV)",
            threat_name=_list(cves),
            message=f"{name} : {len(cves)} faille(s) activement exploitée(s) non corrigée(s) sur ce {what} "
            f"({_list(cves)}) ; {len(a.get('kev') or [])} au total, {a.get('cve_count', 0)} CVE présentes",
        )
    if kind == "prioritized_vulnerabilities":
        return Event(
            **base,
            severity=2 if server else 1,
            rule_name="Nouvelles vulnérabilités prioritaires",
            threat_name=_list(cves),
            message=f"{name} : {len(cves)} nouvelle(s) vulnérabilité(s) prioritaire(s) selon Cyberwatch "
            f"({_list(cves)}) ; {a.get('prioritized_count', 0)} prioritaire(s) au total",
        )
    if kind == "os_end_of_life":
        return Event(
            **base,
            severity=2 if server else 1,
            rule_name="Système en fin de support",
            threat_name=str(a.get("os") or ""),
            message=f"{name} : {a.get('os') or 'système'} n'est plus maintenu par l'éditeur depuis le "
            f"{a.get('eol') or '?'} (plus de correctifs de sécurité)",
        )
    return Event(**base, message=f"Cyberwatch : {kind} sur {name}")
