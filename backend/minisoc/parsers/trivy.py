"""Trivy : nouvelles failles notables d'une source (VM du Mini-SOC ou serveur), voir minisoc/trivy.py."""

from __future__ import annotations

import json
from datetime import datetime

from minisoc.ecs import Event

MODULE = "trivy"
LABELS = {
    "kev_vulnerabilities": ("Faille activement exploitée présente (CISA KEV, Trivy)", 3,
                            "faille(s) activement exploitée(s)"),
    "critical_fixable": ("Faille critique corrigeable (Trivy)", 3, "faille(s) critique(s) avec correctif disponible"),
    "high_fixable": ("Faille haute corrigeable (Trivy)", 2, "faille(s) haute(s) avec correctif disponible"),
}


def _list(cves: list[str], limit: int = 8) -> str:
    more = f" (+{len(cves) - limit})" if len(cves) > limit else ""
    return ", ".join(cves[:limit]) + more


def parse_trivy(record: dict, received: datetime) -> Event:
    kind = str(record.get("kind") or "")
    rule, severity, what = LABELS.get(kind, ("Rapport Trivy", 1, "faille(s)"))
    cves = [str(c) for c in record.get("cves") or []]
    name = str(record.get("name") or "")
    where = "les images du Mini-SOC" if record.get("local") else name
    fixes = [f"{c} → {d['fix']}" for c, d in (record.get("detail") or {}).items() if d.get("fix")][:3]
    return Event(
        ts=received,
        module=MODULE,
        kind="event",
        category="vulnerability",
        action=kind,
        severity=severity,
        host_name=name,
        rule_name=rule,
        threat_name=_list(cves),
        observer="Trivy",
        reference=f"/vulnerabilities?cve={cves[0]}" if cves else "",
        message=f"{where} : {record.get('count', len(cves))} nouvelle(s) {what} ({_list(cves)})"
        f"{' ; correctifs : ' + ', '.join(fixes) if fixes else ''}",
        raw=json.dumps(record, ensure_ascii=False, default=str),
    )
