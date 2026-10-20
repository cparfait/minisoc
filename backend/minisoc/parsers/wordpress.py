"""WordPress : composants vulnérables apparus sur un site (voir minisoc/connectors/wordpress.py)."""

from __future__ import annotations

import json
from datetime import datetime

from minisoc.connectors.wordpress import KINDS
from minisoc.ecs import Event

MODULE = "wordpress"


def _item(item: dict) -> str:
    kind = KINDS.get(item.get("kind"), "Composant")
    label = "WordPress" if item.get("kind") == "core" else f"{kind} {item.get('name') or item.get('slug')}"
    fix = f" → {item['fixed_in']}" if item.get("fixed_in") else " (pas encore de correctif)"
    cves = f" ({', '.join(item['cves'][:3])})" if item.get("cves") else ""
    return f"{label} {item.get('installed') or '?'}{fix}{cves}"


def parse_wordpress(record: dict, received: datetime) -> Event:
    items = [i for i in record.get("items") or [] if isinstance(i, dict)]
    cves = sorted({c for i in items for c in i.get("cves") or []})
    scores = [i["score"] for i in items if isinstance(i.get("score"), (int, float))]
    # Gravité : critique si une faille est notée 9 ou plus, sinon haute (site public, exploitable à distance)
    severity = 4 if scores and max(scores) >= 9 else 3
    more = f" (+{len(items) - 4})" if len(items) > 4 else ""
    return Event(
        ts=received,
        module=MODULE,
        kind="event",
        category="vulnerability",
        action=str(record.get("kind") or "vulnerable_component"),
        severity=severity,
        host_name=str(record.get("name") or ""),
        rule_name="Composant WordPress vulnérable",
        threat_name=", ".join(cves[:8]),
        observer="WPScan",
        reference="/cve",
        message=f"{record.get('name')} : {len(items)} composant(s) vulnérable(s) à mettre à jour : "
        + " ; ".join(_item(i) for i in items[:4]) + more,
        raw=json.dumps(record, ensure_ascii=False, default=str),
    )
