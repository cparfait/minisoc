"""Décision locale CrowdSec (bannissement déclenché par un scénario sur vos serveurs)."""

from __future__ import annotations

import json
from datetime import datetime

from minisoc.ecs import Event
from minisoc.parsers.common import first

MODULE = "crowdsec"


def parse_crowdsec(decision: dict, received: datetime) -> Event:
    scenario = first(decision, "scenario", default="ban")
    scope = first(decision, "scope").lower()
    value = first(decision, "value")
    return Event(
        ts=received,
        module=MODULE,
        kind="alert",
        category="intrusion_detection",
        action=first(decision, "type", default="ban").lower(),
        outcome="",
        severity=2,
        source_ip=value if scope == "ip" else "",
        rule_name=scenario,
        threat_name=scenario,
        intel=f"crowdsec:{scenario}",
        observer=first(decision, "origin", default="crowdsec"),
        message=f"CrowdSec : {first(decision, 'type', default='ban')} de {scope} {value} pendant "
                f"{first(decision, 'duration', default='?')} (scénario {scenario})",
        raw=json.dumps(decision, ensure_ascii=False, default=str),
    )
