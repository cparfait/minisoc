"""Rejeu d'une règle sur l'historique (avant activation) et couverture MITRE ATT&CK des outils raccordés."""

from __future__ import annotations

import json

from minisoc.ecs import FIELDS, INT_COLUMNS
from minisoc.frameworks import TACTICS, TECHNIQUE_RE, TECHNIQUES, describe
from minisoc.rules.filters import Params, to_sql
from minisoc.rules.model import Rule

MAX_DAYS = 365
_OPS = {">=": ">=", ">": ">", "==": "=", "<=": "<=", "<": "<"}
# Tactiques citées dans les étiquettes Sigma des outils (attack.defense_evasion…) → identifiant MITRE
TACTIC_TAGS = {
    "reconnaissance": "TA0043",
    "resource_development": "TA0042",
    "initial_access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege_escalation": "TA0004",
    "defense_evasion": "TA0005",
    "credential_access": "TA0006",
    "discovery": "TA0007",
    "lateral_movement": "TA0008",
    "collection": "TA0009",
    "command_and_control": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0040",
}


class ReplayError(ValueError):
    pass


def _entity(rule: Rule) -> tuple[list[str], str]:
    """Colonnes de l'entité (group_by) et condition « renseignée »."""
    cols = [FIELDS[f] for f in rule.group_by] or ["'global'"]
    filled = " AND ".join(f"{c} != 0" if c in INT_COLUMNS else f"{c} != ''" for c in cols if c != "'global'")
    return cols, (f" AND {filled}" if filled else "")


def replay_queries(rule: Rule, days: int) -> dict[str, tuple[str, dict]]:
    """Requêtes du rejeu (testables sans base). Règles « match » et « threshold » seulement."""
    if rule.type not in ("match", "threshold"):
        raise ReplayError("rejeu possible pour les règles de correspondance et de seuil seulement")
    days = max(1, min(int(days), MAX_DAYS))
    params = Params()
    where = to_sql(rule.filter, params)
    span = params.add(days, "UInt32")
    base = f"ts >= now64(3) - toIntervalDay({span}) AND ({where})"
    cols, filled = _entity(rule)
    entity = f"tuple({', '.join(cols)})"
    groups = ", ".join(f"{c} AS g{i}" for i, c in enumerate(cols))
    group_names = ", ".join(f"g{i}" for i in range(len(cols)))
    queries: dict[str, tuple[str, dict]] = {}
    if rule.type == "match":
        dedup = params.add(int(rule.dedup_window.total_seconds()), "UInt32")
        queries["summary"] = (
            f"SELECT count() AS events, min(ts) AS first_seen, max(ts) AS last_seen, "
            f"uniqExact({entity}) AS entities, "
            f"uniqExact(tuple({', '.join(cols)}, toStartOfInterval(ts, toIntervalSecond({dedup})))) AS alerts "
            f"FROM events WHERE {base}{filled}",
            params.values,
        )
        queries["entities"] = (
            f"SELECT {groups}, count() AS count, min(ts) AS first_seen, max(ts) AS last_seen FROM events "
            f"WHERE {base}{filled} GROUP BY {group_names} ORDER BY count DESC LIMIT 20",
            params.values,
        )
    else:
        cond = rule.condition
        agg = "count()" if cond.function == "count" else f"uniqExact({FIELDS[cond.field]})"
        window = params.add(int(rule.window.total_seconds()), "UInt32")
        threshold = params.add(cond.value, "Int64")
        windows = (
            f"SELECT {groups}, toStartOfInterval(ts, toIntervalSecond({window})) AS w, {agg} AS value "
            f"FROM events WHERE {base}{filled} GROUP BY {group_names}, w "
            f"HAVING value {_OPS[cond.op]} {threshold}"
        )
        queries["summary"] = (
            f"SELECT count() AS alerts, uniqExact(tuple({group_names})) AS entities, min(w) AS first_seen, "
            f"max(w) AS last_seen, sum(value) AS events FROM ({windows})",
            params.values,
        )
        queries["entities"] = (
            f"SELECT {group_names}, count() AS count, max(value) AS peak, min(w) AS first_seen, max(w) AS last_seen "
            f"FROM ({windows}) GROUP BY {group_names} ORDER BY count DESC LIMIT 20",
            params.values,
        )
    queries["by_day"] = (
        f"SELECT toDate(ts) AS day, count() AS count FROM events WHERE {base}{filled} GROUP BY day ORDER BY day",
        params.values,
    )
    queries["sample"] = (
        f"SELECT ts, module, host_name, user_name, source_ip, rule_name, message FROM events "
        f"WHERE {base}{filled} ORDER BY ts DESC LIMIT 5",
        params.values,
    )
    return queries


def _iso(value) -> str | None:
    return value.isoformat() if hasattr(value, "isoformat") else (str(value) if value else None)


async def replay(store, rule: Rule, days: int) -> dict:
    queries = replay_queries(rule, days)
    summary = (await store.query(*queries["summary"]))[0]
    entities = await store.query(*queries["entities"])
    by_day = await store.query(*queries["by_day"])
    sample = await store.query(*queries["sample"])
    fields = rule.group_by or ["global"]
    return {
        "rule_id": rule.id,
        "type": rule.type,
        "days": max(1, min(int(days), MAX_DAYS)),
        "events": int(summary.get("events") or 0),
        "alerts": int(summary.get("alerts") or 0),
        "entities": int(summary.get("entities") or 0),
        "first_seen": _iso(summary.get("first_seen")) if summary.get("events") or summary.get("alerts") else None,
        "last_seen": _iso(summary.get("last_seen")) if summary.get("events") or summary.get("alerts") else None,
        "top": [
            {
                "entity": " | ".join(f"{f}={row.get(f'g{i}', '')}" for i, f in enumerate(fields)),
                "count": int(row["count"]),
                "peak": int(row.get("peak") or 0),
                "first_seen": _iso(row["first_seen"]),
                "last_seen": _iso(row["last_seen"]),
            }
            for row in entities
        ],
        "by_day": [{"day": _iso(r["day"]), "count": int(r["count"])} for r in by_day],
        "sample": [{k: _iso(v) if k == "ts" else v for k, v in r.items()} for r in sample],
    }


# ---------- Couverture par les outils ----------


def tool_coverage_from_tags(rows: list[list[str]]) -> dict[str, dict]:
    """Étiquettes Sigma des alertes d'outils (attack.t1059.001, attack.execution…) → technique : {count, tactics}."""
    out: dict[str, dict] = {}
    for tags in rows:
        tags = [str(t).lower() for t in tags or []]
        tactics = {TACTIC_TAGS[t[7:]] for t in tags if t.startswith("attack.") and t[7:] in TACTIC_TAGS}
        for tag in tags:
            if not tag.startswith("attack.t"):
                continue
            technique = tag[7:].upper()
            if not TECHNIQUE_RE.match(technique):
                continue
            known = set(TECHNIQUES.get(technique, ("", ()))[1])
            entry = out.setdefault(technique, {"count": 0, "tactics": set()})
            entry["count"] += 1
            entry["tactics"] |= tactics or known
    return out


async def tool_coverage(store, days: int = 90) -> dict[str, dict]:
    rows = await store.query(
        "SELECT JSONExtract(raw, 'tags', 'Array(String)') AS tags FROM events "
        "WHERE ts >= now64(3) - toIntervalDay({d:UInt32}) AND kind = 'alert' AND isValidJSON(raw) "
        "AND JSONHas(raw, 'tags') LIMIT 100000",
        {"d": days},
    )
    return tool_coverage_from_tags([r["tags"] for r in rows])


def merged_coverage(rule_techniques: dict[str, list[str]], tools: dict[str, dict]) -> list[dict]:
    """Par tactique : techniques couvertes par les règles du Mini-SOC et/ou détectées par les outils."""
    out = []
    for tactic_id, tactic_name in TACTICS.items():
        techniques: dict[str, dict] = {}
        for rule_id, techs in rule_techniques.items():
            for tech in techs:
                if tactic_id in TECHNIQUES.get(tech, ("", ()))[1]:
                    techniques.setdefault(tech, {"rules": [], "tool_hits": 0})["rules"].append(rule_id)
        for tech, info in tools.items():
            if tactic_id in info["tactics"]:
                techniques.setdefault(tech, {"rules": [], "tool_hits": 0})["tool_hits"] = info["count"]
        out.append(
            {
                "id": tactic_id,
                "name": tactic_name,
                "techniques": [
                    {
                        **describe(t),
                        "rules": sorted(v["rules"]),
                        "tool_hits": v["tool_hits"],
                        "covered_by": ("both" if v["rules"] and v["tool_hits"] else "rules" if v["rules"] else "tools"),
                    }
                    for t, v in sorted(techniques.items())
                ],
            }
        )
    return out


def dumps(value) -> str:
    return json.dumps(value, ensure_ascii=False, default=str)
