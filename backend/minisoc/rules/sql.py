"""Compilation des règles `threshold` et `sequence` en requêtes ClickHouse."""

from __future__ import annotations

from minisoc.ecs import FIELDS, INT_COLUMNS
from minisoc.rules.filters import Params, to_sql
from minisoc.rules.model import Rule

_OPS = {">=": ">=", ">": ">", "==": "=", "<=": "<=", "<": "<"}


def threshold_query(rule: Rule) -> tuple[str, dict]:
    assert rule.type == "threshold" and rule.condition
    params = Params()
    where = to_sql(rule.filter, params)
    window = params.add(int(rule.window.total_seconds()), "UInt32")
    cond = rule.condition
    agg = "count()" if cond.function == "count" else f"uniqExact({FIELDS[cond.field]})"

    groups, not_empty = _groups(rule.group_by)
    threshold = params.add(cond.value, "Int64")
    sql = f"""
SELECT {", ".join(groups)},
       {agg} AS value,
       count() AS events,
       min(ts) AS first_seen,
       max(ts) AS last_seen,
       groupArray(50)(toString(event_id)) AS event_ids,
       groupUniqArray(10)(module) AS modules,
       groupUniqArray(20)(source_ip) AS sample_ips,
       groupUniqArray(20)(user_name) AS sample_users
FROM events
WHERE ts >= now64(3) - toIntervalSecond({window}) AND ({where}){not_empty}
GROUP BY {", ".join(f"g{i}" for i in range(len(groups)))}
HAVING value {_OPS[cond.op]} {threshold}
ORDER BY value DESC
LIMIT 500"""
    return sql, params.values


def sequence_query(rule: Rule) -> tuple[str, dict]:
    assert rule.type == "sequence" and rule.sequence
    seq = rule.sequence
    params = Params()
    key = FIELDS[seq.join_on]
    then_where = to_sql(seq.then, params)
    window = params.add(int(rule.window.total_seconds()), "UInt32")
    first_where = to_sql(seq.first, params)
    within = params.add(int(seq.within.total_seconds()), "UInt32")
    min_count = params.add(seq.min_count, "Int64")
    sql = f"""
SELECT {key} AS g0,
       count() AS value,
       count() AS events,
       min(ts) AS first_seen,
       max(ts) AS last_seen,
       groupArray(50)(toString(event_id)) AS event_ids,
       groupUniqArray(10)(module) AS modules,
       groupUniqArray(20)(source_ip) AS sample_ips,
       groupUniqArray(20)(user_name) AS sample_users
FROM events
WHERE ts >= now64(3) - toIntervalSecond({window}) AND ({then_where}) AND {key} != ''
  AND {key} IN (
      SELECT {key} FROM events
      WHERE ts >= now64(3) - toIntervalSecond({within}) AND ({first_where}) AND {key} != ''
      GROUP BY {key}
      HAVING count() >= {min_count}
  )
GROUP BY g0
LIMIT 500"""
    return sql, params.values


def novelty_query(rule: Rule) -> tuple[str, dict]:
    assert rule.type == "novelty" and rule.novelty
    nov = rule.novelty
    params = Params()
    keys = [FIELDS[f] for f in rule.group_by[:-1]]
    novel = FIELDS[nov.field]
    recent_where = to_sql(rule.filter, params)
    window = params.add(int(rule.window.total_seconds()), "UInt32")
    history_where = to_sql(rule.filter, params)
    history = params.add(int(nov.history.total_seconds()), "UInt32")
    min_history = params.add(nov.min_history, "Int64")
    key_list = ", ".join(keys)
    not_empty = " AND ".join(f"{c} != ''" for c in [*keys, novel])
    past = (f"ts >= now64(3) - toIntervalSecond({history}) AND ts < now64(3) - toIntervalSecond({window}) "
            f"AND ({history_where})")
    groups = ", ".join(f"{c} AS g{i}" for i, c in enumerate([*keys, novel]))
    sql = f"""
SELECT {groups},
       count() AS value,
       count() AS events,
       min(ts) AS first_seen,
       max(ts) AS last_seen,
       groupArray(50)(toString(event_id)) AS event_ids,
       groupUniqArray(10)(module) AS modules,
       groupUniqArray(20)(source_ip) AS sample_ips,
       groupUniqArray(20)(user_name) AS sample_users
FROM events
WHERE ts >= now64(3) - toIntervalSecond({window}) AND ({recent_where}) AND {not_empty}
  AND ({key_list}, {novel}) NOT IN (SELECT {key_list}, {novel} FROM events WHERE {past} GROUP BY {key_list}, {novel})
  AND ({key_list}) IN (SELECT {key_list} FROM events WHERE {past} GROUP BY {key_list} HAVING count() >= {min_history})
GROUP BY {", ".join(f"g{i}" for i in range(len(keys) + 1))}
LIMIT 500"""
    return sql, params.values


def _groups(group_by: list[str]) -> tuple[list[str], str]:
    if not group_by:
        return ["'global' AS g0"], ""
    groups, filters = [], []
    for i, fld in enumerate(group_by):
        col = FIELDS[fld]
        groups.append(f"{col} AS g{i}")
        filters.append(f"{col} != 0" if col in INT_COLUMNS else f"{col} != ''")
    return groups, " AND " + " AND ".join(filters)
