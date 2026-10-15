"""Compilation des règles `threshold`, `sequence` et `novelty` en requêtes ClickHouse.

Identités : les comptes et les machines sont regroupés sur leur clé unifiée (`user_key`, `host_key`, voir
minisoc/identity.py) : « MAIRIE\\JDupont », « jdupont » et « jean.dupont@chatillon92.fr » sont le même compte. Les
événements reçus avant cette version n'ont pas de clé : leur nom est normalisé à la volée de la même façon (sans
domaine, sans casse ; nom court de machine).

Retards : certaines sources livrent leurs événements avec retard (journaux d'audit Microsoft 365 : 30 à 90 minutes).
Une règle évaluée sur « les N dernières minutes » les manquerait. Chaque évaluation regarde donc les événements
*reçus* depuis la précédente (`ingest_ts`, filigrane `since` tenu par le worker), avec une marge de LATE_SECONDS
sur leur date : les fenêtres sont glissantes et exactes (fonctions de fenêtre ClickHouse sur la date de
l'événement), quel que soit l'ordre d'arrivée.
"""

from __future__ import annotations

from minisoc.ecs import FIELDS, INT_COLUMNS
from minisoc.rules.filters import Params, to_sql
from minisoc.rules.model import Rule

_OPS = {">=": ">=", ">": ">", "==": "=", "<=": "<=", "<": "<"}
MAX_FIRST_EVENTS = 100000  # horodatages « first » gardés par clé (une attaque massive reste bornée en mémoire)
MAX_GROUP_EVENTS = 10000  # événements gardés par groupe pour les preuves d'une règle de seuil
LATE_SECONDS = 2 * 3600  # retard toléré d'une source (Microsoft 365 : jusqu'à 90 minutes)

# Clé unifiée ; à défaut (événements antérieurs), normalisation à la volée identique à minisoc/identity.py
USER_KEY = ("if(user_key != '', user_key, "
            "lower(splitByChar('@', substring(user_name, position(user_name, char(92)) + 1))[1]))")
HOST_KEY = ("if(host_key != '', host_key, if(match(lower(host_name), '^(ip[-_])?[0-9]{1,3}([.][0-9]{1,3}){3}$'), "
            "replaceRegexpOne(lower(host_name), '^ip[-_]', ''), lower(splitByChar('.', host_name)[1])))")
IDENTITY_KEYS = {"user.name": USER_KEY, "host.name": HOST_KEY}


def key_expr(ecs_field: str) -> str:
    """Expression SQL de regroupement d'un champ : clé unifiée pour les comptes et machines, colonne sinon."""
    return IDENTITY_KEYS.get(ecs_field) or FIELDS[ecs_field]


def _span(rule: Rule, params: Params, since: int | None, extra: int = 0) -> tuple[str, str]:
    """(période scrutée sur la date des événements, période de réception depuis la dernière évaluation)."""
    span = int(rule.window.total_seconds()) + LATE_SECONDS + extra
    return params.add(span, "UInt32"), params.add(int(since or span), "UInt32")


def threshold_query(rule: Rule, since: int | None = None) -> tuple[str, dict]:
    """Groupes ayant franchi le seuil dans une fenêtre glissante de `window` (n'importe où dans la période
    scrutée), parmi ceux qui ont reçu un événement depuis `since` secondes. first_seen / last_seen bornent les
    fenêtres en dépassement : une alerte clôturée n'est pas recréée pour une rafale déjà traitée."""
    assert rule.type == "threshold" and rule.condition
    params = Params()
    where = to_sql(rule.filter, params)
    span, recent = _span(rule, params, since)
    cond = rule.condition
    agg = "count()" if cond.function == "count" else f"uniqExact({FIELDS[cond.field]})"
    threshold = params.add(cond.value, "Int64")
    hit = f"v {_OPS[cond.op]} {threshold}"
    keys, not_empty = _groups(rule.group_by)
    partition = f"PARTITION BY {', '.join(keys)} " if rule.group_by else ""
    frame = (f"OVER ({partition}ORDER BY toUnixTimestamp64Milli(ts) "
             f"RANGE BETWEEN {int(rule.window.total_seconds() * 1000)} PRECEDING AND CURRENT ROW)")
    fresh_where = to_sql(rule.filter, params)
    received = (f"ingest_ts >= now64(3) - toIntervalSecond({recent}) AND ts >= now64(3) - toIntervalSecond({span}) "
                f"AND ({fresh_where}){not_empty}")
    if rule.group_by:
        fresh = f"({', '.join(keys)}) IN (SELECT {', '.join(keys)} FROM events WHERE {received})"
    else:
        fresh = f"(SELECT count() FROM events WHERE {received}) > 0"
    names = [f"g{i}" for i in range(len(keys))]
    aggregate = "max" if cond.op in (">=", ">", "==") else "min"
    in_window = "x -> x.1 >= first_seen AND x.1 <= last_seen"
    sql = f"""
SELECT {", ".join(names)}, value, first_seen, last_seen,
       length(arrayFilter({in_window}, pts)) AS events,
       arrayMap(x -> x.2, arraySlice(arrayFilter({in_window}, pts), 1, 50)) AS event_ids,
       modules, sample_ips, sample_users
FROM (
    SELECT {", ".join(names)},
           {aggregate}(v) AS value,
           minIf(fs, {hit}) AS first_seen,
           maxIf(ts, {hit}) AS last_seen,
           countIf({hit}) AS hits,
           groupArray({MAX_GROUP_EVENTS})((ts, toString(event_id))) AS pts,
           groupUniqArray(10)(module) AS modules,
           groupUniqArray(20)(source_ip) AS sample_ips,
           groupUniqArray(20)(user_name) AS sample_users
    FROM (
        SELECT {", ".join(f"{k} AS g{i}" for i, k in enumerate(keys))}, ts, event_id, module, source_ip, user_name,
               {agg} {frame} AS v,
               min(ts) {frame} AS fs
        FROM events
        WHERE ts >= now64(3) - toIntervalSecond({span}) AND ({where}){not_empty} AND {fresh}
    )
    GROUP BY {", ".join(names)}
    HAVING hits > 0
)
ORDER BY value DESC
LIMIT 500"""
    return sql, params.values


def sequence_query(rule: Rule, since: int | None = None) -> tuple[str, dict]:
    assert rule.type == "sequence" and rule.sequence
    seq = rule.sequence
    params = Params()
    col = FIELDS[seq.join_on]
    joined = key_expr(seq.join_on)  # comptes et machines : clé unifiée (toutes formes du nom, sans casse)
    then_where = to_sql(seq.then, params)
    within = params.add(int(seq.within.total_seconds()), "UInt32")
    span, recent = _span(rule, params, since)
    first_where = to_sql(seq.first, params)
    min_count = params.add(seq.min_count, "Int64")
    fresh_first, fresh_then = to_sql(seq.first, params), to_sql(seq.then, params)
    # Clés ayant reçu un événement (« first » ou « then ») depuis la dernière évaluation : un « first » arrivé en
    # retard, après le « then », est aussi pris en compte
    fresh = (f"SELECT {joined} FROM events WHERE ingest_ts >= now64(3) - toIntervalSecond({recent}) "
             f"AND ts >= now64(3) - toIntervalSecond({span}) - toIntervalSecond({within}) "
             f"AND (({fresh_first}) OR ({fresh_then})) AND {col} != ''")
    # Ordre respecté : pour chaque événement « then », seuls comptent les « first » survenus AVANT lui et dans les
    # `within` qui le précèdent (une réussite suivie d'échecs n'est pas une réussite après des échecs)
    sql = f"""
SELECT t.g0 AS g0,
       count() AS value,
       count() AS events,
       min(t.ts) AS first_seen,
       max(t.ts) AS last_seen,
       groupArray(50)(toString(t.event_id)) AS event_ids,
       groupUniqArray(10)(t.module) AS modules,
       groupUniqArray(20)(t.source_ip) AS sample_ips,
       groupUniqArray(20)(t.user_name) AS sample_users
FROM (
    SELECT {joined} AS g0, ts, event_id, module, source_ip, user_name FROM events
    WHERE ts >= now64(3) - toIntervalSecond({span}) AND ({then_where}) AND {col} != ''
      AND {joined} IN ({fresh})
) AS t
INNER JOIN (
    SELECT {joined} AS g0, groupArray({MAX_FIRST_EVENTS})(ts) AS fts FROM events
    WHERE ts >= now64(3) - toIntervalSecond({span}) - toIntervalSecond({within}) AND ({first_where})
      AND {col} != ''
    GROUP BY g0
    HAVING count() >= {min_count}
) AS f ON t.g0 = f.g0
WHERE arrayCount(x -> x < t.ts AND x >= t.ts - toIntervalSecond({within}), f.fts) >= {min_count}
GROUP BY g0
LIMIT 500"""
    return sql, params.values


def novelty_query(rule: Rule, since: int | None = None) -> tuple[str, dict]:
    """Valeurs reçues depuis la dernière évaluation, jamais vues pour l'entité dans ce qui avait été reçu avant
    (sur `history`) : un événement arrivé en retard est comparé à tout ce qui l'a précédé à la réception."""
    assert rule.type == "novelty" and rule.novelty
    nov = rule.novelty
    params = Params()
    keys = [key_expr(f) for f in rule.group_by[:-1]]
    columns = [FIELDS[f] for f in rule.group_by[:-1]]
    novel = FIELDS[nov.field]
    recent_where = to_sql(rule.filter, params)
    span, recent = _span(rule, params, since)
    history_where = to_sql(rule.filter, params)
    history = params.add(int(nov.history.total_seconds()), "UInt32")
    min_history = params.add(nov.min_history, "Int64")
    key_list = ", ".join(keys)
    not_empty = " AND ".join(f"{c} != ''" for c in [*columns, novel])
    past = (f"ts >= now64(3) - toIntervalSecond({history}) AND ingest_ts < now64(3) - toIntervalSecond({recent}) "
            f"AND ({history_where}) AND {not_empty}")
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
WHERE ts >= now64(3) - toIntervalSecond({span}) AND ingest_ts >= now64(3) - toIntervalSecond({recent})
  AND ({recent_where}) AND {not_empty}
  AND ({key_list}, {novel}) NOT IN (SELECT {key_list}, {novel} FROM events WHERE {past} GROUP BY {key_list}, {novel})
  AND ({key_list}) IN (SELECT {key_list} FROM events WHERE {past} GROUP BY {key_list} HAVING count() >= {min_history})
GROUP BY {", ".join(f"g{i}" for i in range(len(keys) + 1))}
LIMIT 500"""
    return sql, params.values


def _groups(group_by: list[str]) -> tuple[list[str], str]:
    if not group_by:
        return ["'global'"], ""
    keys, filters = [], []
    for fld in group_by:
        col = FIELDS[fld]
        keys.append(key_expr(fld))
        filters.append(f"{col} != 0" if col in INT_COLUMNS else f"{col} != ''")
    return keys, " AND " + " AND ".join(filters)
