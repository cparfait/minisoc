"""Filtres de règles : une même syntaxe évaluée en Python (événement par événement) ou compilée en SQL.

Syntaxe :
    champ: valeur                 égalité
    champ: [v1, v2]               appartenance
    champ: {op: valeur}           opérateurs : eq, ne, in, not_in, contains, not_contains,
                                  gt, gte, lt, lte, exists, cidr, not_cidr,
                                  ieq, startswith, endswith (texte, insensibles à la casse ; liste = l'une des valeurs)
    any: [filtre, filtre]         OU
    all: [filtre, filtre]         ET
    not: filtre                   NON
"""

from __future__ import annotations

import ipaddress
from typing import Any

from minisoc.ecs import FIELDS, INT_COLUMNS, Event

OPERATORS = {"eq", "ne", "in", "not_in", "contains", "not_contains", "gt", "gte", "lt", "lte", "exists", "cidr",
             "not_cidr", "ieq", "startswith", "endswith"}
COMBINATORS = {"any", "all", "not"}


class FilterError(ValueError):
    pass


def column(ecs_field: str) -> str:
    try:
        return FIELDS[ecs_field]
    except KeyError:
        raise FilterError(f"champ inconnu : {ecs_field}") from None


def validate(flt: Any) -> None:
    if not isinstance(flt, dict):
        raise FilterError("un filtre doit être un dictionnaire")
    for key, value in flt.items():
        if key in ("any", "all"):
            if not isinstance(value, list) or not value:
                raise FilterError(f"`{key}` attend une liste non vide de filtres")
            for sub in value:
                validate(sub)
        elif key == "not":
            validate(value)
        else:
            column(key)
            if isinstance(value, dict):
                unknown = set(value) - OPERATORS
                if unknown:
                    raise FilterError(f"opérateur inconnu pour {key} : {', '.join(sorted(unknown))}")
                for op in ("cidr", "not_cidr"):
                    for net in _as_list(value.get(op, [])):
                        try:
                            ipaddress.ip_network(net, strict=False)
                        except ValueError as exc:
                            raise FilterError(f"réseau invalide pour {key} : {net}") from exc


# --- Évaluation Python -------------------------------------------------------------------------


def matches(flt: dict, event: Event) -> bool:
    for key, expected in flt.items():
        if key == "any":
            if not any(matches(sub, event) for sub in expected):
                return False
        elif key == "all":
            if not all(matches(sub, event) for sub in expected):
                return False
        elif key == "not":
            if matches(expected, event):
                return False
        elif not _match_field(event.get(key), expected):
            return False
    return True


def _match_field(actual: Any, expected: Any) -> bool:
    if isinstance(expected, dict):
        return all(_apply(op, actual, value) for op, value in expected.items())
    if isinstance(expected, list):
        return _apply("in", actual, expected)
    return _apply("eq", actual, expected)


def _apply(op: str, actual: Any, value: Any) -> bool:
    if op == "eq":
        return _norm(actual) == _norm(value)
    if op == "ne":
        return _norm(actual) != _norm(value)
    if op == "in":
        return _norm(actual) in {_norm(v) for v in _as_list(value)}
    if op == "not_in":
        return _norm(actual) not in {_norm(v) for v in _as_list(value)}
    if op == "ieq":
        return any(_norm(actual).lower() == str(v).lower() for v in _as_list(value))
    if op == "startswith":
        return any(_norm(actual).lower().startswith(str(v).lower()) for v in _as_list(value))
    if op == "endswith":
        return any(_norm(actual).lower().endswith(str(v).lower()) for v in _as_list(value))
    if op == "contains":
        return any(str(v).lower() in str(actual).lower() for v in _as_list(value))
    if op == "not_contains":
        return not any(str(v).lower() in str(actual).lower() for v in _as_list(value))
    if op in ("gt", "gte", "lt", "lte"):
        try:
            a, b = float(actual), float(value)
        except (TypeError, ValueError):
            return False
        return {"gt": a > b, "gte": a >= b, "lt": a < b, "lte": a <= b}[op]
    if op == "exists":
        return bool(actual not in (None, "", 0)) == bool(value)
    if op in ("cidr", "not_cidr"):
        try:
            ip = ipaddress.ip_address(str(actual))
        except ValueError:
            return False  # adresse absente ou invalide : jamais de correspondance
        inside = any(ip in ipaddress.ip_network(net, strict=False) for net in _as_list(value))
        return inside if op == "cidr" else not inside
    raise FilterError(f"opérateur inconnu : {op}")


def _norm(value: Any) -> str:
    return "" if value is None else str(value)


def _as_list(value: Any) -> list:
    return value if isinstance(value, list) else [value]


# --- Compilation SQL (ClickHouse, paramètres liés côté serveur) --------------------------------


class Params:
    """Accumule les paramètres liés : aucune valeur de règle n'est concaténée dans le SQL."""

    def __init__(self) -> None:
        self.values: dict[str, Any] = {}

    def add(self, value: Any, ch_type: str) -> str:
        name = f"p{len(self.values)}"
        self.values[name] = value
        return f"{{{name}:{ch_type}}}"


def to_sql(flt: dict, params: Params) -> str:
    clauses: list[str] = []
    for key, expected in flt.items():
        if key == "any":
            clauses.append("(" + " OR ".join(to_sql(sub, params) for sub in expected) + ")")
        elif key == "all":
            clauses.append("(" + " AND ".join(to_sql(sub, params) for sub in expected) + ")")
        elif key == "not":
            clauses.append(f"NOT ({to_sql(expected, params)})")
        else:
            col = column(key)
            ops = expected if isinstance(expected, dict) else {"in" if isinstance(expected, list) else "eq": expected}
            clauses.extend(_sql_op(col, op, value, params) for op, value in ops.items())
    return " AND ".join(clauses) if clauses else "1"


def _sql_op(col: str, op: str, value: Any, params: Params) -> str:
    is_int = col in INT_COLUMNS
    scalar_type = "Int64" if is_int else "String"

    def cast(v: Any) -> Any:
        return int(v) if is_int else str(v)

    if op == "eq":
        return f"{col} = {params.add(cast(value), scalar_type)}"
    if op == "ne":
        return f"{col} != {params.add(cast(value), scalar_type)}"
    if op == "in":
        return f"{col} IN {params.add([cast(v) for v in _as_list(value)], f'Array({scalar_type})')}"
    if op == "not_in":
        return f"{col} NOT IN {params.add([cast(v) for v in _as_list(value)], f'Array({scalar_type})')}"
    if op in ("ieq", "startswith", "endswith"):
        fn = {"ieq": "equals", "startswith": "startsWith", "endswith": "endsWith"}[op]
        terms = " OR ".join(
            f"{fn}(lowerUTF8(toString({col})), lowerUTF8({params.add(str(v), 'String')}))" for v in _as_list(value)
        )
        return f"({terms})"
    if op in ("contains", "not_contains"):
        terms = " OR ".join(
            f"positionCaseInsensitiveUTF8(toString({col}), {params.add(str(v), 'String')}) > 0" for v in _as_list(value)
        )
        return f"({terms})" if op == "contains" else f"NOT ({terms})"
    if op in ("gt", "gte", "lt", "lte"):
        sign = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[op]
        return f"{col} {sign} {params.add(float(value), 'Float64')}"
    if op == "exists":
        empty = f"{col} != 0" if is_int else f"{col} != ''"
        return empty if value else f"NOT ({empty})"
    if op in ("cidr", "not_cidr"):
        valid = f"(isIPv4String({col}) OR isIPv6String({col}))"
        ranges = " OR ".join(
            f"isIPAddressInRange({col}, {params.add(str(net), 'String')})" for net in _as_list(value)
        )
        return f"({valid} AND ({ranges}))" if op == "cidr" else f"({valid} AND NOT ({ranges}))"
    raise FilterError(f"opérateur inconnu : {op}")


def sql_condition(col: str, op: str, value: Any, params: Params) -> str:
    """Condition SQL paramétrée sur une colonne (réutilisée par le langage de recherche)."""
    return _sql_op(col, op, value, params)
