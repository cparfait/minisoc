"""Fonctions partagées par les analyseurs."""

from __future__ import annotations

import copy
import json
import re
from datetime import datetime, timezone

_KV = re.compile(r'([A-Za-z_][\w.\-]*)=("(?:[^"\\]|\\.)*"|\S*)')
_PRI = re.compile(r"^<\d{1,3}>")
_TS_FORMATS = ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%d %H:%M:%S%z", "%Y-%m-%dT%H:%M:%S")


def parse_kv(text: str) -> dict[str, str]:
    """Analyse un texte `cle=valeur cle2="valeur avec espaces"`."""
    out: dict[str, str] = {}
    for key, value in _KV.findall(text):
        if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
            value = value[1:-1].replace('\\"', '"')
        out[key] = value
    return out


def strip_pri(line: str) -> str:
    return _PRI.sub("", line.strip(), count=1)


def parse_ts(value: object, default: datetime | None = None) -> datetime:
    """Convertit une date (ISO 8601, epoch en s ou ms) en datetime UTC ; `default` sinon."""
    fallback = default or datetime.now(timezone.utc)
    if value is None or value == "":
        return fallback
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)) or (isinstance(value, str) and value.isdigit()):
        number = float(value)
        if number > 1e12:  # millisecondes
            number /= 1000
        try:
            return datetime.fromtimestamp(number, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return fallback
    text = str(value).strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(text)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    for fmt in _TS_FORMATS:
        try:
            parsed = datetime.strptime(text, fmt)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return fallback


def first(data: dict, *keys: str, default: str = "") -> str:
    """Première valeur non vide parmi plusieurs clés (gère les clés imbriquées `a.b`)."""
    for key in keys:
        value: object = data
        for part in key.split("."):
            value = value.get(part) if isinstance(value, dict) else None
        if value not in (None, "", [], {}):
            return str(value)
    return default


RAW_LIMIT = 16000  # sous la limite de stockage du contenu brut (minisoc/ecs.py), pour garder un JSON valide
_CUT = " …[tronqué]"


def _drop(data: dict, path: str) -> None:
    *parents, last = path.split(".")
    for key in parents:
        data = data.get(key) if isinstance(data, dict) else None
        if not isinstance(data, dict):
            return
    data.pop(last, None)


def _strings(node, out: list) -> None:
    """(longueur, conteneur, clé) de chaque texte, pour raccourcir les plus longs."""
    items = node.items() if isinstance(node, dict) else enumerate(node) if isinstance(node, list) else ()
    for key, value in items:
        if isinstance(value, str):
            out.append((len(value), node, key))
        else:
            _strings(value, out)


def compact_json(data: dict, limit: int = RAW_LIMIT, drop: tuple[str, ...] = ()) -> str:
    """JSON de `data` d'au plus `limit` caractères et toujours valide : champs `drop` (redondants ou volumineux)
    retirés si nécessaire, puis textes les plus longs raccourcis. Évite qu'une troncature brute rende le
    contenu illisible (levée de doute, synchronisation)."""
    text = json.dumps(data, ensure_ascii=False, default=str)
    if len(text) <= limit:
        return text
    data = copy.deepcopy(data)
    for path in drop:
        _drop(data, path)
    text = json.dumps(data, ensure_ascii=False, default=str)
    while len(text) > limit:
        strings: list = []
        _strings(data, strings)
        size, node, key = max(strings, key=lambda s: s[0], default=(0, None, None))
        if size <= 200:
            break
        excess = len(text) - limit
        node[key] = node[key][: max(100, size - excess - len(_CUT) - 16, size // 2)] + _CUT
        text = json.dumps(data, ensure_ascii=False, default=str)
    return text if len(text) <= limit else json.dumps({"raw_truncated": True, "id": data.get("id")})
