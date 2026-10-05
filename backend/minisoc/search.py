"""Langage de recherche dans les événements (page Recherche), compilé en SQL ClickHouse paramétré.

    user.name=j.dupont outcome=failure | count by source.ip
    source.ip=10.0.0.0/8 AND NOT module=harfanglab
    host=PC-* ("mot de passe" OR password) | timeline
    rule.name~4625 | top user.name 20

Conditions : `champ=valeur` (`*` joker, réseau CIDR pour une adresse IP), `!=`, `~` (contient), `!~`,
`>`, `>=`, `<`, `<=` (champs numériques) ; texte libre (message et contenu brut) ; ET / OU / NON (ou AND, OR,
NOT ; ET implicite entre deux conditions), parenthèses. Étapes : `| count [by champ, …]`,
`| top champ [N]`, `| distinct champ [by champ]`, `| timeline [by champ]`, `| head N`.

Sécurité : seuls les champs connus sont acceptés ; toutes les valeurs sont des paramètres liés.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from datetime import timedelta

from minisoc.ecs import FIELDS, INT_COLUMNS
from minisoc.rules.filters import Params, sql_condition

ALIASES: dict[str, str | tuple[str, ...]] = {
    "ip": ("source.ip", "destination.ip", "host.ip"),
    "src": "source.ip",
    "dst": "destination.ip",
    "user": "user.name",
    "compte": "user.name",
    "host": "host.name",
    "machine": "host.name",
    "module": "event.module",
    "outil": "event.module",
    "source": "event.module",
    "action": "event.action",
    "outcome": "event.outcome",
    "resultat": "event.outcome",
    "kind": "event.kind",
    "category": "event.category",
    "severity": "event.severity",
    "rule": "rule.name",
    "detection": "rule.name",
    "country": "source.geo.country_iso_code",
    "pays": "source.geo.country_iso_code",
    "port": "destination.port",
    "service": "network.service",
    "file": "file.path",
    "dns": "dns.question.name",
    "domaine": "dns.question.registered_domain",
    "threat": "threat.name",
    "reason": "event.reason",
}
IP_COLUMNS = {"source_ip", "destination_ip", "host_ip"}
KEYWORDS = {"and": "AND", "et": "AND", "or": "OR", "ou": "OR", "not": "NOT", "non": "NOT"}
MAX_EVENTS = 1000
MAX_GROUPS = 500
TIMELINE_SERIES = 8

LIST_COLUMNS = (
    "ts, module, kind, category, action, outcome, reason, severity, source_ip, source_port, source_country, "
    "source_as, intel, destination_ip, destination_port, user_name, user_roles, host_name, host_ip, "
    "network_service, rule_name, threat_name, file_path, dns_query, observer, reference, message, "
    "substring(raw, 1, 2000) AS raw, toString(event_id) AS event_id"
)

_TOKEN = re.compile(
    r"""\s*(?:
        (?P<lp>\()|(?P<rp>\))|(?P<pipe>\|)|(?P<comma>,)|
        (?P<cond>[A-Za-z_@][\w.@]*)\s*(?P<op>>=|<=|!=|!~|=|~|>|<)\s*(?P<val>"(?:[^"\\]|\\.)*"|[^\s()|"]+)|
        (?P<quoted>"(?:[^"\\]|\\.)*")|
        (?P<word>[^\s()|",]+)
    )""",
    re.VERBOSE,
)


class SearchError(ValueError):
    pass


@dataclass
class Token:
    kind: str  # lp, rp, pipe, comma, cond, text, word, kw
    value: str = ""
    field: str = ""
    op: str = ""


@dataclass
class Stage:
    kind: str  # events, count, top, distinct, timeline
    by: list[str] = field(default_factory=list)  # champs ECS
    target: str = ""  # champ ECS (top, distinct)
    limit: int = 0


@dataclass
class Compiled:
    where: str
    params: dict
    stage: Stage


def _unquote(text: str) -> str:
    if len(text) >= 2 and text[0] == text[-1] == '"':
        return re.sub(r"\\(.)", r"\1", text[1:-1])
    return text


def tokenize(query: str) -> list[Token]:
    tokens, pos = [], 0
    query = query.strip()
    while pos < len(query):
        match = _TOKEN.match(query, pos)
        if not match or match.end() == pos:
            raise SearchError(f"syntaxe incomprise près de « {query[pos : pos + 20]} »")
        pos = match.end()
        if match.group("lp"):
            tokens.append(Token("lp"))
        elif match.group("rp"):
            tokens.append(Token("rp"))
        elif match.group("pipe"):
            tokens.append(Token("pipe"))
        elif match.group("comma"):
            tokens.append(Token("comma"))
        elif match.group("cond"):
            tokens.append(Token("cond", _unquote(match.group("val")), match.group("cond"), match.group("op")))
        elif match.group("quoted"):
            tokens.append(Token("text", _unquote(match.group("quoted"))))
        else:
            word = match.group("word")
            keyword = KEYWORDS.get(word.lower())
            tokens.append(Token("kw", keyword) if keyword else Token("word", word))
    return tokens


def resolve(name: str) -> tuple[str, ...]:
    """Champ ECS (ou alias) → champs ECS ; erreur explicite sinon."""
    key = name.lower()
    if key in FIELDS:
        return (key,)
    alias = ALIASES.get(key)
    if alias is None:
        known = ", ".join(sorted(ALIASES))
        raise SearchError(f"champ inconnu : {name} (champs ECS comme user.name, ou raccourcis : {known})")
    return alias if isinstance(alias, tuple) else (alias,)


def _single(name: str) -> str:
    fields = resolve(name)
    if len(fields) != 1:
        raise SearchError(f"« {name} » désigne plusieurs champs : préciser (ex. source.ip)")
    return fields[0]


class _Parser:
    def __init__(self, tokens: list[Token], params: Params) -> None:
        self.tokens, self.i, self.params = tokens, 0, params

    def peek(self) -> Token | None:
        return self.tokens[self.i] if self.i < len(self.tokens) else None

    def take(self) -> Token:
        token = self.tokens[self.i]
        self.i += 1
        return token

    def expression(self) -> str:
        parts = [self.conjunction()]
        while (t := self.peek()) and t.kind == "kw" and t.value == "OR":
            self.take()
            parts.append(self.conjunction())
        return parts[0] if len(parts) == 1 else "(" + " OR ".join(parts) + ")"

    def conjunction(self) -> str:
        parts = [self.unary()]
        while (t := self.peek()) and t.kind not in ("rp", "pipe") and not (t.kind == "kw" and t.value == "OR"):
            if t.kind == "kw" and t.value == "AND":
                self.take()
            parts.append(self.unary())
        return parts[0] if len(parts) == 1 else "(" + " AND ".join(parts) + ")"

    def unary(self) -> str:
        t = self.peek()
        if t is None:
            raise SearchError("condition attendue en fin de recherche")
        if t.kind == "kw" and t.value == "NOT":
            self.take()
            return f"NOT ({self.unary()})"
        if t.kind == "lp":
            self.take()
            inner = self.expression()
            if not (closing := self.peek()) or closing.kind != "rp":
                raise SearchError("parenthèse fermante manquante")
            self.take()
            return inner
        if t.kind == "cond":
            self.take()
            return self.condition(t)
        if t.kind in ("text", "word"):
            self.take()
            return self.full_text(t.value)
        raise SearchError(f"élément inattendu : {t.value or t.kind}")

    def full_text(self, text: str) -> str:
        if not text:
            raise SearchError("texte vide")
        p = self.params.add(text, "String")
        return f"(positionCaseInsensitiveUTF8(message, {p}) > 0 OR positionCaseInsensitiveUTF8(raw, {p}) > 0)"

    def condition(self, t: Token) -> str:
        fields = resolve(t.field)
        clauses = [self.one(FIELDS[f], t.op, t.value, t.field) for f in fields]
        if len(clauses) == 1:
            return clauses[0]
        joiner = " AND " if t.op in ("!=", "!~") else " OR "  # ip!=x : aucune des adresses
        return "(" + joiner.join(clauses) + ")"

    def one(self, col: str, op: str, value: str, name: str) -> str:
        if op in (">", ">=", "<", "<="):
            if col not in INT_COLUMNS:
                raise SearchError(f"« {name} » n'est pas numérique : comparaison {op} impossible")
            try:
                float(value)
            except ValueError:
                raise SearchError(f"nombre attendu après {name}{op}") from None
            return sql_condition(col, {">": "gt", ">=": "gte", "<": "lt", "<=": "lte"}[op], value, self.params)
        if op in ("~", "!~"):
            return sql_condition(col, "contains" if op == "~" else "not_contains", value, self.params)
        negate = op == "!="
        if col in IP_COLUMNS and "/" in value:
            try:
                ipaddress.ip_network(value, strict=False)
            except ValueError:
                raise SearchError(f"réseau invalide : {value}") from None
            return sql_condition(col, "not_cidr" if negate else "cidr", value, self.params)
        if "*" in value and col not in INT_COLUMNS:
            pattern = value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_").replace("*", "%")
            clause = f"toString({col}) ILIKE {self.params.add(pattern, 'String')}"
            return f"NOT ({clause})" if negate else clause
        if col in INT_COLUMNS:
            try:
                int(value)
            except ValueError:
                raise SearchError(f"nombre entier attendu pour {name}") from None
        if col in INT_COLUMNS or col in IP_COLUMNS:
            return sql_condition(col, "ne" if negate else "eq", value, self.params)
        # Texte : égalité insensible à la casse (comptes, machines, détections)
        clause = f"lowerUTF8(toString({col})) = lowerUTF8({self.params.add(value, 'String')})"
        return f"NOT ({clause})" if negate else clause


def _fields_list(tokens: list[Token], i: int) -> tuple[list[str], int]:
    out = []
    while i < len(tokens):
        t = tokens[i]
        if t.kind == "word":
            out.append(_single(t.value))
            i += 1
            if i < len(tokens) and tokens[i].kind == "comma":
                i += 1
                continue
        break
    if not out:
        raise SearchError("champ attendu après « by »")
    return out, i


def parse_stage(tokens: list[Token]) -> Stage:
    if not tokens or tokens[0].kind != "word":
        raise SearchError("étape attendue après « | » : count, top, distinct, timeline ou head")
    name = tokens[0].value.lower()
    i = 1
    stage = Stage(kind={"compte": "count", "stats": "count"}.get(name, name))
    if stage.kind in ("top", "distinct"):
        if i >= len(tokens) or tokens[i].kind != "word":
            raise SearchError(f"champ attendu après « {name} »")
        stage.target = _single(tokens[i].value)
        i += 1
    if stage.kind == "top" and i < len(tokens) and tokens[i].kind == "word" and tokens[i].value.isdigit():
        stage.limit = min(int(tokens[i].value), MAX_GROUPS)
        i += 1
    if stage.kind == "head":
        if i >= len(tokens) or not tokens[i].value.isdigit():
            raise SearchError("nombre attendu après « head »")
        stage.limit = min(int(tokens[i].value), MAX_EVENTS)
        stage.kind = "events"
        i += 1
    if i < len(tokens) and tokens[i].kind == "word" and tokens[i].value.lower() in ("by", "par"):
        stage.by, i = _fields_list(tokens, i + 1)
    if stage.kind not in ("count", "top", "distinct", "timeline", "events"):
        raise SearchError(f"étape inconnue : {name} (count, top, distinct, timeline, head)")
    if stage.kind == "timeline" and len(stage.by) > 1:
        raise SearchError("timeline : un seul champ après « by »")
    if i < len(tokens):
        raise SearchError(f"élément inattendu dans l'étape « {name} »")
    return stage


def compile_query(query: str) -> Compiled:
    tokens = tokenize(query)
    params = Params()
    # Sépare la recherche des étapes (seule la première étape d'agrégation est retenue, plus « head »)
    pipes = [i for i, t in enumerate(tokens) if t.kind == "pipe"]
    search_tokens = tokens[: pipes[0]] if pipes else tokens
    stage_tokens = []
    for n, start in enumerate(pipes):
        end = pipes[n + 1] if n + 1 < len(pipes) else len(tokens)
        stage_tokens.append(tokens[start + 1 : end])
    where = "1"
    if search_tokens:
        parser = _Parser(search_tokens, params)
        where = parser.expression()
        if parser.i < len(search_tokens):
            raise SearchError("parenthèse fermante en trop")
    stage = Stage("events")
    for st in stage_tokens:
        parsed = parse_stage(st)
        if parsed.kind == "events":  # head N
            stage.limit = parsed.limit
        elif stage.kind != "events":
            raise SearchError("une seule étape d'agrégation par recherche")
        else:
            stage = Stage(parsed.kind, parsed.by, parsed.target, parsed.limit or stage.limit)
    return Compiled(where, params.values, stage)


def interval_for(span: timedelta) -> tuple[int, str]:
    """Largeur des barres de la chronologie selon la période."""
    hours = span.total_seconds() / 3600
    if hours <= 6:
        return 5, "MINUTE"
    if hours <= 48:
        return 1, "HOUR"
    if hours <= 24 * 14:
        return 6, "HOUR"
    return 1, "DAY"


def build_sql(compiled: Compiled, span: timedelta) -> tuple[str, list[str]]:
    """SQL final (bornes temporelles {since}/{until} à fournir) et noms des colonnes de résultat (ECS)."""
    stage, where = (
        compiled.stage,
        f"ts >= {{since:DateTime64(3)}} AND ts <= {{until:DateTime64(3)}} AND ({compiled.where})",
    )
    if stage.kind == "events":
        limit = stage.limit or 200
        return f"SELECT {LIST_COLUMNS} FROM events WHERE {where} ORDER BY ts DESC LIMIT {limit}", []
    if stage.kind in ("count", "top"):
        by = stage.by or ([stage.target] if stage.target else [])
        if not by:
            return f"SELECT count() AS count FROM events WHERE {where}", ["count"]
        cols = ", ".join(f"{FIELDS[f]} AS g{i}" for i, f in enumerate(by))
        groups = ", ".join(f"g{i}" for i in range(len(by)))
        limit = stage.limit or (20 if stage.kind == "top" else MAX_GROUPS)
        return (
            f"SELECT {cols}, count() AS count FROM events WHERE {where} GROUP BY {groups} "
            f"ORDER BY count DESC LIMIT {limit}",
            [*by, "count"],
        )
    if stage.kind == "distinct":
        target = FIELDS[stage.target]
        if not stage.by:
            return (
                f"SELECT {target} AS g0, count() AS count FROM events WHERE {where} AND {target} != '' "
                f"GROUP BY g0 ORDER BY count DESC LIMIT {MAX_GROUPS}"
            ), [stage.target, "count"]
        cols = ", ".join(f"{FIELDS[f]} AS g{i}" for i, f in enumerate(stage.by))
        groups = ", ".join(f"g{i}" for i in range(len(stage.by)))
        return (
            f"SELECT {cols}, uniqExact({target}) AS distinct, groupUniqArray(10)({target}) AS sample "
            f"FROM events WHERE {where} GROUP BY {groups} ORDER BY distinct DESC LIMIT {MAX_GROUPS}",
            [*stage.by, "distinct", "sample"],
        )
    # timeline
    n, unit = interval_for(span)
    bucket = f"toStartOfInterval(ts, INTERVAL {n} {unit})"
    if stage.by:
        col = FIELDS[stage.by[0]]
        top = f"SELECT {col} FROM events WHERE {where} GROUP BY {col} ORDER BY count() DESC LIMIT {TIMELINE_SERIES}"
        return (
            f"SELECT {bucket} AS bucket, {col} AS series, count() AS count FROM events WHERE {where} "
            f"AND {col} IN ({top}) GROUP BY bucket, series ORDER BY bucket"
        ), ["bucket", stage.by[0], "count"]
    return (f"SELECT {bucket} AS bucket, count() AS count FROM events WHERE {where} GROUP BY bucket ORDER BY bucket"), [
        "bucket",
        "count",
    ]
