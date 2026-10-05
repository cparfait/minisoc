"""Modèle d'une règle de détection et validation de son fichier YAML."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Any

from minisoc.ecs import FIELDS, SEVERITY_BY_NAME
from minisoc.frameworks import TECHNIQUE_RE
from minisoc.rules.filters import FilterError, column, validate

RULE_TYPES = ("match", "threshold", "sequence", "absence", "novelty")
QUALIFIERS = ("auth_source_ip", "auth_account", "auth_success_ip", "auth_success_user")
_DURATION = re.compile(r"^(\d+)\s*([smhd])$")
_CONDITION = re.compile(r"^(count|count_distinct)\(\s*([\w.@]*)\s*\)\s*(>=|>|==|<=|<)\s*(\d+)$")
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


class RuleError(ValueError):
    pass


def parse_duration(value: Any) -> timedelta:
    match = _DURATION.match(str(value).strip())
    if not match:
        raise RuleError(f"durée invalide : {value!r} (exemples : 30s, 10m, 1h, 7d)")
    return timedelta(**{_UNITS[match.group(2)]: int(match.group(1))})


@dataclass(frozen=True)
class Condition:
    function: str  # count | count_distinct
    field: str  # champ ECS (count_distinct)
    op: str
    value: int

    @classmethod
    def parse(cls, text: str) -> Condition:
        match = _CONDITION.match(str(text).strip())
        if not match:
            raise RuleError(f"condition invalide : {text!r} (ex. count_distinct(source.ip) >= 20)")
        function, fld, op, value = match.groups()
        if function == "count_distinct":
            if not fld:
                raise RuleError("count_distinct() attend un champ")
            column(fld)
        return cls(function, fld, op, int(value))


@dataclass(frozen=True)
class Sequence:
    """`then` survient alors que `first` s'est produit au moins `min_count` fois dans `within`."""

    first: dict
    min_count: int
    within: timedelta
    then: dict
    join_on: str  # champ ECS commun aux deux étapes


@dataclass(frozen=True)
class Novelty:
    """Valeur de `field` jamais observée pour l'entité (`group_by`) sur `history`, hors fenêtre récente."""

    field: str
    history: timedelta
    min_history: int  # nombre minimal d'occurrences passées de l'entité (évite d'alerter sur un nouvel arrivant)


@dataclass
class Rule:
    id: str
    name: str
    type: str
    severity: str  # nom de sévérité ou "from_event"
    title: str
    description: str = ""
    filter: dict = field(default_factory=dict)
    group_by: list[str] = field(default_factory=list)
    window: timedelta = timedelta(minutes=10)
    condition: Condition | None = None
    sequence: Sequence | None = None
    novelty: Novelty | None = None
    sources: dict[str, timedelta] = field(default_factory=dict)  # règles « absence »
    dedup_window: timedelta = timedelta(hours=24)
    fallback: bool = False  # règle « match » appliquée seulement si aucune autre ne correspond
    storm_limit: int = 5  # alertes distinctes par heure avant regroupement (0 = jamais)
    qualify: str = ""  # qualification automatique (voir minisoc/qualify.py)
    mitre: list[str] = field(default_factory=list)  # techniques MITRE ATT&CK détectées
    playbook: str = ""
    enabled: bool = True
    path: str = ""

    @property
    def severity_level(self) -> int:
        return SEVERITY_BY_NAME.get(self.severity, 2)

    @classmethod
    def from_dict(cls, data: dict, path: str = "") -> Rule:
        try:
            return cls._from_dict(data, path)
        except (FilterError, RuleError) as exc:
            raise RuleError(f"{path or data.get('id', '?')} : {exc}") from exc

    @classmethod
    def _from_dict(cls, data: dict, path: str) -> Rule:
        if not isinstance(data, dict):
            raise RuleError("le fichier doit contenir un objet YAML")
        for key in ("id", "name", "type", "severity"):
            if not data.get(key):
                raise RuleError(f"champ obligatoire manquant : {key}")
        rtype = data["type"]
        if rtype not in RULE_TYPES:
            raise RuleError(f"type inconnu : {rtype} (attendus : {', '.join(RULE_TYPES)})")
        severity = str(data["severity"])
        if severity != "from_event" and severity not in SEVERITY_BY_NAME:
            raise RuleError(f"sévérité inconnue : {severity}")

        flt = data.get("filter") or {}
        if flt:
            validate(flt)
        group_by = list(data.get("group_by") or [])
        for fld in group_by:
            if fld not in FIELDS:
                raise RuleError(f"group_by : champ inconnu {fld}")

        rule = cls(
            id=str(data["id"]),
            name=str(data["name"]),
            type=rtype,
            severity=severity,
            title=str(data.get("title") or data["name"]),
            description=str(data.get("description") or "").strip(),
            filter=flt,
            group_by=group_by,
            dedup_window=parse_duration(data.get("dedup_window", "24h")),
            fallback=bool(data.get("fallback", False)),
            storm_limit=int(data.get("storm_limit", 5)),
            qualify=str(data.get("qualify") or ""),
            playbook=str(data.get("playbook") or ""),
            enabled=bool(data.get("enabled", True)),
            path=path,
            mitre=[str(t).strip().upper() for t in data.get("mitre") or []],
        )
        for technique in rule.mitre:
            if not TECHNIQUE_RE.match(technique):
                raise RuleError(f"technique MITRE ATT&CK invalide : {technique} (format T1110 ou T1110.003)")

        if rule.qualify and rule.qualify not in QUALIFIERS:
            raise RuleError(f"qualification inconnue : {rule.qualify} (attendues : {', '.join(QUALIFIERS)})")
        if rule.qualify and rtype not in ("threshold", "sequence", "novelty"):
            raise RuleError("la qualification ne s'applique qu'aux règles threshold et sequence")

        if rtype == "threshold":
            rule.window = parse_duration(data.get("window", "10m"))
            rule.condition = Condition.parse(data.get("condition", ""))
            if not flt:
                raise RuleError("une règle threshold doit avoir un filtre")
        elif rtype == "sequence":
            seq = data.get("sequence") or {}
            first, then = seq.get("first") or {}, seq.get("then") or {}
            validate(first)
            validate(then)
            join_on = str(seq.get("join_on", ""))
            column(join_on)
            rule.sequence = Sequence(
                first=first,
                min_count=int(seq.get("min_count", 1)),
                within=parse_duration(seq.get("within", "24h")),
                then=then,
                join_on=join_on,
            )
            rule.window = parse_duration(data.get("window", "15m"))
            rule.group_by = [join_on]
        elif rtype == "novelty":
            nov = data.get("novelty") or {}
            fld = str(nov.get("field", ""))
            column(fld)
            if not flt or not group_by:
                raise RuleError("une règle novelty doit avoir un filtre et un group_by")
            rule.novelty = Novelty(field=fld, history=parse_duration(nov.get("history", "30d")),
                                   min_history=int(nov.get("min_history", 3)))
            rule.window = parse_duration(data.get("window", "15m"))
            rule.group_by = [*group_by, fld]
        elif rtype == "absence":
            sources = data.get("sources") or {}
            if sources == "auto":  # intégrations actives du catalogue (délais définis par intégration)
                rule.sources = {}
            elif not isinstance(sources, dict) or not sources:
                raise RuleError("une règle absence doit lister ses sources, ou indiquer « auto »")
            else:
                rule.sources = {str(name): parse_duration(delay) for name, delay in sources.items()}
            rule.group_by = ["event.module"]
        elif rtype == "match" and not flt:
            raise RuleError("une règle match doit avoir un filtre")
        return rule
