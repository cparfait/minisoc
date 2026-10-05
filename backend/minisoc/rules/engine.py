"""Évaluation des règles `match` sur un événement et outils communs (entité, titre)."""

from __future__ import annotations

import re
from dataclasses import dataclass

from minisoc.ecs import Event
from minisoc.rules.filters import matches
from minisoc.rules.model import Rule

_PLACEHOLDER = re.compile(r"\{([\w.@|]+)\}")


@dataclass
class RuleSet:
    rules: list[Rule]

    def __post_init__(self) -> None:
        active = [r for r in self.rules if r.enabled]
        self.match_rules = [r for r in active if r.type == "match" and not r.fallback]
        self.fallback_rules = [r for r in active if r.type == "match" and r.fallback]
        self.scheduled_rules = [r for r in active if r.type in ("threshold", "sequence", "novelty")]
        self.absence_rules = [r for r in active if r.type == "absence"]
        self.by_id = {r.id: r for r in self.rules}

    def match(self, event: Event) -> list[Rule]:
        hits = [r for r in self.match_rules if matches(r.filter, event)]
        if not hits:
            hits = [r for r in self.fallback_rules if matches(r.filter, event)]
        return hits


def entity_key(group_by: list[str], values: dict[str, object]) -> str:
    if not group_by:
        return "global"
    return " | ".join(f"{fld}={values.get(fld, '')}" for fld in group_by)


def render_title(template: str, values: dict[str, object]) -> str:
    """Remplace {champ.ecs} par sa valeur ; {a|b} : première valeur renseignée ; aucune valeur : « ? »."""

    def repl(match: re.Match) -> str:
        for name in match.group(1).split("|"):
            value = values.get(name)
            if value not in (None, ""):
                return str(value)
        return "?"

    return _PLACEHOLDER.sub(repl, template)[:300]
