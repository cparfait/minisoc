"""Chargement des règles depuis un dossier de fichiers YAML."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

from minisoc.rules.model import Rule, RuleError

log = logging.getLogger(__name__)


def substitute(value: Any, variables: dict[str, Any]) -> Any:
    """Remplace dans les filtres les références à un réglage (« $home_countries ») par sa valeur."""
    if isinstance(value, str) and value.startswith("$") and value[1:] in variables:
        return variables[value[1:]]
    if isinstance(value, dict):
        return {k: substitute(v, variables) for k, v in value.items()}
    if isinstance(value, list):
        return [substitute(v, variables) for v in value]
    return value


def load_rules(directory: str | Path, *, strict: bool = False, variables: dict[str, Any] | None = None) -> list[Rule]:
    """Charge toutes les règles. Une règle invalide est ignorée (journalisée), sauf en mode strict.
    `variables` : valeurs des réglages cités dans les filtres (« $home_countries ») ; sans elles, la référence reste
    telle quelle (affichage)."""
    rules: list[Rule] = []
    seen: set[str] = set()
    for path in sorted(Path(directory).glob("*.y*ml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if variables and isinstance(data, dict):
                for key in ("filter", "sequence"):
                    if key in data:
                        data[key] = substitute(data[key], variables)
            rule = Rule.from_dict(data, path.name)
            if rule.id in seen:
                raise RuleError(f"{path.name} : identifiant en double {rule.id}")
            seen.add(rule.id)
            rules.append(rule)
        except (RuleError, yaml.YAMLError) as exc:
            if strict:
                raise
            log.error("règle ignorée : %s", exc)
    return rules


def load_playbook(directory: str | Path, rule: Rule) -> str:
    """Contenu texte de la fiche réflexe, limité au dossier des règles."""
    if not rule.playbook:
        return ""
    base = Path(directory).resolve()
    target = (base / rule.playbook).resolve()
    if base not in target.parents or not target.is_file():
        return ""
    return target.read_text(encoding="utf-8")
