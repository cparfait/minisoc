"""Règles ajoutées depuis l'interface (import Sigma), stockées en base et chargées avec celles des fichiers."""

from __future__ import annotations

import logging

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from minisoc.models import CustomRule
from minisoc.rules.loader import load_rules, substitute
from minisoc.rules.model import Rule, RuleError

log = logging.getLogger(__name__)


def to_rule(row: CustomRule, variables: dict | None = None) -> Rule:
    data = dict(row.definition)
    if variables and "filter" in data:
        data["filter"] = substitute(data["filter"], variables)
    rule = Rule.from_dict({**data, "enabled": row.enabled}, f"{row.source}:{row.rule_id}")
    return rule


async def custom_rules(session: AsyncSession, variables: dict | None = None) -> list[Rule]:
    out = []
    for row in (await session.scalars(select(CustomRule).order_by(CustomRule.rule_id))).all():
        try:
            out.append(to_rule(row, variables))
        except RuleError as exc:
            log.error("règle importée ignorée : %s", exc)
    return out


async def signature(session: AsyncSession) -> tuple:
    """Change dès qu'une règle importée est ajoutée, modifiée ou supprimée (rechargement du worker)."""
    row = (await session.execute(select(func.count(), func.max(CustomRule.updated_at)))).one()
    return tuple(row)


async def load_all(session: AsyncSession, rules_dir: str, variables: dict | None = None) -> list[Rule]:
    files = load_rules(rules_dir, variables=variables)
    taken = {r.id for r in files}
    extra = [r for r in await custom_rules(session, variables) if r.id not in taken]
    return files + extra
