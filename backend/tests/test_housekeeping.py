"""Ménage : chaque catégorie purgée respecte sa durée de conservation (requêtes vérifiées sans base)."""

from datetime import datetime, timezone

from minisoc.config import Settings
from minisoc.housekeeping import purge


class FakeResult:
    rowcount = 2


class FakeSession:
    def __init__(self):
        self.statements = []
        self.committed = False

    async def execute(self, stmt):
        self.statements.append(str(stmt.compile(compile_kwargs={"literal_binds": True})))
        return FakeResult()

    async def commit(self):
        self.committed = True


async def test_purge_targets_only_expired_data():
    session = FakeSession()
    counts = await purge(session, Settings(), {"alerts_retention_days": 1095},
                         now=datetime(2026, 10, 3, tzinfo=timezone.utc))
    joined = "\n".join(session.statements)
    assert session.committed and len(session.statements) == 5
    assert "DELETE FROM alerts" in joined and "'resolved', 'false_positive'" in joined
    assert "2023-10-04" in joined  # 1095 jours avant le 3 octobre 2026
    assert "DELETE FROM audit_log" not in joined  # la chaîne d'audit n'est jamais purgée
    assert counts["sessions expirées"] == 2
