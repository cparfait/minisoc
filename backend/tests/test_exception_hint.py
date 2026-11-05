"""Proposition d'exception après des faux positifs répétés : portée proposée, seuil, exception déjà active."""

from datetime import datetime, timezone

from sqlalchemy.dialects import postgresql

from minisoc.api.alerts import closed_as_false_positive, exception_hint, exception_target
from minisoc.ecs import FIELDS
from minisoc.models import Alert, RuleException

NATIVE = "event.module=harfanglab | host.name=PC-1 | rule.name=Encoded PowerShell"
NOW = datetime(2026, 11, 5, tzinfo=timezone.utc)


def test_target_prefers_the_detection_over_the_machine():
    assert exception_target(NATIVE) == ("rule.name", "Encoded PowerShell")


def test_target_is_the_entity_otherwise_and_never_the_whole_tool():
    assert exception_target("source.ip=1.2.3.4") == ("source.ip", "1.2.3.4")
    assert exception_target("host.name=PC-1 | user.name=bob") == ("user.name", "bob")
    assert exception_target("event.module=sophos_xgs") is None
    assert exception_target("*regroupement*=UC-02b") is None


def test_proposed_fields_can_be_saved_as_exceptions():
    for key in (NATIVE, "source.ip=1.2.3.4", "user.name=bob"):
        assert exception_target(key)[0] in FIELDS


def sql(*conditions) -> str:
    return " AND ".join(
        str(c.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True})) for c in conditions
    )


def test_detection_counts_on_every_machine_and_escapes_wildcards():
    text = sql(*closed_as_false_positive(9, "UC-30", NATIVE, "rule.name", "50%_test", NOW))
    assert "false_positive" in text and "UC-30" in text and "alerts.id != 9" in text
    assert "LIKE '%%' || 'rule.name=50/%%/_test' ESCAPE '/'" in text  # « % » doublé par le pilote


def test_other_entities_count_on_the_exact_entity():
    text = sql(*closed_as_false_positive(9, "UC-01", "source.ip=1.2.3.4", "source.ip", "1.2.3.4", NOW))
    assert "alerts.entity_key = 'source.ip=1.2.3.4'" in text


class FakeDb:
    def __init__(self, count, exceptions=(), comment="Téléphone"):
        self.count, self.exceptions, self.comment = count, exceptions, comment
        self.queries = 0

    async def execute(self, _stmt):
        self.queries += 1
        return type("Result", (), {"one": lambda _self: (self.count, NOW)})()

    async def scalars(self, _stmt):
        return type("Result", (), {"all": lambda _self: list(self.exceptions)})()

    async def scalar(self, _stmt):
        return self.comment


def open_alert(status="new", entity_key="source.ip=1.2.3.4"):
    return Alert(id=9, rule_id="UC-01", status=status, entity_key=entity_key)


async def test_hint_from_two_closures_with_last_comment():
    hint = await exception_hint(FakeDb(2), open_alert())
    assert hint["count"] == 2 and hint["field"] == "source.ip" and hint["value"] == "1.2.3.4"
    assert hint["last_comment"] == "Téléphone" and hint["days"] == 90


async def test_no_hint_below_the_threshold():
    assert await exception_hint(FakeDb(1), open_alert()) is None


async def test_no_hint_on_closed_alert_or_without_target():
    db = FakeDb(5)
    assert await exception_hint(db, open_alert(status="resolved")) is None
    assert await exception_hint(db, open_alert(entity_key="*regroupement*=UC-01")) is None
    assert db.queries == 0


async def test_no_hint_when_an_exception_already_covers_it():
    active = RuleException(rule_id="*", field="source.ip", value="1.2.3.4")
    assert await exception_hint(FakeDb(5, [active]), open_alert()) is None
    other = RuleException(rule_id="UC-01", field="source.ip", value="9.9.9.9")
    assert await exception_hint(FakeDb(5, [other]), open_alert()) is not None
