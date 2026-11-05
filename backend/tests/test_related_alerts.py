"""Alertes liées en une requête et contexte des alertes ouvertes gardé quelques secondes."""

import json
import re

from minisoc.api import alerts as api
from minisoc.api.alerts import related_labels, related_lookups
from minisoc.models import Alert


def alert(entity_key="", **details):
    return Alert(entity_key=entity_key, details=details)


LOOKUPS = related_lookups(["PC-1"], [r"MAIRIE\j.dupont"], ["1.2.3.4"])


def test_labels_name_each_value_cited():
    both = alert("host.name=PC-1 | rule.name=X", sample_users=[r"MAIRIE\j.dupont"])
    assert related_labels(both, LOOKUPS) == ["machine PC-1", r"compte MAIRIE\j.dupont"]
    assert related_labels(alert("source.ip=1.2.3.4"), LOOKUPS) == ["IP 1.2.3.4"]


def test_labels_ignore_case_and_near_values():
    assert related_labels(alert("host.name=pc-1"), LOOKUPS) == ["machine PC-1"]
    assert related_labels(alert("host.name=PC-10"), LOOKUPS) == []
    assert related_labels(alert("source.ip=1.2.3.45"), LOOKUPS) == []


def test_combined_pattern_finds_what_each_label_finds():
    combined = "|".join(p for p, _ in LOOKUPS)
    for item in (alert("host.name=PC-1"), alert("source.ip=1.2.3.4"), alert("x=y", sample_ips=["1.2.3.4"])):
        text = f"{item.entity_key} {json.dumps(item.details, ensure_ascii=False)}"
        assert re.search(combined, text, re.I) and related_labels(item, LOOKUPS)


def test_lookups_are_capped_per_kind_and_skip_blanks():
    lookups = related_lookups(["A", "B", "C", "D"], ["", "  "], ["1.1.1.1"])
    assert [label for _, label in lookups] == ["machine A", "machine B", "machine C", "IP 1.1.1.1"]


async def test_open_context_is_kept_a_few_seconds(monkeypatch):
    calls = []

    async def light(_db):
        calls.append(1)
        return []

    monkeypatch.setattr(api, "_open_light", light)
    monkeypatch.setattr(api, "_open_context_cache", None)
    clock = [100.0]
    monkeypatch.setattr(api.time, "monotonic", lambda: clock[0])
    await api.open_context(None)
    await api.open_context(None)
    assert len(calls) == 1
    clock[0] += api.OPEN_CONTEXT_SECONDS + 1
    await api.open_context(None)
    assert len(calls) == 2
