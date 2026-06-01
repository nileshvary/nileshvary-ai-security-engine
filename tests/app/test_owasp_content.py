"""Tests for components.owasp_content — shape and partitioning."""

from __future__ import annotations

import pytest

from components.owasp_content import (
    ACTIVE_CATEGORIES,
    ESCALATION_CATEGORIES,
    OWASP_CONTENT,
    get,
    is_escalation,
)


_REQUIRED_KEYS = {
    "name",
    "color",
    "icon",
    "danger_explanation",
    "fix_explanation",
    "strategy_icon",
    "escalation_note",
    "external_tools",
}


def test_exactly_ten_categories() -> None:
    assert len(OWASP_CONTENT) == 10
    assert set(OWASP_CONTENT.keys()) == {f"LLM{i:02d}" for i in range(1, 11)}


@pytest.mark.parametrize("code", sorted(OWASP_CONTENT.keys()))
def test_every_entry_has_required_keys(code: str) -> None:
    entry = OWASP_CONTENT[code]
    assert _REQUIRED_KEYS.issubset(entry.keys())
    assert entry["name"]
    assert entry["color"].startswith("#")
    assert entry["icon"]
    assert entry["danger_explanation"]
    assert entry["fix_explanation"]
    assert entry["strategy_icon"]
    assert isinstance(entry["external_tools"], list)


@pytest.mark.parametrize("code", sorted(ESCALATION_CATEGORIES))
def test_escalation_categories_have_note_and_tools(code: str) -> None:
    entry = OWASP_CONTENT[code]
    assert entry["escalation_note"] is not None and entry["escalation_note"]
    assert len(entry["external_tools"]) >= 1


@pytest.mark.parametrize("code", sorted(ACTIVE_CATEGORIES))
def test_active_categories_have_no_escalation_note(code: str) -> None:
    entry = OWASP_CONTENT[code]
    assert entry["escalation_note"] is None
    assert entry["external_tools"] == []


def test_active_and_escalation_sets_partition_all_ten() -> None:
    assert ACTIVE_CATEGORIES.isdisjoint(ESCALATION_CATEGORIES)
    assert ACTIVE_CATEGORIES | ESCALATION_CATEGORIES == set(OWASP_CONTENT.keys())


def test_get_returns_entry() -> None:
    assert get("LLM01")["name"] == "Prompt Injection"


def test_get_raises_on_unknown() -> None:
    with pytest.raises(KeyError):
        get("LLM99")


def test_is_escalation_matches_set() -> None:
    for code in ACTIVE_CATEGORIES:
        assert is_escalation(code) is False
    for code in ESCALATION_CATEGORIES:
        assert is_escalation(code) is True
