"""Tests for OWASP taxonomy completeness and lookup helpers."""

from __future__ import annotations

import pytest

from integration_bridge.owasp_taxonomy import (
    AGENTIC_TOP_10,
    LLM_TOP_10,
    all_agentic_categories,
    all_llm_categories,
    get_agentic_category,
    get_llm_category,
)


class TestLlmTop10:
    """The OWASP LLM Top 10 reference must be complete and well-formed."""

    def test_has_ten_entries(self) -> None:
        assert len(LLM_TOP_10) == 10

    def test_codes_are_llm01_through_llm10(self) -> None:
        expected = {f"LLM{i:02d}" for i in range(1, 11)}
        assert set(LLM_TOP_10.keys()) == expected

    def test_every_category_well_formed(self) -> None:
        for code, cat in LLM_TOP_10.items():
            assert cat.code == code
            assert cat.name, f"Empty name for {code}"
            assert cat.description, f"Empty description for {code}"
            assert cat.framework == "LLM"

    def test_llm01_is_prompt_injection(self) -> None:
        assert get_llm_category("LLM01").name == "Prompt Injection"

    def test_get_llm_category_unknown_raises(self) -> None:
        with pytest.raises(KeyError):
            get_llm_category("LLM99")

    def test_all_llm_categories_returns_ten(self) -> None:
        assert len(all_llm_categories()) == 10


class TestAgenticTop10:
    """The OWASP Agentic Top 10 (ASI) reference must be complete and well-formed."""

    def test_has_ten_entries(self) -> None:
        assert len(AGENTIC_TOP_10) == 10

    def test_codes_are_asi01_through_asi10(self) -> None:
        expected = {f"ASI{i:02d}" for i in range(1, 11)}
        assert set(AGENTIC_TOP_10.keys()) == expected

    def test_every_category_well_formed(self) -> None:
        for code, cat in AGENTIC_TOP_10.items():
            assert cat.code == code
            assert cat.name, f"Empty name for {code}"
            assert cat.description, f"Empty description for {code}"
            assert cat.framework == "AGENTIC"

    def test_asi01_is_agent_goal_hijack(self) -> None:
        assert "Goal Hijack" in get_agentic_category("ASI01").name

    def test_get_agentic_category_unknown_raises(self) -> None:
        with pytest.raises(KeyError):
            get_agentic_category("ASI99")

    def test_all_agentic_categories_returns_ten(self) -> None:
        assert len(all_agentic_categories()) == 10
