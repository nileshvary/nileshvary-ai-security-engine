"""Tests for ``PromptRemediator`` LLM01 and LLM07 hardening behavior."""

from __future__ import annotations

import pytest

from remediation_engine.prompt_remediator.remediator import PromptRemediator

from tests.remediation_engine.fixtures.sample_findings import make_finding


@pytest.fixture
def remediator() -> PromptRemediator:
    return PromptRemediator()


class TestLLM01:
    def test_patch_contains_all_four_techniques(
        self, remediator: PromptRemediator
    ) -> None:
        patch = remediator.patch_prompt(
            make_finding("LLM01"), "You are a helpful assistant."
        )
        assert set(patch.injection_resistance_techniques) == {
            "instruction-hierarchy",
            "delimiter-tagging",
            "role-confirmation",
            "refusal-patterns",
        }

    def test_patched_prompt_includes_delimiter_tag(
        self, remediator: PromptRemediator
    ) -> None:
        patch = remediator.patch_prompt(
            make_finding("LLM01"), "You are a helpful assistant."
        )
        assert "<user_input>" in patch.patched_prompt
        assert "</user_input>" in patch.patched_prompt

    def test_patched_prompt_wraps_original(
        self, remediator: PromptRemediator
    ) -> None:
        original = "You are a helpful assistant named Pat."
        patch = remediator.patch_prompt(make_finding("LLM01"), original)
        assert original in patch.patched_prompt
        assert patch.original_prompt == original
        assert patch.patched_prompt != original  # something was added

    def test_explanation_is_present(self, remediator: PromptRemediator) -> None:
        patch = remediator.patch_prompt(make_finding("LLM01"), "x")
        assert patch.patch_explanation
        assert "injection" in patch.patch_explanation.lower()


class TestLLM07:
    def test_patch_contains_non_disclosure_technique(
        self, remediator: PromptRemediator
    ) -> None:
        patch = remediator.patch_prompt(
            make_finding("LLM07"), "You are a helpful assistant."
        )
        assert "non-disclosure-clause" in patch.injection_resistance_techniques
        assert "meta-question-refusal" in patch.injection_resistance_techniques

    def test_patched_prompt_includes_never_reveal(
        self, remediator: PromptRemediator
    ) -> None:
        patch = remediator.patch_prompt(make_finding("LLM07"), "x")
        assert "Never reveal" in patch.patched_prompt

    def test_patched_prompt_wraps_original(
        self, remediator: PromptRemediator
    ) -> None:
        original = "You are the assistant for Acme Corp."
        patch = remediator.patch_prompt(make_finding("LLM07"), original)
        assert original in patch.patched_prompt


class TestUnhandledCategory:
    @pytest.mark.parametrize("code", ["LLM02", "LLM05", "LLM09", "LLM10"])
    def test_returns_noop_patch(self, remediator: PromptRemediator, code: str) -> None:
        original = "system prompt"
        patch = remediator.patch_prompt(make_finding(code), original)
        assert patch.patched_prompt == original
        assert patch.injection_resistance_techniques == []
        assert "not handled" in patch.patch_explanation
        assert code in patch.patch_explanation
