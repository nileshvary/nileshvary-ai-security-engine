"""Tests for the remediation engine dataclasses and strategy enum."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from remediation_engine.models import (
    GuardrailConfig,
    PromptPatch,
    RemediationResult,
    RemediationStrategy,
    ResponseSanitization,
)

from tests.remediation_engine.fixtures.sample_findings import make_finding


class TestRemediationStrategy:
    @pytest.mark.parametrize(
        ("member", "expected_value"),
        [
            (RemediationStrategy.BLOCK, "block"),
            (RemediationStrategy.SANITIZE, "sanitize"),
            (RemediationStrategy.HARDEN, "harden"),
            (RemediationStrategy.LOG_ONLY, "log_only"),
            (RemediationStrategy.GUARDRAIL, "guardrail"),
        ],
    )
    def test_string_values(
        self, member: RemediationStrategy, expected_value: str
    ) -> None:
        assert member.value == expected_value

    def test_strenum_subtypes_str(self) -> None:
        assert isinstance(RemediationStrategy.HARDEN, str)


class TestPromptPatch:
    def test_construct_with_all_fields(self) -> None:
        patch = PromptPatch(
            original_prompt="orig",
            patched_prompt="patched",
            patch_explanation="why",
            injection_resistance_techniques=["t1"],
        )
        assert patch.original_prompt == "orig"
        assert patch.patched_prompt == "patched"
        assert patch.patch_explanation == "why"
        assert patch.injection_resistance_techniques == ["t1"]

    def test_frozen(self) -> None:
        patch = PromptPatch(
            original_prompt="o",
            patched_prompt="p",
            patch_explanation="e",
            injection_resistance_techniques=[],
        )
        with pytest.raises(FrozenInstanceError):
            patch.original_prompt = "mutated"  # type: ignore[misc]


class TestResponseSanitization:
    def test_construct_with_all_fields(self) -> None:
        s = ResponseSanitization(
            original_response="orig",
            sanitized_response="san",
            detected_issues=["i1"],
            actions_taken=["a1"],
        )
        assert s.sanitized_response == "san"
        assert s.detected_issues == ["i1"]
        assert s.actions_taken == ["a1"]

    def test_frozen(self) -> None:
        s = ResponseSanitization(
            original_response="o",
            sanitized_response="s",
            detected_issues=[],
            actions_taken=[],
        )
        with pytest.raises(FrozenInstanceError):
            s.sanitized_response = "mutated"  # type: ignore[misc]


class TestGuardrailConfig:
    def test_construct_with_all_fields(self) -> None:
        c = GuardrailConfig(
            format="portkey",
            input_filters=[{"id": "x"}],
            output_filters=[],
            rate_limits={"requests_per_minute": 60},
            yaml_export="key: value\n",
        )
        assert c.format == "portkey"
        assert c.input_filters == [{"id": "x"}]
        assert c.rate_limits["requests_per_minute"] == 60

    def test_frozen(self) -> None:
        c = GuardrailConfig(
            format="generic",
            input_filters=[],
            output_filters=[],
            rate_limits={},
            yaml_export="",
        )
        with pytest.raises(FrozenInstanceError):
            c.format = "mutated"  # type: ignore[misc]


class TestRemediationResult:
    def test_construct_with_all_fields(self) -> None:
        finding = make_finding("LLM01")
        result = RemediationResult(
            finding=finding,
            strategy=RemediationStrategy.HARDEN,
            prompt_patch=None,
            response_sanitization=None,
            guardrail_config=None,
            confidence=0.85,
            notes=["note"],
        )
        assert result.finding is finding
        assert result.strategy is RemediationStrategy.HARDEN
        assert result.confidence == 0.85
        assert result.notes == ["note"]

    def test_frozen(self) -> None:
        result = RemediationResult(
            finding=make_finding("LLM01"),
            strategy=RemediationStrategy.LOG_ONLY,
            prompt_patch=None,
            response_sanitization=None,
            guardrail_config=None,
            confidence=0.0,
            notes=[],
        )
        with pytest.raises(FrozenInstanceError):
            result.confidence = 1.0  # type: ignore[misc]
