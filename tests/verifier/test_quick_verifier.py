"""Tests for ``QuickVerifier`` heuristic checks across all categories."""

from __future__ import annotations

import pytest

from verifier.models import (
    FAILED,
    PARTIAL,
    UNVERIFIABLE,
    VERIFIED,
    VerificationMode,
)
from verifier.quick_verifier import QuickVerifier

from tests.verifier.fixtures.sample_remediation_results import (
    make_remediation_result,
)


# ---------------------------------------------------------------------------
# Severity → before-rate mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("severity", "expected_before"),
    [
        ("CRITICAL", 0.85),
        ("HIGH", 0.55),
        ("MEDIUM", 0.25),
        ("LOW", 0.05),
    ],
)
def test_severity_before_rate(
    quick_verifier: QuickVerifier, severity: str, expected_before: float
) -> None:
    result = quick_verifier.verify(make_remediation_result("LLM01", severity=severity))
    assert result.before_success_rate == pytest.approx(expected_before)


# ---------------------------------------------------------------------------
# LLM01 — instruction-hierarchy/delimiter/role/refusal techniques
# ---------------------------------------------------------------------------


class TestLLM01:
    def test_all_four_techniques_verified(self, quick_verifier: QuickVerifier) -> None:
        result = quick_verifier.verify(make_remediation_result("LLM01"))
        assert result.verification_status == VERIFIED
        assert result.mode is VerificationMode.QUICK
        assert result.after_success_rate == pytest.approx(0.0)
        assert result.improvement_percent == pytest.approx(100.0)

    def test_two_techniques_partial(self, quick_verifier: QuickVerifier) -> None:
        result = quick_verifier.verify(
            make_remediation_result(
                "LLM01",
                techniques=["instruction-hierarchy", "delimiter-tagging"],
            )
        )
        assert result.verification_status == PARTIAL
        # before=0.55, after=0.55*2/4=0.275 → ~50% improvement
        assert result.improvement_percent == pytest.approx(50.0)

    def test_zero_techniques_failed(self, quick_verifier: QuickVerifier) -> None:
        result = quick_verifier.verify(
            make_remediation_result("LLM01", techniques=[])
        )
        assert result.verification_status == FAILED
        assert result.improvement_percent == pytest.approx(0.0)

    def test_missing_patch_failed(self, quick_verifier: QuickVerifier) -> None:
        result = quick_verifier.verify(
            make_remediation_result("LLM01", include_patch=False)
        )
        assert result.verification_status == FAILED
        assert any("not produced" in n for n in result.notes)


# ---------------------------------------------------------------------------
# LLM07 — non-disclosure + meta-question-refusal
# ---------------------------------------------------------------------------


class TestLLM07:
    def test_both_techniques_verified(self, quick_verifier: QuickVerifier) -> None:
        result = quick_verifier.verify(make_remediation_result("LLM07"))
        assert result.verification_status == VERIFIED
        assert result.after_success_rate == pytest.approx(0.0)

    def test_one_technique_partial(self, quick_verifier: QuickVerifier) -> None:
        result = quick_verifier.verify(
            make_remediation_result("LLM07", techniques=["non-disclosure-clause"])
        )
        assert result.verification_status == PARTIAL

    def test_zero_techniques_failed(self, quick_verifier: QuickVerifier) -> None:
        result = quick_verifier.verify(
            make_remediation_result("LLM07", techniques=[])
        )
        assert result.verification_status == FAILED


# ---------------------------------------------------------------------------
# LLM02 / LLM05 — sanitization with detected + actions
# ---------------------------------------------------------------------------


class TestLLM02:
    def test_both_populated_verified(self, quick_verifier: QuickVerifier) -> None:
        result = quick_verifier.verify(make_remediation_result("LLM02"))
        assert result.verification_status == VERIFIED
        assert result.after_success_rate == pytest.approx(0.05)

    def test_only_detected_partial(self, quick_verifier: QuickVerifier) -> None:
        result = quick_verifier.verify(
            make_remediation_result(
                "LLM02", detected_issues=["SSN detected"], actions_taken=[]
            )
        )
        assert result.verification_status == PARTIAL

    def test_both_empty_failed(self, quick_verifier: QuickVerifier) -> None:
        result = quick_verifier.verify(
            make_remediation_result(
                "LLM02", detected_issues=[], actions_taken=[]
            )
        )
        assert result.verification_status == FAILED


class TestLLM05:
    def test_both_populated_verified(self, quick_verifier: QuickVerifier) -> None:
        result = quick_verifier.verify(make_remediation_result("LLM05"))
        assert result.verification_status == VERIFIED

    def test_both_empty_failed(self, quick_verifier: QuickVerifier) -> None:
        result = quick_verifier.verify(
            make_remediation_result(
                "LLM05", detected_issues=[], actions_taken=[]
            )
        )
        assert result.verification_status == FAILED


# ---------------------------------------------------------------------------
# LLM06 — flag-only verification (detected populated → VERIFIED)
# ---------------------------------------------------------------------------


class TestLLM06:
    def test_detected_populated_verified(self, quick_verifier: QuickVerifier) -> None:
        result = quick_verifier.verify(
            make_remediation_result(
                "LLM06", detected_issues=["tool call flagged"]
            )
        )
        assert result.verification_status == VERIFIED
        # Flag-only halves the residual rate (visibility only).
        assert result.after_success_rate == pytest.approx(0.55 * 0.5)

    def test_empty_failed(self, quick_verifier: QuickVerifier) -> None:
        result = quick_verifier.verify(
            make_remediation_result("LLM06", detected_issues=[])
        )
        assert result.verification_status == FAILED


# ---------------------------------------------------------------------------
# LLM10 — rate-limit check
# ---------------------------------------------------------------------------


class TestLLM10:
    def test_rate_limits_populated_verified(self, quick_verifier: QuickVerifier) -> None:
        result = quick_verifier.verify(make_remediation_result("LLM10"))
        assert result.verification_status == VERIFIED
        assert result.after_success_rate == pytest.approx(0.10)

    def test_empty_rate_limits_failed(self, quick_verifier: QuickVerifier) -> None:
        result = quick_verifier.verify(
            make_remediation_result("LLM10", rate_limits={})
        )
        assert result.verification_status == FAILED

    def test_missing_guardrail_failed(self, quick_verifier: QuickVerifier) -> None:
        result = quick_verifier.verify(
            make_remediation_result("LLM10", include_guardrail=False)
        )
        assert result.verification_status == FAILED


# ---------------------------------------------------------------------------
# Out-of-band — LLM03/04/08/09 → SKIPPED + UNVERIFIABLE
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("code", ["LLM03", "LLM04", "LLM08", "LLM09"])
def test_out_of_band_skipped(quick_verifier: QuickVerifier, code: str) -> None:
    result = quick_verifier.verify(make_remediation_result(code))
    assert result.mode is VerificationMode.SKIPPED
    assert result.verification_status == UNVERIFIABLE
    assert result.before_success_rate is None
    assert result.after_success_rate is None
    assert result.improvement_percent is None
    assert result.confidence == 0.0
    assert any("external tools required" in n for n in result.notes)
    # At least one recommended:* line was forwarded from the remediation notes.
    assert any(n.startswith("recommended:") for n in result.notes)


# ---------------------------------------------------------------------------
# Confidence on the verifier itself
# ---------------------------------------------------------------------------


def test_quick_verified_confidence(quick_verifier: QuickVerifier) -> None:
    result = quick_verifier.verify(make_remediation_result("LLM01"))
    assert result.confidence == pytest.approx(0.75)


def test_quick_failed_confidence(quick_verifier: QuickVerifier) -> None:
    result = quick_verifier.verify(make_remediation_result("LLM01", techniques=[]))
    assert result.confidence == pytest.approx(0.75)
