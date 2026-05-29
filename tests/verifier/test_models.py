"""Tests for verifier dataclasses, enum, and status constants."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from verifier.models import (
    FAILED,
    PARTIAL,
    UNVERIFIABLE,
    VERIFIED,
    VerificationMode,
    VerificationReport,
    VerificationResult,
)

from tests.verifier.fixtures.sample_remediation_results import (
    make_remediation_result,
)


class TestVerificationMode:
    @pytest.mark.parametrize(
        ("member", "expected"),
        [
            (VerificationMode.QUICK, "quick"),
            (VerificationMode.FULL, "full"),
            (VerificationMode.SKIPPED, "skipped"),
        ],
    )
    def test_values(self, member: VerificationMode, expected: str) -> None:
        assert member.value == expected

    def test_subtypes_str(self) -> None:
        assert isinstance(VerificationMode.QUICK, str)


class TestStatusConstants:
    @pytest.mark.parametrize(
        ("const", "expected"),
        [
            (VERIFIED, "VERIFIED"),
            (PARTIAL, "PARTIAL"),
            (FAILED, "FAILED"),
            (UNVERIFIABLE, "UNVERIFIABLE"),
        ],
    )
    def test_status_values(self, const: str, expected: str) -> None:
        assert const == expected


class TestVerificationResult:
    def test_construct_with_all_fields(self) -> None:
        remediation = make_remediation_result("LLM01")
        result = VerificationResult(
            remediation_result=remediation,
            mode=VerificationMode.QUICK,
            before_success_rate=0.55,
            after_success_rate=0.05,
            improvement_percent=90.9,
            verification_status=VERIFIED,
            confidence=0.75,
            notes=["all four techniques present"],
        )
        assert result.remediation_result is remediation
        assert result.mode is VerificationMode.QUICK
        assert result.before_success_rate == 0.55
        assert result.verification_status == VERIFIED

    def test_frozen(self) -> None:
        result = VerificationResult(
            remediation_result=make_remediation_result("LLM01"),
            mode=VerificationMode.QUICK,
            before_success_rate=None,
            after_success_rate=None,
            improvement_percent=None,
            verification_status=UNVERIFIABLE,
            confidence=0.0,
            notes=[],
        )
        with pytest.raises(FrozenInstanceError):
            result.confidence = 1.0  # type: ignore[misc]


class TestVerificationReport:
    def test_construct_with_all_fields(self) -> None:
        report = VerificationReport(
            results=[],
            total_findings=0,
            verified_count=0,
            partial_count=0,
            failed_count=0,
            unverifiable_count=0,
            overall_improvement_percent=0.0,
            summary={},
        )
        assert report.total_findings == 0
        assert report.summary == {}

    def test_frozen(self) -> None:
        report = VerificationReport(
            results=[],
            total_findings=0,
            verified_count=0,
            partial_count=0,
            failed_count=0,
            unverifiable_count=0,
            overall_improvement_percent=0.0,
            summary={},
        )
        with pytest.raises(FrozenInstanceError):
            report.total_findings = 1  # type: ignore[misc]
