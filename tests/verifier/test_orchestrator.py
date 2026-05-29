"""Tests for ``VerificationOrchestrator`` routing and report aggregation."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from verifier.models import FAILED, UNVERIFIABLE, VERIFIED, VerificationMode
from verifier.orchestrator import VerificationOrchestrator

from tests.verifier.fixtures.sample_remediation_results import (
    all_category_results,
    make_remediation_result,
)


# ---------------------------------------------------------------------------
# Whole-batch happy path
# ---------------------------------------------------------------------------


def test_quick_mode_over_all_ten_categories(
    verifier_orchestrator: VerificationOrchestrator,
) -> None:
    report = verifier_orchestrator.verify_all(
        all_category_results(), mode="quick"
    )
    assert report.total_findings == 10
    assert len(report.results) == 10
    # Out-of-band categories contribute 4 unverifiable.
    assert report.unverifiable_count == 4
    # All in-band defaults are VERIFIED (the factory fills full artifacts).
    assert report.verified_count == 6
    assert report.failed_count == 0
    # Summary covers every category exactly once.
    assert set(report.summary.keys()) == {f"LLM{i:02d}" for i in range(1, 11)}
    assert all(count == 1 for count in report.summary.values())


def test_empty_input_produces_zero_counts(
    verifier_orchestrator: VerificationOrchestrator,
) -> None:
    report = verifier_orchestrator.verify_all([], mode="quick")
    assert report.total_findings == 0
    assert report.results == []
    assert report.verified_count == 0
    assert report.partial_count == 0
    assert report.failed_count == 0
    assert report.unverifiable_count == 0
    assert report.overall_improvement_percent == 0.0


# ---------------------------------------------------------------------------
# Mode validation
# ---------------------------------------------------------------------------


def test_invalid_mode_raises(verifier_orchestrator: VerificationOrchestrator) -> None:
    with pytest.raises(ValueError, match="unsupported mode"):
        verifier_orchestrator.verify_all([make_remediation_result("LLM01")], mode="bogus")


# ---------------------------------------------------------------------------
# Full-mode behavior
# ---------------------------------------------------------------------------


def test_full_mode_in_band_propagates_not_implemented(
    verifier_orchestrator: VerificationOrchestrator,
) -> None:
    with pytest.raises(NotImplementedError, match="garak integration"):
        verifier_orchestrator.verify_all(
            [make_remediation_result("LLM01")], mode="full"
        )


def test_full_mode_with_only_out_of_band_does_not_raise(
    verifier_orchestrator: VerificationOrchestrator,
) -> None:
    report = verifier_orchestrator.verify_all(
        [
            make_remediation_result("LLM03"),
            make_remediation_result("LLM04"),
            make_remediation_result("LLM08"),
            make_remediation_result("LLM09"),
        ],
        mode="full",
    )
    assert report.unverifiable_count == 4
    assert all(r.mode is VerificationMode.SKIPPED for r in report.results)


# ---------------------------------------------------------------------------
# Out-of-band routing: neither verifier is touched.
# ---------------------------------------------------------------------------


def test_out_of_band_bypasses_both_verifiers() -> None:
    quick = MagicMock(name="quick")
    full = MagicMock(name="full")
    orch = VerificationOrchestrator(quick_verifier=quick, full_verifier=full)
    report = orch.verify_all(
        [make_remediation_result("LLM03")], mode="quick"
    )
    quick.verify.assert_not_called()
    full.verify.assert_not_called()
    assert report.unverifiable_count == 1
    assert report.results[0].verification_status == UNVERIFIABLE


def test_out_of_band_notes_carry_recommendations() -> None:
    orch = VerificationOrchestrator()
    report = orch.verify_all(
        [make_remediation_result("LLM09")], mode="quick"
    )
    [result] = report.results
    assert any("external tools required" in n for n in result.notes)
    assert any(n.startswith("recommended:") for n in result.notes)


# ---------------------------------------------------------------------------
# Weighted overall improvement
# ---------------------------------------------------------------------------


def test_weighted_overall_improvement_hand_calculated(
    verifier_orchestrator: VerificationOrchestrator,
) -> None:
    # Three results:
    # - LLM01 CRITICAL, full techniques → improvement 100% (weight 4)
    # - LLM02 HIGH, full sanitization   → improvement ~90.9% (weight 3)
    #   before=0.55, after=0.05, (0.55-0.05)/0.55 = 90.909%
    # - LLM10 LOW, full rate_limits     → improvement 0% (before=0.05, after=0.10 → negative actually)
    #   With before=0.05 and after=0.10, improvement = (0.05-0.10)/0.05*100 = -100%
    #   Weight 1.
    results = [
        make_remediation_result("LLM01", severity="CRITICAL"),
        make_remediation_result("LLM02", severity="HIGH"),
        make_remediation_result("LLM10", severity="LOW"),
    ]
    report = verifier_orchestrator.verify_all(results, mode="quick")
    # Weighted sum: 4*100 + 3*90.909... + 1*(-100) = 400 + 272.727... - 100 = 572.727
    # Total weight: 4+3+1 = 8
    # Average: 572.727... / 8 = 71.59
    assert report.overall_improvement_percent == pytest.approx(71.59, abs=0.1)


def test_overall_excludes_skipped(
    verifier_orchestrator: VerificationOrchestrator,
) -> None:
    # Two LLM01 CRITICAL with full techniques (100% improvement each, weight 4)
    # and one LLM03 (SKIPPED, contributes nothing).
    results = [
        make_remediation_result("LLM01", severity="CRITICAL"),
        make_remediation_result("LLM01", severity="CRITICAL"),
        make_remediation_result("LLM03"),
    ]
    report = verifier_orchestrator.verify_all(results, mode="quick")
    assert report.overall_improvement_percent == pytest.approx(100.0)


# ---------------------------------------------------------------------------
# Status counts
# ---------------------------------------------------------------------------


def test_status_counts_sum_to_total(
    verifier_orchestrator: VerificationOrchestrator,
) -> None:
    results = [
        make_remediation_result("LLM01"),                                # VERIFIED
        make_remediation_result("LLM01", techniques=[]),                 # FAILED
        make_remediation_result("LLM01", techniques=["instruction-hierarchy", "delimiter-tagging"]),  # PARTIAL
        make_remediation_result("LLM03"),                                # UNVERIFIABLE
    ]
    report = verifier_orchestrator.verify_all(results, mode="quick")
    total = (
        report.verified_count
        + report.partial_count
        + report.failed_count
        + report.unverifiable_count
    )
    assert total == report.total_findings == 4
    assert report.verified_count == 1
    assert report.partial_count == 1
    assert report.failed_count == 1
    assert report.unverifiable_count == 1
