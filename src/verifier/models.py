"""Data models for the verifier.

Defines the per-finding ``VerificationResult`` and the batch
``VerificationReport`` produced by ``VerificationOrchestrator``, plus the
``VerificationMode`` enum and the verification-status string constants.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from remediation_engine.models import RemediationResult


class VerificationMode(StrEnum):
    """Which verification path produced a ``VerificationResult``."""

    QUICK = "quick"
    FULL = "full"
    SKIPPED = "skipped"


VERIFIED: Final[str] = "VERIFIED"
PARTIAL: Final[str] = "PARTIAL"
FAILED: Final[str] = "FAILED"
UNVERIFIABLE: Final[str] = "UNVERIFIABLE"


@dataclass(frozen=True, slots=True)
class VerificationResult:
    """Verification outcome for one ``RemediationResult``.

    Attributes:
        remediation_result: The input ``RemediationResult`` that was checked.
        mode: ``QUICK``, ``FULL``, or ``SKIPPED``.
        before_success_rate: Estimated attack success rate prior to
            remediation. ``None`` when no estimate is meaningful (SKIPPED).
        after_success_rate: Estimated residual attack success rate after
            remediation. ``None`` for SKIPPED.
        improvement_percent: ``(before - after) / before * 100`` when both
            rates are present and ``before > 0``; ``None`` otherwise.
        verification_status: One of ``"VERIFIED"``, ``"PARTIAL"``,
            ``"FAILED"``, ``"UNVERIFIABLE"``.
        confidence: 0.0-1.0 confidence in the verification itself
            (distinct from ``RemediationResult.confidence``).
        notes: Free-form messages describing what was checked or why a
            particular status was assigned.
    """

    remediation_result: RemediationResult
    mode: VerificationMode
    before_success_rate: float | None
    after_success_rate: float | None
    improvement_percent: float | None
    verification_status: str
    confidence: float
    notes: list[str]


@dataclass(frozen=True, slots=True)
class VerificationReport:
    """Aggregate report across all verified findings.

    Attributes:
        results: Per-finding verification results (same length as the
            input remediation results).
        total_findings: ``len(results)``.
        verified_count: Number of results with status ``"VERIFIED"``.
        partial_count: Number of results with status ``"PARTIAL"``.
        failed_count: Number of results with status ``"FAILED"``.
        unverifiable_count: Number of results with status ``"UNVERIFIABLE"``.
        overall_improvement_percent: Severity-weighted average of
            ``improvement_percent`` across in-band results
            (SKIPPED results are excluded). ``0.0`` when there are
            zero in-band results.
        summary: Count of findings per OWASP LLM category, e.g.
            ``{"LLM01": 3, "LLM02": 1}``.
    """

    results: list[VerificationResult]
    total_findings: int
    verified_count: int
    partial_count: int
    failed_count: int
    unverifiable_count: int
    overall_improvement_percent: float
    summary: dict[str, int]
