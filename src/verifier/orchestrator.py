"""Routes RemediationResults to the appropriate verifier and aggregates the report.

For the four out-of-band OWASP categories (LLM03, LLM04, LLM08, LLM09),
no verifier is called at all — the orchestrator builds a SKIPPED result
directly and forwards the recommended-tool notes from Phase 3.

For everything else, dispatch is by the ``mode`` argument:
- ``"quick"`` → ``QuickVerifier`` (real, heuristic).
- ``"full"`` → ``FullVerifier`` (v1.0 stub, raises NotImplementedError).
"""

from __future__ import annotations

import logging
from collections import Counter
from typing import Final

from remediation_engine.models import RemediationResult

from verifier.full_verifier import FullVerifier
from verifier.models import (
    FAILED,
    PARTIAL,
    UNVERIFIABLE,
    VERIFIED,
    VerificationMode,
    VerificationReport,
    VerificationResult,
)
from verifier.quick_verifier import QuickVerifier

logger = logging.getLogger(__name__)


_VALID_MODES: Final[frozenset[str]] = frozenset({"quick", "full"})

_OUT_OF_BAND_CATEGORIES: Final[frozenset[str]] = frozenset(
    {"LLM03", "LLM04", "LLM08", "LLM09"}
)

_SEVERITY_WEIGHTS: Final[dict[str, int]] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
}
_DEFAULT_WEIGHT: Final[int] = 1


def _skipped_for(result: RemediationResult, category: str) -> VerificationResult:
    """Build a SKIPPED + UNVERIFIABLE result for an out-of-band finding."""
    forwarded = [n for n in result.notes if n.startswith("recommended:")]
    notes = [
        f"verification skipped for {category}: external tools required, "
        f"no runtime check is meaningful"
    ]
    notes.extend(forwarded)
    return VerificationResult(
        remediation_result=result,
        mode=VerificationMode.SKIPPED,
        before_success_rate=None,
        after_success_rate=None,
        improvement_percent=None,
        verification_status=UNVERIFIABLE,
        confidence=0.0,
        notes=notes,
    )


def _weighted_overall(results: list[VerificationResult]) -> float:
    """Severity-weighted average of improvement_percent over in-band results."""
    total_weight = 0
    weighted_sum = 0.0
    for r in results:
        if r.improvement_percent is None:
            continue
        weight = _SEVERITY_WEIGHTS.get(
            r.remediation_result.finding.severity, _DEFAULT_WEIGHT
        )
        total_weight += weight
        weighted_sum += weight * r.improvement_percent
    if total_weight == 0:
        return 0.0
    return weighted_sum / total_weight


class VerificationOrchestrator:
    """Iterates a batch of ``RemediationResult`` objects into a ``VerificationReport``."""

    def __init__(
        self,
        quick_verifier: QuickVerifier | None = None,
        full_verifier: FullVerifier | None = None,
    ) -> None:
        """Initialize the orchestrator.

        Args:
            quick_verifier: Optional injected ``QuickVerifier``; defaults
                to a fresh instance.
            full_verifier: Optional injected ``FullVerifier``; defaults
                to a fresh instance.
        """
        self.quick_verifier = quick_verifier or QuickVerifier()
        self.full_verifier = full_verifier or FullVerifier()

    def verify_all(
        self,
        remediation_results: list[RemediationResult],
        mode: str = "quick",
    ) -> VerificationReport:
        """Verify every result and return an aggregate ``VerificationReport``.

        Args:
            remediation_results: The Phase 3 outputs to verify.
            mode: ``"quick"`` (default) or ``"full"``. Out-of-band
                categories (LLM03/04/08/09) are always routed to SKIPPED
                regardless of ``mode``.

        Returns:
            A ``VerificationReport`` whose ``results`` list is the same
            length as the input.

        Raises:
            ValueError: If ``mode`` is not ``"quick"`` or ``"full"``.
            NotImplementedError: Propagated from ``FullVerifier`` when
                ``mode="full"`` is requested for any in-band finding.
        """
        if mode not in _VALID_MODES:
            raise ValueError(
                f"unsupported mode {mode!r}; expected one of {sorted(_VALID_MODES)}"
            )

        results: list[VerificationResult] = []
        for remediation_result in remediation_results:
            category = remediation_result.finding.owasp_llm_category
            if category in _OUT_OF_BAND_CATEGORIES:
                results.append(_skipped_for(remediation_result, category))
                continue
            if mode == "quick":
                results.append(self.quick_verifier.verify(remediation_result))
            else:
                results.append(self.full_verifier.verify(remediation_result))

        status_counts = Counter(r.verification_status for r in results)
        category_counts = dict(
            Counter(r.remediation_result.finding.owasp_llm_category for r in results)
        )
        overall = _weighted_overall(results)

        report = VerificationReport(
            results=results,
            total_findings=len(results),
            verified_count=status_counts.get(VERIFIED, 0),
            partial_count=status_counts.get(PARTIAL, 0),
            failed_count=status_counts.get(FAILED, 0),
            unverifiable_count=status_counts.get(UNVERIFIABLE, 0),
            overall_improvement_percent=overall,
            summary=category_counts,
        )

        if report.failed_count:
            logger.warning(
                "VerificationReport contains %d FAILED result(s) of %d total",
                report.failed_count,
                report.total_findings,
            )
        logger.info(
            "VerificationReport: total=%d verified=%d partial=%d failed=%d "
            "unverifiable=%d overall_improvement=%.2f%%",
            report.total_findings,
            report.verified_count,
            report.partial_count,
            report.failed_count,
            report.unverifiable_count,
            report.overall_improvement_percent,
        )
        return report
