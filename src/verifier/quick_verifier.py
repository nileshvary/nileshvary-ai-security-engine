"""Heuristic verifier that checks Phase 3 artifacts for expected markers.

Pure pattern matching — no garak re-run, no external calls. The verifier
estimates before/after attack success rates from the finding's severity
bucket and the completeness of the produced remediation artifacts.

Real before/after numbers from a garak re-run land in v1.1 via
``FullVerifier``.
"""

from __future__ import annotations

import logging
from typing import Final

from remediation_engine.models import RemediationResult

from verifier.models import (
    FAILED,
    PARTIAL,
    UNVERIFIABLE,
    VERIFIED,
    VerificationMode,
    VerificationResult,
)

logger = logging.getLogger(__name__)


_BEFORE_BY_SEVERITY: Final[dict[str, float]] = {
    "CRITICAL": 0.85,
    "HIGH": 0.55,
    "MEDIUM": 0.25,
    "LOW": 0.05,
}
_DEFAULT_BEFORE: Final[float] = 0.50

_LLM01_TECHNIQUES: Final[frozenset[str]] = frozenset(
    {
        "instruction-hierarchy",
        "delimiter-tagging",
        "role-confirmation",
        "refusal-patterns",
    }
)
_LLM07_TECHNIQUES: Final[frozenset[str]] = frozenset(
    {"non-disclosure-clause", "meta-question-refusal"}
)

_OUT_OF_BAND_CATEGORIES: Final[frozenset[str]] = frozenset(
    {"LLM03", "LLM04", "LLM08", "LLM09"}
)

_CONFIDENCE_VERIFIED: Final[float] = 0.75
_CONFIDENCE_PARTIAL: Final[float] = 0.55
_CONFIDENCE_FAILED: Final[float] = 0.75
_CONFIDENCE_SKIPPED: Final[float] = 0.0


def _before_rate(severity: str) -> float:
    """Return the severity-bucket midpoint estimate for ``before``."""
    return _BEFORE_BY_SEVERITY.get(severity, _DEFAULT_BEFORE)


def _improvement(before: float, after: float) -> float | None:
    """Return the percent improvement, or ``None`` when ``before`` is zero."""
    if before <= 0:
        return None
    return (before - after) / before * 100.0


class QuickVerifier:
    """Heuristic verifier — checks artifacts for expected markers."""

    def verify(self, remediation_result: RemediationResult) -> VerificationResult:
        """Return a heuristic ``VerificationResult`` for ``remediation_result``.

        Args:
            remediation_result: The Phase 3 result to inspect.

        Returns:
            A ``VerificationResult`` with ``mode=QUICK`` (or ``SKIPPED``
            for out-of-band categories) and rate estimates derived from
            the finding's severity and the completeness of the produced
            artifacts.
        """
        category = remediation_result.finding.owasp_llm_category

        if category in _OUT_OF_BAND_CATEGORIES:
            return self._skipped(remediation_result, category)

        before = _before_rate(remediation_result.finding.severity)

        if category == "LLM01":
            return self._verify_prompt_patch(
                remediation_result, before, _LLM01_TECHNIQUES, category
            )
        if category == "LLM07":
            return self._verify_prompt_patch(
                remediation_result, before, _LLM07_TECHNIQUES, category
            )
        if category in {"LLM02", "LLM05"}:
            return self._verify_sanitization(remediation_result, before, category)
        if category == "LLM06":
            return self._verify_flag_only(remediation_result, before, category)
        if category == "LLM10":
            return self._verify_rate_limits(remediation_result, before, category)

        # Unknown category — best-effort PARTIAL with a note.
        return self._build(
            remediation_result=remediation_result,
            mode=VerificationMode.QUICK,
            before=before,
            after=before,
            status=PARTIAL,
            confidence=_CONFIDENCE_PARTIAL,
            notes=[f"unknown OWASP category {category!r}; no quick check available"],
        )

    # ------------------------------------------------------------------
    # Per-category checks
    # ------------------------------------------------------------------

    def _verify_prompt_patch(
        self,
        remediation_result: RemediationResult,
        before: float,
        expected: frozenset[str],
        category: str,
    ) -> VerificationResult:
        patch = remediation_result.prompt_patch
        if patch is None:
            logger.warning(
                "%s verification: no prompt_patch on result for probe '%s'",
                category,
                remediation_result.finding.probe_name,
            )
            return self._build(
                remediation_result=remediation_result,
                mode=VerificationMode.QUICK,
                before=before,
                after=before,
                status=FAILED,
                confidence=_CONFIDENCE_FAILED,
                notes=["prompt patch not produced — remediation was downgraded"],
            )

        present = set(patch.injection_resistance_techniques) & expected
        total = len(expected)
        count = len(present)
        after = before * (total - count) / total if total > 0 else before

        if count == total:
            status, confidence = VERIFIED, _CONFIDENCE_VERIFIED
        elif count == 0:
            status, confidence = FAILED, _CONFIDENCE_FAILED
        elif category == "LLM01" and count >= 2:
            status, confidence = PARTIAL, _CONFIDENCE_PARTIAL
        elif category == "LLM07" and count == 1:
            status, confidence = PARTIAL, _CONFIDENCE_PARTIAL
        else:
            status, confidence = FAILED, _CONFIDENCE_FAILED

        notes = [
            f"{category} techniques present: {sorted(present)}",
            f"{category} techniques missing: {sorted(expected - present)}",
        ]
        logger.debug(
            "%s techniques check: %d/%d present (%s)", category, count, total, status
        )
        return self._build(
            remediation_result=remediation_result,
            mode=VerificationMode.QUICK,
            before=before,
            after=after,
            status=status,
            confidence=confidence,
            notes=notes,
        )

    def _verify_sanitization(
        self,
        remediation_result: RemediationResult,
        before: float,
        category: str,
    ) -> VerificationResult:
        san = remediation_result.response_sanitization
        if san is None:
            logger.warning(
                "%s verification: no response_sanitization on result for probe '%s'",
                category,
                remediation_result.finding.probe_name,
            )
            return self._build(
                remediation_result=remediation_result,
                mode=VerificationMode.QUICK,
                before=before,
                after=before,
                status=FAILED,
                confidence=_CONFIDENCE_FAILED,
                notes=["response sanitization not produced"],
            )

        has_detected = bool(san.detected_issues)
        has_actions = bool(san.actions_taken)

        if has_detected and has_actions:
            status, confidence, after = VERIFIED, _CONFIDENCE_VERIFIED, 0.05
            notes = [
                f"{len(san.detected_issues)} issue(s) detected and acted on",
            ]
        elif has_detected:
            status, confidence, after = PARTIAL, _CONFIDENCE_PARTIAL, before * 0.5
            notes = ["issues detected but no actions recorded"]
        else:
            status, confidence, after = FAILED, _CONFIDENCE_FAILED, before
            notes = ["sanitization produced no detections — likely a no-op"]

        logger.debug(
            "%s sanitization check: detected=%s actions=%s (%s)",
            category,
            has_detected,
            has_actions,
            status,
        )
        return self._build(
            remediation_result=remediation_result,
            mode=VerificationMode.QUICK,
            before=before,
            after=after,
            status=status,
            confidence=confidence,
            notes=notes,
        )

    def _verify_flag_only(
        self,
        remediation_result: RemediationResult,
        before: float,
        category: str,
    ) -> VerificationResult:
        san = remediation_result.response_sanitization
        if san is None:
            return self._build(
                remediation_result=remediation_result,
                mode=VerificationMode.QUICK,
                before=before,
                after=before,
                status=FAILED,
                confidence=_CONFIDENCE_FAILED,
                notes=["response sanitization not produced"],
            )

        if san.detected_issues:
            status, confidence, after = VERIFIED, _CONFIDENCE_VERIFIED, before * 0.5
            notes = [f"{len(san.detected_issues)} flag(s) recorded for review"]
        else:
            status, confidence, after = FAILED, _CONFIDENCE_FAILED, before
            notes = ["no agent-action flags recorded"]

        logger.debug(
            "%s flag-only check: flags=%d (%s)",
            category,
            len(san.detected_issues),
            status,
        )
        return self._build(
            remediation_result=remediation_result,
            mode=VerificationMode.QUICK,
            before=before,
            after=after,
            status=status,
            confidence=confidence,
            notes=notes,
        )

    def _verify_rate_limits(
        self,
        remediation_result: RemediationResult,
        before: float,
        category: str,
    ) -> VerificationResult:
        config = remediation_result.guardrail_config
        if config is None or not config.rate_limits:
            return self._build(
                remediation_result=remediation_result,
                mode=VerificationMode.QUICK,
                before=before,
                after=before,
                status=FAILED,
                confidence=_CONFIDENCE_FAILED,
                notes=["guardrail config has no rate_limits entries"],
            )

        after = 0.10
        notes = [f"rate_limits configured: {sorted(config.rate_limits.keys())}"]
        logger.debug("%s rate-limits check: keys=%s", category, sorted(config.rate_limits.keys()))
        return self._build(
            remediation_result=remediation_result,
            mode=VerificationMode.QUICK,
            before=before,
            after=after,
            status=VERIFIED,
            confidence=_CONFIDENCE_VERIFIED,
            notes=notes,
        )

    def _skipped(
        self, remediation_result: RemediationResult, category: str
    ) -> VerificationResult:
        forwarded = [n for n in remediation_result.notes if n.startswith("recommended:")]
        notes = [
            f"quick verification not applicable for {category}: external tools required"
        ]
        notes.extend(forwarded)
        logger.info(
            "Out-of-band category %s for probe '%s' — verification SKIPPED",
            category,
            remediation_result.finding.probe_name,
        )
        return VerificationResult(
            remediation_result=remediation_result,
            mode=VerificationMode.SKIPPED,
            before_success_rate=None,
            after_success_rate=None,
            improvement_percent=None,
            verification_status=UNVERIFIABLE,
            confidence=_CONFIDENCE_SKIPPED,
            notes=notes,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _build(
        self,
        *,
        remediation_result: RemediationResult,
        mode: VerificationMode,
        before: float,
        after: float,
        status: str,
        confidence: float,
        notes: list[str],
    ) -> VerificationResult:
        improvement = _improvement(before, after)
        if status == FAILED:
            logger.warning(
                "Quick verification FAILED for probe '%s' (category=%s)",
                remediation_result.finding.probe_name,
                remediation_result.finding.owasp_llm_category,
            )
        else:
            logger.info(
                "Quick verification %s for probe '%s' (improvement=%s%%)",
                status,
                remediation_result.finding.probe_name,
                f"{improvement:.1f}" if improvement is not None else "n/a",
            )
        return VerificationResult(
            remediation_result=remediation_result,
            mode=mode,
            before_success_rate=before,
            after_success_rate=after,
            improvement_percent=improvement,
            verification_status=status,
            confidence=confidence,
            notes=notes,
        )
