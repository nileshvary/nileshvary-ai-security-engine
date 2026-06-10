"""Agent 4 — Verifier: runs before/after benchmark and confirms remediations work.

This is the fourth stage of the RemediAX v2.0 pipeline:

    Scanner → findings.json → Remediator → results → Reporter → Verifier → benchmark.json

The VerifierAgent wraps the existing ``src/verifier/`` package (already fully
built and tested) and adds JSON serialisation, a CI gate, and the standard
agent DI pattern.

Connection from Agent 3:
    findings = scanner.scan()
    results  = remediator.remediate(findings)
    html     = reporter.generate_report(findings, results)
    report   = verifier.verify(results)
    verifier.save_report(report, "artifacts/benchmark.json")

CI gate usage:
    if not verifier.ci_passed(report):
        sys.exit(1)
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_SRC = Path(__file__).parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


class VerifierAgent:
    """Coordinate heuristic verification and CI gate evaluation.

    Args:
        orchestrator:    Optional ``VerificationOrchestrator`` instance.
                         Defaults to a fresh one backed by ``QuickVerifier``.
        quick_verifier:  Optional ``QuickVerifier`` instance. Passed to a
                         freshly constructed orchestrator when ``orchestrator``
                         is not provided.
        mode:            Default verification mode — ``"quick"`` (heuristic,
                         offline) or ``"full"`` (requires garak re-run; v1.1
                         only). Can be overridden per ``verify()`` call.
    """

    def __init__(
        self,
        orchestrator: Any | None = None,
        quick_verifier: Any | None = None,
        mode: str = "quick",
    ) -> None:
        self._default_mode = mode

        if orchestrator is not None:
            self._orchestrator = orchestrator
        else:
            from verifier.orchestrator import VerificationOrchestrator
            self._orchestrator = VerificationOrchestrator(
                quick_verifier=quick_verifier,
            )

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def verify(
        self,
        remediation_results: list[Any],
        mode: str | None = None,
    ) -> Any:
        """Verify every remediation result and return a ``VerificationReport``.

        Args:
            remediation_results: List of ``RemediationResult`` from Agent 2.
            mode: ``"quick"`` (default) or ``"full"``. Falls back to the
                  ``mode`` passed to ``__init__`` when ``None``.

        Returns:
            A ``VerificationReport`` with per-finding results, aggregate
            improvement stats, and a severity-weighted overall score.
        """
        effective_mode = mode if mode is not None else self._default_mode
        if not remediation_results:
            logger.info("VerifierAgent: no remediation results to verify")

        report = self._orchestrator.verify_all(remediation_results, mode=effective_mode)

        logger.info(
            "VerifierAgent: verified=%d partial=%d failed=%d unverifiable=%d "
            "overall_improvement=%.1f%%",
            report.verified_count,
            report.partial_count,
            report.failed_count,
            report.unverifiable_count,
            report.overall_improvement_percent,
        )
        return report

    def ci_passed(self, report: Any) -> bool:
        """Return ``True`` when the report has zero FAILED results.

        Use this as a CI gate — exit code 1 when ``False``:

            if not verifier.ci_passed(report):
                sys.exit(1)

        UNVERIFIABLE (out-of-band categories like LLM03/04/08/09) and
        PARTIAL results do not trigger failure — only explicit FAILED.
        """
        return report.failed_count == 0

    def save_report(
        self,
        report: Any,
        output_path: str | Path,
    ) -> Path:
        """Serialise a ``VerificationReport`` to ``benchmark.json``.

        Args:
            report:      The report returned by ``verify()``.
            output_path: File path, or directory (``benchmark.json`` appended).

        Returns:
            The resolved ``Path`` that was written.
        """
        dest = Path(output_path)
        if dest.is_dir():
            dest = dest / "benchmark.json"
        dest.parent.mkdir(parents=True, exist_ok=True)

        payload = _report_to_dict(report)
        dest.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        logger.info("VerifierAgent: wrote benchmark to %s", dest)
        return dest

    @staticmethod
    def load_report(source_path: str | Path) -> dict[str, Any]:
        """Load a benchmark previously written by ``save_report()``.

        Returns a plain dict (not a dataclass) so CI scripts can consume
        it without importing the full RemediAX package.
        """
        raw = json.loads(Path(source_path).read_text(encoding="utf-8"))
        logger.info("VerifierAgent: loaded benchmark from %s", source_path)
        return raw


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------

def _report_to_dict(report: Any) -> dict[str, Any]:
    """Serialise a ``VerificationReport`` to a JSON-safe dict."""
    return {
        "total_findings": report.total_findings,
        "verified_count": report.verified_count,
        "partial_count": report.partial_count,
        "failed_count": report.failed_count,
        "unverifiable_count": report.unverifiable_count,
        "overall_improvement_percent": round(report.overall_improvement_percent, 2),
        "ci_passed": report.failed_count == 0,
        "summary": report.summary,
        "results": [_result_to_dict(r) for r in report.results],
    }


def _result_to_dict(result: Any) -> dict[str, Any]:
    """Serialise a single ``VerificationResult``."""
    rr = result.remediation_result
    finding = rr.finding

    if hasattr(finding, "to_dict"):
        finding_dict = finding.to_dict()
    else:
        finding_dict = {
            "probe_name": finding.probe_name,
            "owasp_llm_category": finding.owasp_llm_category,
            "severity": finding.severity,
        }

    return {
        "finding": finding_dict,
        "strategy": str(rr.strategy),
        "mode": str(result.mode),
        "verification_status": result.verification_status,
        "before_success_rate": result.before_success_rate,
        "after_success_rate": result.after_success_rate,
        "improvement_percent": (
            round(result.improvement_percent, 2)
            if result.improvement_percent is not None else None
        ),
        "confidence": round(result.confidence, 3),
        "notes": list(result.notes),
    }
