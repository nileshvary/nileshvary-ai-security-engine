"""Agent 5 — Orchestrator: connects all agents into one pipeline run.

This is the fifth and final stage of the RemediAX v2.0 pipeline:

    remediax scan --target <TARGET>
    ↓
    OrchestratorAgent.run(target)
      Stage 1 — ScannerAgent.scan()           → list[Finding]
      Stage 2 — RemediatorAgent.remediate()   → list[RemediationResult]
      Stage 3 — ReporterAgent.generate_report() → str (HTML)
      Stage 4 — VerifierAgent.verify()        → VerificationReport
    ↓
    PipelineResult + artifacts/ (findings.json, remediation_results.json,
                                 summary.html, benchmark.json,
                                 pipeline_summary.json)

CLI usage::

    python -m agents.orchestrator --target openai:gpt-4o

    python -m agents.orchestrator \\
        --target openai:gpt-4o \\
        --system-prompt "You are a helpful assistant." \\
        --artifacts-dir artifacts/

CI gate::

    if not agent.ci_passed(result):
        sys.exit(1)   # ← at least one remediation failed verification
"""

from __future__ import annotations

import json
import logging
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_ROOT = Path(__file__).parent.parent
_SRC = _ROOT / "src"
for _p in (str(_ROOT), str(_SRC)):
    if _p not in sys.path:
        sys.path.insert(0, _p)


# ---------------------------------------------------------------------------
# PipelineResult — flat, JSON-serialisable, no nested dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PipelineResult:
    """Flat summary of one full RemediAX pipeline run.

    All fields are primitive types so the dataclass serialises to JSON
    directly via ``_result_to_dict()`` without any helpers.

    Attributes:
        target:                    Target identifier passed to ``run()``.
        finding_count:             Total findings from Agent 1.
        remediation_count:         Total remediations from Agent 2.
        verified_count:            VERIFIED results from Agent 4.
        partial_count:             PARTIAL results from Agent 4.
        failed_count:              FAILED results from Agent 4 (blocks CI).
        unverifiable_count:        UNVERIFIABLE/SKIPPED results (never blocks CI).
        overall_improvement_percent: Severity-weighted improvement across all
                                   in-band findings (0–100).
        ci_passed:                 ``True`` when ``failed_count == 0``.
        artifacts:                 Mapping of label → resolved path string
                                   for every file written to disk.
                                   Empty dict when ``save_artifacts=False``.
    """

    target: str
    finding_count: int
    remediation_count: int
    verified_count: int
    partial_count: int
    failed_count: int
    unverifiable_count: int
    overall_improvement_percent: float
    ci_passed: bool
    artifacts: dict[str, str]


# ---------------------------------------------------------------------------
# OrchestratorAgent
# ---------------------------------------------------------------------------

class OrchestratorAgent:
    """Connect Scanner → Remediator → Reporter → Verifier in one ``run()`` call.

    All four sub-agents are optional constructor parameters.  When omitted, a
    fresh default instance is constructed for each.  This follows the same
    dependency-injection pattern used by Agents 1–4 so tests can inject mocks
    without modifying any global state.

    Args:
        scanner:      Optional ``ScannerAgent`` instance.
        remediator:   Optional ``RemediatorAgent`` instance.
        reporter:     Optional ``ReporterAgent`` instance.
        verifier:     Optional ``VerifierAgent`` instance.
        artifacts_dir: Directory for artifact files (created if absent).
                      Defaults to ``"artifacts"``.
    """

    def __init__(
        self,
        scanner: Any | None = None,
        remediator: Any | None = None,
        reporter: Any | None = None,
        verifier: Any | None = None,
        artifacts_dir: str | Path = "artifacts",
    ) -> None:
        self._artifacts_dir = Path(artifacts_dir)

        if scanner is not None:
            self._scanner = scanner
        else:
            from agents.scanner_agent import ScannerAgent
            self._scanner = ScannerAgent()

        if remediator is not None:
            self._remediator = remediator
        else:
            from agents.remediator_agent import RemediatorAgent
            self._remediator = RemediatorAgent()

        if reporter is not None:
            self._reporter = reporter
        else:
            from agents.reporter_agent import ReporterAgent
            self._reporter = ReporterAgent()

        if verifier is not None:
            self._verifier = verifier
        else:
            from agents.verifier_agent import VerifierAgent
            self._verifier = VerifierAgent()

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def run(
        self,
        target: str,
        system_prompt: str = "",
        garak_probes: list[str] | None = None,
        pyrit_probes: list[str] | None = None,
        save_artifacts: bool = True,
    ) -> PipelineResult:
        """Run the full RemediAX pipeline for one target.

        Executes four stages in order:

        1. **Scan** — ``ScannerAgent.scan()`` discovers vulnerabilities.
        2. **Remediate** — ``RemediatorAgent.remediate()`` generates fixes.
        3. **Report** — ``ReporterAgent.generate_report()`` builds the HTML report.
        4. **Verify** — ``VerifierAgent.verify()`` benchmarks the fixes.

        Args:
            target:        Target identifier (e.g. ``"openai:gpt-4o"``).
            system_prompt: System prompt of the target LLM.  Passed to the
                           remediator so it can produce contextual patches.
            garak_probes:  Optional probe list forwarded to the scanner.
                           ``None`` → run all default probes.
            pyrit_probes:  Optional PyRIT probe list forwarded to the scanner.
            save_artifacts: When ``True`` (default), write all four artifact
                           files plus ``pipeline_summary.json`` to
                           ``artifacts_dir``.

        Returns:
            A flat ``PipelineResult`` with counts, improvement score,
            CI gate flag, and artifact file paths.
        """
        logger.info("OrchestratorAgent: starting pipeline for target=%s", target)

        # Stage 1 — Scan
        logger.info("OrchestratorAgent: Stage 1 — scanning")
        findings = self._scanner.scan(
            garak_probes=garak_probes,
            pyrit_probes=pyrit_probes,
        )
        logger.info("OrchestratorAgent: scan complete — %d findings", len(findings))

        # Stage 2 — Remediate
        logger.info("OrchestratorAgent: Stage 2 — remediating")
        results = self._remediator.remediate(findings, system_prompt)
        logger.info(
            "OrchestratorAgent: remediation complete — %d results", len(results)
        )

        # Stage 3 — Report
        logger.info("OrchestratorAgent: Stage 3 — generating report")
        html = self._reporter.generate_report(findings, results, target)
        logger.info(
            "OrchestratorAgent: report generated (%d chars)", len(html)
        )

        # Stage 4 — Verify
        logger.info("OrchestratorAgent: Stage 4 — verifying remediations")
        report = self._verifier.verify(results)

        # Artifact persistence
        artifacts: dict[str, str] = {}
        if save_artifacts:
            artifacts = self._save_all(findings, results, html, report)

        pipeline_result = PipelineResult(
            target=target,
            finding_count=len(findings),
            remediation_count=len(results),
            verified_count=report.verified_count,
            partial_count=report.partial_count,
            failed_count=report.failed_count,
            unverifiable_count=report.unverifiable_count,
            overall_improvement_percent=round(
                report.overall_improvement_percent, 2
            ),
            ci_passed=self._verifier.ci_passed(report),
            artifacts=artifacts,
        )

        logger.info(
            "OrchestratorAgent: pipeline complete — "
            "findings=%d verified=%d failed=%d improvement=%.1f%% ci_passed=%s",
            pipeline_result.finding_count,
            pipeline_result.verified_count,
            pipeline_result.failed_count,
            pipeline_result.overall_improvement_percent,
            pipeline_result.ci_passed,
        )
        return pipeline_result

    def ci_passed(self, result: PipelineResult) -> bool:
        """Return ``True`` when the pipeline produced zero FAILED verifications.

        Use this as a CI exit gate::

            if not agent.ci_passed(result):
                sys.exit(1)

        UNVERIFIABLE (out-of-band categories LLM03/04/08/09) and PARTIAL
        results do not trigger failure — only explicit FAILED verifications.
        """
        return result.ci_passed

    def save_pipeline_result(
        self,
        result: PipelineResult,
        output_path: str | Path,
    ) -> Path:
        """Write a ``PipelineResult`` to ``pipeline_summary.json``.

        Args:
            result:      The ``PipelineResult`` returned by ``run()``.
            output_path: File path, or directory (``pipeline_summary.json``
                         is appended when a directory is given).

        Returns:
            The resolved ``Path`` that was written.
        """
        dest = Path(output_path)
        if dest.is_dir():
            dest = dest / "pipeline_summary.json"
        dest.parent.mkdir(parents=True, exist_ok=True)

        payload = _result_to_dict(result)
        dest.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        logger.info("OrchestratorAgent: wrote pipeline summary to %s", dest)
        return dest

    @staticmethod
    def load_pipeline_result(source_path: str | Path) -> dict[str, Any]:
        """Load a ``pipeline_summary.json`` written by ``save_pipeline_result()``.

        Returns a plain ``dict`` so CI scripts can consume the file without
        importing any RemediAX code.
        """
        raw = json.loads(Path(source_path).read_text(encoding="utf-8"))
        logger.info(
            "OrchestratorAgent: loaded pipeline summary from %s", source_path
        )
        return raw

    # ------------------------------------------------------------------ #
    #  Private helpers                                                     #
    # ------------------------------------------------------------------ #

    def _save_all(
        self,
        findings: list[Any],
        results: list[Any],
        html: str,
        report: Any,
    ) -> dict[str, str]:
        """Save all four artifact files; return label → path mapping."""
        self._artifacts_dir.mkdir(parents=True, exist_ok=True)

        artifacts: dict[str, str] = {}

        p = self._scanner.save_findings(findings, self._artifacts_dir)
        artifacts["findings"] = str(p)

        p = self._remediator.save_results(results, self._artifacts_dir)
        artifacts["remediation_results"] = str(p)

        p = self._reporter.save_report(html, self._artifacts_dir)
        artifacts["html_report"] = str(p)

        p = self._verifier.save_report(report, self._artifacts_dir)
        artifacts["benchmark"] = str(p)

        return artifacts


# ---------------------------------------------------------------------------
# Serialisation helper
# ---------------------------------------------------------------------------

def _result_to_dict(result: PipelineResult) -> dict[str, Any]:
    """Serialise a ``PipelineResult`` to a JSON-safe dict."""
    return {
        "target": result.target,
        "finding_count": result.finding_count,
        "remediation_count": result.remediation_count,
        "verified_count": result.verified_count,
        "partial_count": result.partial_count,
        "failed_count": result.failed_count,
        "unverifiable_count": result.unverifiable_count,
        "overall_improvement_percent": result.overall_improvement_percent,
        "ci_passed": result.ci_passed,
        "artifacts": result.artifacts,
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser(
        prog="remediax",
        description="RemediAX — Full AI Security Pipeline (Agent 5 Orchestrator)",
    )
    parser.add_argument(
        "--target", required=True,
        help="Target identifier, e.g. openai:gpt-4o or http://localhost:8080",
    )
    parser.add_argument(
        "--system-prompt", default="",
        help="System prompt of the target LLM (used for contextual prompt patches)",
    )
    parser.add_argument(
        "--artifacts-dir", default="artifacts",
        help="Directory for output files (default: artifacts/)",
    )
    parser.add_argument(
        "--no-save", action="store_true",
        help="Skip writing artifact files to disk",
    )
    args = parser.parse_args()

    agent = OrchestratorAgent(artifacts_dir=args.artifacts_dir)
    pipeline_result = agent.run(
        target=args.target,
        system_prompt=args.system_prompt,
        save_artifacts=not args.no_save,
    )

    sys.exit(0 if agent.ci_passed(pipeline_result) else 1)
