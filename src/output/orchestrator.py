"""Coordinates all output writers and builds the ``FinalReport`` manifest."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version as pkg_version
from pathlib import Path

from integration_bridge.models import Finding
from remediation_engine.models import GuardrailConfig, RemediationResult
from verifier.models import VerificationReport

from output.models import FinalReport, OutputArtifact
from output.writers import HtmlWriter, JsonWriter, MarkdownWriter, YamlWriter

logger = logging.getLogger(__name__)


_FALLBACK_VERSION = "0.0.0+unknown"


def _resolve_tool_version() -> str:
    """Return the installed package version, with a defensive fallback."""
    try:
        return pkg_version("ai-security-engine")
    except PackageNotFoundError:
        return _FALLBACK_VERSION


class OutputOrchestrator:
    """Runs every writer and bundles the result into a ``FinalReport``."""

    def __init__(
        self,
        json_writer: JsonWriter | None = None,
        yaml_writer: YamlWriter | None = None,
        markdown_writer: MarkdownWriter | None = None,
        html_writer: HtmlWriter | None = None,
        tool_version: str | None = None,
    ) -> None:
        """Initialize the orchestrator.

        Args:
            json_writer: Optional injected ``JsonWriter``; defaults to a
                fresh instance.
            yaml_writer: Optional injected ``YamlWriter``.
            markdown_writer: Optional injected ``MarkdownWriter``.
            html_writer: Optional injected ``HtmlWriter``.
            tool_version: Override the tool version string. When ``None``,
                resolved via ``importlib.metadata``.
        """
        self.json_writer = json_writer or JsonWriter()
        self.yaml_writer = yaml_writer or YamlWriter()
        self.markdown_writer = markdown_writer or MarkdownWriter()
        self.html_writer = html_writer or HtmlWriter()
        self.tool_version = tool_version or _resolve_tool_version()

    def write_all(
        self,
        findings: list[Finding],
        remediation_results: list[RemediationResult],
        verification_report: VerificationReport,
        guardrail_config: GuardrailConfig,
        output_dir: Path,
    ) -> FinalReport:
        """Write every artifact to ``output_dir`` and return a ``FinalReport``.

        Args:
            findings: Phase 2 findings.
            remediation_results: Phase 3 results.
            verification_report: Phase 4 aggregate report.
            guardrail_config: The single shared guardrail config.
            output_dir: Destination directory. Created with parents if it
                does not exist.

        Returns:
            A ``FinalReport`` whose ``artifacts`` list has one entry per
            file written.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        logger.info("Writing output artifacts to %s", output_dir)

        artifacts: list[OutputArtifact] = []
        artifacts.extend(
            self.json_writer.write(
                findings, remediation_results, verification_report, output_dir
            )
        )
        artifacts.append(self.yaml_writer.write(guardrail_config, output_dir))
        artifacts.append(self.markdown_writer.write(remediation_results, output_dir))
        artifacts.append(
            self.html_writer.write(
                findings,
                remediation_results,
                verification_report,
                output_dir,
                guardrail_config=guardrail_config,
            )
        )

        logger.info(
            "Output orchestration complete: %d artifact(s) written", len(artifacts)
        )
        return FinalReport(
            findings=findings,
            remediation_results=remediation_results,
            verification_report=verification_report,
            guardrail_config=guardrail_config,
            artifacts=artifacts,
            generated_at=datetime.now(timezone.utc),
            tool_version=self.tool_version,
        )
