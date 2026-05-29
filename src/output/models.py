"""Data models for the output stage.

``OutputArtifact`` describes one file written to disk; ``FinalReport``
bundles the full pipeline state plus the manifest of artifacts produced.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from integration_bridge.models import Finding
from remediation_engine.models import GuardrailConfig, RemediationResult
from verifier.models import VerificationReport


@dataclass(frozen=True, slots=True)
class OutputArtifact:
    """One file produced by an output writer.

    Attributes:
        filename: Just the base name (e.g. ``"summary.html"``).
        filepath: Absolute path on disk.
        format: One of ``"json"``, ``"yaml"``, ``"markdown"``, ``"html"``.
        description: Short human description of what the file contains.
        size_bytes: Size of the file in bytes, captured after write.
    """

    filename: str
    filepath: Path
    format: str
    description: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class FinalReport:
    """The bundled output of a complete pipeline run.

    Attributes:
        findings: Phase 2 findings consumed by the pipeline.
        remediation_results: Phase 3 results (one per finding).
        verification_report: Phase 4 aggregate verification report.
        guardrail_config: The single shared guardrail config built from
            the full findings batch.
        artifacts: One ``OutputArtifact`` per file written to disk.
        generated_at: UTC timestamp when the report was produced.
        tool_version: Version string of the installed
            ``ai-security-engine`` package.
    """

    findings: list[Finding]
    remediation_results: list[RemediationResult]
    verification_report: VerificationReport
    guardrail_config: GuardrailConfig
    artifacts: list[OutputArtifact]
    generated_at: datetime
    tool_version: str
