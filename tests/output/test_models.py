"""Tests for output-stage dataclasses."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import datetime, timezone
from pathlib import Path

import pytest

from output.models import FinalReport, OutputArtifact


class TestOutputArtifact:
    def test_construct_with_all_fields(self) -> None:
        artifact = OutputArtifact(
            filename="x.json",
            filepath=Path("/tmp/x.json"),
            format="json",
            description="x",
            size_bytes=42,
        )
        assert artifact.filename == "x.json"
        assert artifact.size_bytes == 42

    def test_frozen(self) -> None:
        artifact = OutputArtifact(
            filename="x.json",
            filepath=Path("/tmp/x.json"),
            format="json",
            description="x",
            size_bytes=42,
        )
        with pytest.raises(FrozenInstanceError):
            artifact.size_bytes = 0  # type: ignore[misc]


class TestFinalReport:
    def test_construct_with_all_fields(
        self,
        sample_findings_list,
        sample_remediation_results,
        sample_verification_report,
        sample_guardrail_config,
    ) -> None:
        report = FinalReport(
            findings=sample_findings_list,
            remediation_results=sample_remediation_results,
            verification_report=sample_verification_report,
            guardrail_config=sample_guardrail_config,
            artifacts=[],
            generated_at=datetime.now(timezone.utc),
            tool_version="0.1.0",
        )
        assert report.tool_version == "0.1.0"
        assert report.generated_at.tzinfo is not None

    def test_frozen(
        self,
        sample_findings_list,
        sample_remediation_results,
        sample_verification_report,
        sample_guardrail_config,
    ) -> None:
        report = FinalReport(
            findings=sample_findings_list,
            remediation_results=sample_remediation_results,
            verification_report=sample_verification_report,
            guardrail_config=sample_guardrail_config,
            artifacts=[],
            generated_at=datetime.now(timezone.utc),
            tool_version="0.1.0",
        )
        with pytest.raises(FrozenInstanceError):
            report.tool_version = "other"  # type: ignore[misc]
