"""Tests for ``OutputOrchestrator.write_all`` and the resulting ``FinalReport``."""

from __future__ import annotations

from datetime import timezone
from pathlib import Path

from output.orchestrator import OutputOrchestrator


def test_write_all_produces_six_artifacts(
    tmp_path: Path,
    sample_findings_list,
    sample_remediation_results,
    sample_verification_report,
    sample_guardrail_config,
) -> None:
    output_dir = tmp_path / "out"
    report = OutputOrchestrator().write_all(
        findings=sample_findings_list,
        remediation_results=sample_remediation_results,
        verification_report=sample_verification_report,
        guardrail_config=sample_guardrail_config,
        output_dir=output_dir,
    )
    # 3 JSON + 1 YAML + 1 MD + 1 HTML = 6
    assert len(report.artifacts) == 6
    names = {a.filename for a in report.artifacts}
    assert names == {
        "findings.json",
        "remediation_results.json",
        "verification_report.json",
        "guardrails.yaml",
        "patched_prompts.md",
        "summary.html",
    }


def test_write_all_creates_missing_output_dir(
    tmp_path: Path,
    sample_findings_list,
    sample_remediation_results,
    sample_verification_report,
    sample_guardrail_config,
) -> None:
    output_dir = tmp_path / "nested" / "out"
    assert not output_dir.exists()
    OutputOrchestrator().write_all(
        sample_findings_list,
        sample_remediation_results,
        sample_verification_report,
        sample_guardrail_config,
        output_dir,
    )
    assert output_dir.is_dir()


def test_artifacts_have_positive_size_and_existing_paths(
    tmp_path: Path,
    sample_findings_list,
    sample_remediation_results,
    sample_verification_report,
    sample_guardrail_config,
) -> None:
    output_dir = tmp_path / "out"
    report = OutputOrchestrator().write_all(
        sample_findings_list,
        sample_remediation_results,
        sample_verification_report,
        sample_guardrail_config,
        output_dir,
    )
    for artifact in report.artifacts:
        assert artifact.filepath.is_file()
        assert artifact.size_bytes > 0


def test_final_report_generated_at_is_utc(
    tmp_path: Path,
    sample_findings_list,
    sample_remediation_results,
    sample_verification_report,
    sample_guardrail_config,
) -> None:
    report = OutputOrchestrator().write_all(
        sample_findings_list,
        sample_remediation_results,
        sample_verification_report,
        sample_guardrail_config,
        tmp_path / "out",
    )
    assert report.generated_at.tzinfo is timezone.utc


def test_tool_version_resolved(
    tmp_path: Path,
    sample_findings_list,
    sample_remediation_results,
    sample_verification_report,
    sample_guardrail_config,
) -> None:
    report = OutputOrchestrator(tool_version="9.9.9").write_all(
        sample_findings_list,
        sample_remediation_results,
        sample_verification_report,
        sample_guardrail_config,
        tmp_path / "out",
    )
    assert report.tool_version == "9.9.9"
