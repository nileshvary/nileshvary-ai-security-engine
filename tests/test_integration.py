"""End-to-end pipeline test using the real Phase 2 sample hitlog.

No mocks — runs ``main(["remediate", ...])`` and asserts every expected
artifact lands on disk and parses back correctly.
"""

from __future__ import annotations

import json
from pathlib import Path

import yaml

from ai_security_engine.__main__ import main


_SAMPLE_HITLOG = (
    Path(__file__).parent
    / "integration_bridge"
    / "fixtures"
    / "sample_hitlog.jsonl"
)


def test_sample_hitlog_fixture_exists() -> None:
    assert _SAMPLE_HITLOG.is_file()


def test_full_pipeline_writes_all_artifacts(tmp_path: Path) -> None:
    output_dir = tmp_path / "out"
    prompt_path = tmp_path / "system_prompt.txt"
    prompt_path.write_text("You are a helpful assistant.", encoding="utf-8")

    exit_code = main(
        [
            "remediate",
            "--input",
            str(_SAMPLE_HITLOG),
            "--output",
            str(output_dir),
            "--format",
            "portkey",
            "--prompt",
            str(prompt_path),
        ]
    )

    assert exit_code == 0
    for filename in (
        "findings.json",
        "remediation_results.json",
        "verification_report.json",
        "guardrails.yaml",
        "patched_prompts.md",
        "summary.html",
    ):
        path = output_dir / filename
        assert path.is_file(), f"missing artifact: {filename}"
        assert path.stat().st_size > 0


def test_findings_json_parses_and_has_seven_rows(tmp_path: Path) -> None:
    output_dir = tmp_path / "out"
    main(
        [
            "remediate",
            "--input",
            str(_SAMPLE_HITLOG),
            "--output",
            str(output_dir),
        ]
    )
    data = json.loads((output_dir / "findings.json").read_text(encoding="utf-8"))
    # Phase 2 sample_hitlog.jsonl has 7 rows.
    assert len(data) == 7


def test_guardrails_yaml_parses_back(tmp_path: Path) -> None:
    output_dir = tmp_path / "out"
    main(
        [
            "remediate",
            "--input",
            str(_SAMPLE_HITLOG),
            "--output",
            str(output_dir),
        ]
    )
    parsed = yaml.safe_load((output_dir / "guardrails.yaml").read_text(encoding="utf-8"))
    assert isinstance(parsed, dict)
    assert "version" in parsed


def test_summary_html_is_self_contained(tmp_path: Path) -> None:
    output_dir = tmp_path / "out"
    main(
        [
            "remediate",
            "--input",
            str(_SAMPLE_HITLOG),
            "--output",
            str(output_dir),
        ]
    )
    content = (output_dir / "summary.html").read_text(encoding="utf-8")
    assert content.startswith("<!doctype html>")
    assert "<script>" not in content
    assert "http://" not in content
    assert "https://" not in content


def test_verification_report_has_seven_results(tmp_path: Path) -> None:
    output_dir = tmp_path / "out"
    main(
        [
            "remediate",
            "--input",
            str(_SAMPLE_HITLOG),
            "--output",
            str(output_dir),
        ]
    )
    data = json.loads(
        (output_dir / "verification_report.json").read_text(encoding="utf-8")
    )
    assert data["total_findings"] == 7
    assert len(data["results"]) == 7


def test_litellm_format_changes_yaml_shape(tmp_path: Path) -> None:
    output_dir = tmp_path / "out"
    main(
        [
            "remediate",
            "--input",
            str(_SAMPLE_HITLOG),
            "--output",
            str(output_dir),
            "--format",
            "litellm",
        ]
    )
    parsed = yaml.safe_load((output_dir / "guardrails.yaml").read_text(encoding="utf-8"))
    # litellm format has the "guardrails" top-level key, portkey uses "input_guardrails".
    assert "guardrails" in parsed
    assert "input_guardrails" not in parsed
