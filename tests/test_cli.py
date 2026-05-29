"""Tests for the ``ai-security-engine`` CLI argument parsing.

These tests mock out the heavy pipeline so we exercise argparse + the
``main`` dispatcher without doing real file I/O.
"""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from ai_security_engine import __main__ as cli


def test_no_args_prints_help(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = cli.main([])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "remediate" in out
    assert "version" in out


def test_help_command(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = cli.main(["help"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "Usage" in out
    assert "remediate" in out


def test_version_command(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = cli.main(["version"])
    out = capsys.readouterr().out
    assert exit_code == 0
    assert "ai-security-engine" in out


def test_missing_required_arg_exits_with_code_2() -> None:
    with pytest.raises(SystemExit) as exc_info:
        cli.main(["remediate"])
    assert exc_info.value.code == 2


def test_invalid_format_exits_with_code_2(tmp_path: Path) -> None:
    hitlog = tmp_path / "hitlog.jsonl"
    hitlog.write_text("", encoding="utf-8")
    with pytest.raises(SystemExit) as exc_info:
        cli.main(
            [
                "remediate",
                "--input",
                str(hitlog),
                "--output",
                str(tmp_path / "out"),
                "--format",
                "bogus",
            ]
        )
    assert exc_info.value.code == 2


def test_missing_input_file_returns_2(tmp_path: Path) -> None:
    missing = tmp_path / "does-not-exist.jsonl"
    exit_code = cli.main(
        [
            "remediate",
            "--input",
            str(missing),
            "--output",
            str(tmp_path / "out"),
        ]
    )
    assert exit_code == 2


def test_missing_prompt_file_returns_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hitlog = tmp_path / "hitlog.jsonl"
    hitlog.write_text("{}\n", encoding="utf-8")
    # Stub the parser to avoid running on the placeholder hitlog before
    # we hit the prompt-file check.
    monkeypatch.setattr(
        cli.GarakParser,
        "parse",
        lambda self: [],
    )
    exit_code = cli.main(
        [
            "remediate",
            "--input",
            str(hitlog),
            "--output",
            str(tmp_path / "out"),
            "--prompt",
            str(tmp_path / "missing-prompt.txt"),
        ]
    )
    assert exit_code == 2


def test_verbose_flag_enables_debug_logging(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    hitlog = tmp_path / "hitlog.jsonl"
    hitlog.write_text("", encoding="utf-8")

    # Stub every pipeline stage so we only exercise CLI wiring.
    monkeypatch.setattr(cli.GarakParser, "parse", lambda self: [])

    class _FakeRem:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def remediate_findings(self, findings, original_prompt=None):
            return []

    class _FakeVer:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def verify_all(self, results, mode="quick"):
            class _Report:
                results = []
                total_findings = 0
                verified_count = 0
                partial_count = 0
                failed_count = 0
                unverifiable_count = 0
                overall_improvement_percent = 0.0
                summary: dict = {}

            return _Report()

    class _FakeGen:
        def generate(self, findings, fmt):
            from remediation_engine.models import GuardrailConfig

            return GuardrailConfig(
                format=fmt,
                input_filters=[],
                output_filters=[],
                rate_limits={},
                yaml_export="version: 1\n",
            )

    class _FakeOut:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def write_all(self, **kwargs):
            from datetime import datetime, timezone
            from output.models import FinalReport

            return FinalReport(
                findings=kwargs["findings"],
                remediation_results=kwargs["remediation_results"],
                verification_report=kwargs["verification_report"],
                guardrail_config=kwargs["guardrail_config"],
                artifacts=[],
                generated_at=datetime.now(timezone.utc),
                tool_version="test",
            )

    monkeypatch.setattr(cli, "RemediationOrchestrator", _FakeRem)
    monkeypatch.setattr(cli, "VerificationOrchestrator", _FakeVer)
    monkeypatch.setattr(cli, "GuardrailGenerator", _FakeGen)
    monkeypatch.setattr(cli, "OutputOrchestrator", _FakeOut)

    exit_code = cli.main(
        [
            "remediate",
            "--input",
            str(hitlog),
            "--output",
            str(tmp_path / "out"),
            "--verbose",
        ]
    )
    assert exit_code == 0
    assert logging.getLogger().level == logging.DEBUG
