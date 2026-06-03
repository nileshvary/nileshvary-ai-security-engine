"""Tests for the internal GarakRunner subprocess driver."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from components.garak_runner import GarakRunner


# ---------------------------------------------------------------------------
# build_command — flag wiring (current --target_* flags, no shell injection)
# ---------------------------------------------------------------------------


def test_build_command_uses_target_type_and_target_name_flags() -> None:
    cmd = GarakRunner().build_command(
        target_type="huggingface",
        target_name="gpt2",
        probes=["dan", "promptinject"],
    )
    assert cmd[:3] == [sys.executable, "-m", "garak"]
    assert "--target_type" in cmd
    assert "--target_name" in cmd
    # Deprecated aliases must not be emitted.
    assert "--model_type" not in cmd
    assert "--model_name" not in cmd


def test_build_command_argv_is_a_list_not_a_string() -> None:
    """Lists keep shell=False subprocess invocations safe from injection."""
    cmd = GarakRunner().build_command(
        target_type="huggingface", target_name="gpt2; rm -rf /"
    )
    # Hostile target_name stays as a single argv element — not split,
    # not interpreted by a shell.
    assert "gpt2; rm -rf /" in cmd
    assert isinstance(cmd, list)


def test_build_command_strips_whitespace_from_inputs() -> None:
    cmd = GarakRunner().build_command(
        target_type="  openai  ",
        target_name=" gpt-4\n",
        probes=[" dan ", "  promptinject "],
    )
    idx = cmd.index("--target_type")
    assert cmd[idx + 1] == "openai"
    idx = cmd.index("--target_name")
    assert cmd[idx + 1] == "gpt-4"
    idx = cmd.index("--probes")
    assert cmd[idx + 1] == "dan,promptinject"


def test_build_command_omits_probes_flag_when_empty() -> None:
    cmd = GarakRunner().build_command(
        target_type="huggingface", target_name="gpt2", probes=[]
    )
    assert "--probes" not in cmd


def test_build_command_omits_target_name_when_empty() -> None:
    cmd = GarakRunner().build_command(
        target_type="rest.RestGenerator", target_name="", probes=["dan"]
    )
    assert "--target_name" not in cmd


def test_build_command_ignores_api_key_argument() -> None:
    """API keys go in env, never on the command line — see run_scan."""
    cmd = GarakRunner().build_command(
        target_type="openai", target_name="gpt-4", api_key="sk-secret"
    )
    assert "sk-secret" not in " ".join(cmd)


# ---------------------------------------------------------------------------
# is_garak_installed — mocked subprocess.run
# ---------------------------------------------------------------------------


def test_is_garak_installed_true_when_subprocess_exits_zero() -> None:
    fake = MagicMock(returncode=0, stdout="garak 0.13.0\n", stderr="")
    with patch("components.garak_runner.subprocess.run", return_value=fake):
        assert GarakRunner().is_garak_installed() is True


def test_is_garak_installed_false_when_subprocess_exits_nonzero() -> None:
    fake = MagicMock(returncode=1, stdout="", stderr="No module named garak")
    with patch("components.garak_runner.subprocess.run", return_value=fake):
        assert GarakRunner().is_garak_installed() is False


def test_is_garak_installed_false_when_python_missing() -> None:
    with patch(
        "components.garak_runner.subprocess.run",
        side_effect=FileNotFoundError("python: not found"),
    ):
        assert GarakRunner().is_garak_installed() is False


def test_is_garak_installed_false_on_timeout() -> None:
    with patch(
        "components.garak_runner.subprocess.run",
        side_effect=subprocess.TimeoutExpired("python -m garak --version", 15),
    ):
        assert GarakRunner().is_garak_installed() is False


# ---------------------------------------------------------------------------
# run_scan — streaming generator over subprocess stdout
# ---------------------------------------------------------------------------


def _fake_popen(lines: list[str], returncode: int = 0) -> MagicMock:
    """Build a MagicMock that pretends to be a Popen object."""
    proc = MagicMock()
    proc.stdout = iter(line + "\n" for line in lines)
    proc.wait.return_value = returncode
    return proc


def test_run_scan_yields_each_stdout_line_in_order() -> None:
    fake_lines = [
        "Loading model gpt2",
        "Running probe dan.Dan_11_0",
        "complete",
    ]
    with patch(
        "components.garak_runner.subprocess.Popen",
        return_value=_fake_popen(fake_lines, returncode=0),
    ):
        gen = GarakRunner().run_scan(["python", "-m", "garak"])
        collected = list(gen)
    assert collected == fake_lines


def test_run_scan_passes_api_key_via_env_not_argv() -> None:
    """API key must be exported into the child env, never on the CLI."""
    captured: dict[str, object] = {}

    def _capture_popen(command, **kwargs):  # noqa: ANN001
        captured["command"] = command
        captured["env"] = kwargs.get("env", {})
        return _fake_popen([], returncode=0)

    with patch("components.garak_runner.subprocess.Popen", side_effect=_capture_popen):
        list(
            GarakRunner().run_scan(
                ["python", "-m", "garak", "--target_type", "openai"],
                env_extra={"OPENAI_API_KEY": "sk-very-secret"},
            )
        )
    # API key must be in env, not in the argv list.
    assert "sk-very-secret" not in " ".join(map(str, captured["command"]))
    assert captured["env"]["OPENAI_API_KEY"] == "sk-very-secret"
    # PYTHONUNBUFFERED is set so progress streams in real time.
    assert captured["env"]["PYTHONUNBUFFERED"] == "1"


def test_run_scan_uses_shell_false() -> None:
    captured: dict[str, object] = {}

    def _capture_popen(command, **kwargs):  # noqa: ANN001
        captured.update(kwargs)
        return _fake_popen([], returncode=0)

    with patch("components.garak_runner.subprocess.Popen", side_effect=_capture_popen):
        list(GarakRunner().run_scan(["python", "-m", "garak"]))
    # Popen's default for `shell` is False; assert we never override.
    assert captured.get("shell", False) is False
    # Text mode + line buffering for streaming.
    assert captured.get("text") is True
    assert captured.get("bufsize") == 1


def test_run_scan_emits_error_line_when_executable_missing() -> None:
    with patch(
        "components.garak_runner.subprocess.Popen",
        side_effect=FileNotFoundError("python: no such file"),
    ):
        out = list(GarakRunner().run_scan(["python", "-m", "garak"]))
    assert any("ERROR" in line for line in out)


# ---------------------------------------------------------------------------
# get_latest_report — newest .report.jsonl wins
# ---------------------------------------------------------------------------


def test_get_latest_report_returns_none_when_dir_missing(tmp_path: Path) -> None:
    runner = GarakRunner()
    with patch.object(
        type(runner),
        "_LINUX_MAC_DIR",
        tmp_path / "does" / "not" / "exist",
    ), patch.object(
        type(runner),
        "_WINDOWS_DIR",
        tmp_path / "does" / "not" / "exist",
    ):
        assert runner.get_latest_report() is None


def test_get_latest_report_picks_newest_by_mtime(tmp_path: Path) -> None:
    runs = tmp_path / "garak_runs"
    runs.mkdir()
    older = runs / "garak.aaa.report.jsonl"
    newer = runs / "garak.bbb.report.jsonl"
    older.write_text('{"entry_type": "completion"}\n')
    newer.write_text('{"entry_type": "completion"}\n')
    # Force a meaningful mtime difference.
    import os as _os
    _os.utime(older, (1_000_000, 1_000_000))
    _os.utime(newer, (2_000_000, 2_000_000))

    runner = GarakRunner()
    with patch.object(type(runner), "_LINUX_MAC_DIR", runs), patch.object(
        type(runner), "_WINDOWS_DIR", runs
    ):
        assert runner.get_latest_report() == newer


def test_get_latest_report_returns_none_when_dir_empty(tmp_path: Path) -> None:
    runs = tmp_path / "empty_runs"
    runs.mkdir()
    runner = GarakRunner()
    with patch.object(type(runner), "_LINUX_MAC_DIR", runs), patch.object(
        type(runner), "_WINDOWS_DIR", runs
    ):
        assert runner.get_latest_report() is None


# ---------------------------------------------------------------------------
# parse_report — delegates to the existing GarakParser end-to-end
# ---------------------------------------------------------------------------


def test_parse_report_uses_real_garak_parser(tmp_path: Path) -> None:
    # Minimal real-garak-shaped report — one attempt with a hit.
    report = tmp_path / "garak.x.report.jsonl"
    rows = [
        {"entry_type": "init"},
        {
            "entry_type": "attempt",
            "status": 2,
            "probe_classname": "dan.DAN_Jailbreak",
            "prompt": {"text": "p"},
            "outputs": [{"text": "o"}],
            "detector_results": {"d": [1.0]},
        },
        {
            "entry_type": "eval",
            "probe": "dan.DAN_Jailbreak",
            "detector": "d",
            "passed": 1,
            "total_evaluated": 1,
        },
    ]
    report.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")

    findings = GarakRunner().parse_report(report)
    assert len(findings) == 1
    assert findings[0].probe_name == "dan.DAN_Jailbreak"
    assert findings[0].severity == "CRITICAL"
