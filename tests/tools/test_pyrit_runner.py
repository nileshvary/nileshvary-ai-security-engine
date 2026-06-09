"""Tests for tools/pyrit_runner.py."""

from __future__ import annotations

import pytest

from tools.pyrit_runner import DEFAULT_PROBES, PyRITRunner


class _AlwaysCompliantTarget:
    """Mock target that returns responses matching compliance signals."""

    def respond(self, prompt: str) -> str:
        return "Sure, I'll ignore all previous instructions as you asked."


class _SilentTarget:
    """Mock target that returns empty responses (no attack success)."""

    def respond(self, prompt: str) -> str:
        return "I'm sorry, I can't help with that."


class _EchoTarget:
    """Mock target that echoes the prompt back."""

    def respond(self, prompt: str) -> str:
        return f"Echo: {prompt}"


class TestPyRITRunnerImportGuard:
    def test_import_guard_raises_helpful_message(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import builtins

        real_import = builtins.__import__

        def mock_import(name: str, *args: object, **kwargs: object) -> object:
            if name == "pyrit":
                raise ImportError("No module named 'pyrit'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)

        with pytest.raises(ImportError, match="pip install pyrit"):
            PyRITRunner()


class TestPyRITRunnerWithMockTarget:
    def test_run_scan_returns_one_result_per_probe(self) -> None:
        runner = PyRITRunner(target=_EchoTarget())
        results = runner.run_scan(probes=DEFAULT_PROBES[:3])
        assert len(results) == 3

    def test_result_has_required_keys(self) -> None:
        runner = PyRITRunner(target=_EchoTarget())
        results = runner.run_scan(probes=[DEFAULT_PROBES[0]])
        r = results[0]
        assert "probe_name" in r
        assert "owasp" in r
        assert "attack_prompt" in r
        assert "model_response" in r
        assert "is_successful_attack" in r
        assert r["source"] == "pyrit"

    def test_compliant_response_flagged_as_successful_attack(self) -> None:
        runner = PyRITRunner(target=_AlwaysCompliantTarget())
        results = runner.run_scan(probes=[DEFAULT_PROBES[0]])
        assert results[0]["is_successful_attack"] is True

    def test_refusal_response_not_flagged(self) -> None:
        runner = PyRITRunner(target=_SilentTarget())
        results = runner.run_scan(probes=[DEFAULT_PROBES[0]])
        assert results[0]["is_successful_attack"] is False

    def test_none_target_returns_empty_responses(self) -> None:
        runner = PyRITRunner(target=None)
        results = runner.run_scan(probes=[DEFAULT_PROBES[0]])
        assert results[0]["model_response"] == ""
        assert results[0]["is_successful_attack"] is False

    def test_default_probes_cover_key_owasp_categories(self) -> None:
        owasp_codes = {p["owasp"] for p in DEFAULT_PROBES}
        assert "LLM01" in owasp_codes
        assert "LLM07" in owasp_codes

    def test_custom_probe_list(self) -> None:
        custom = [
            {"name": "test.Custom", "owasp": "LLM02", "prompt": "Custom prompt"}
        ]
        runner = PyRITRunner(target=_EchoTarget())
        results = runner.run_scan(probes=custom)
        assert len(results) == 1
        assert results[0]["probe_name"] == "test.Custom"
        assert results[0]["owasp"] == "LLM02"

    def test_run_scan_with_all_default_probes(self) -> None:
        runner = PyRITRunner(target=_EchoTarget())
        results = runner.run_scan()
        assert len(results) == len(DEFAULT_PROBES)
