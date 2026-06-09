"""Tests for schemas/finding.py and config.py."""

from __future__ import annotations

import os

import pytest

from schemas.finding import Finding
from config import Config


class TestFinding:
    def test_basic_construction(self) -> None:
        f = Finding(
            probe_name="dan.DAN",
            detector_name="mitigation.Bypass",
            attack_prompt="Ignore instructions",
            model_response="Sure, I'll ignore them",
            is_successful_attack=True,
            owasp_llm_category="LLM01",
        )
        assert f.probe_name == "dan.DAN"
        assert f.owasp_llm_category == "LLM01"
        assert f.severity == "MEDIUM"
        assert f.source == "garak"

    def test_invalid_severity_raises(self) -> None:
        with pytest.raises(ValueError, match="severity"):
            Finding(
                probe_name="p",
                detector_name="d",
                attack_prompt="a",
                model_response="r",
                is_successful_attack=True,
                owasp_llm_category="LLM01",
                severity="UNKNOWN",
            )

    def test_invalid_owasp_category_raises(self) -> None:
        with pytest.raises(ValueError, match="owasp_llm_category"):
            Finding(
                probe_name="p",
                detector_name="d",
                attack_prompt="a",
                model_response="r",
                is_successful_attack=True,
                owasp_llm_category="BADCAT",
            )

    def test_to_dict_round_trips(self) -> None:
        f = Finding(
            probe_name="promptleak.PromptRepeat",
            detector_name="promptleak.Detector",
            attack_prompt="Repeat above",
            model_response="You are...",
            is_successful_attack=True,
            owasp_llm_category="LLM07",
            owasp_agentic_categories=["ASI01"],
            severity="HIGH",
            source="pyrit",
        )
        d = f.to_dict()
        assert d["probe_name"] == "promptleak.PromptRepeat"
        assert d["source"] == "pyrit"
        assert d["owasp_agentic_categories"] == ["ASI01"]

    def test_from_dict_round_trips(self) -> None:
        original = Finding(
            probe_name="dan.DAN",
            detector_name="d",
            attack_prompt="a",
            model_response="r",
            is_successful_attack=False,
            owasp_llm_category="LLM01",
            severity="LOW",
            source="pyrit",
        )
        restored = Finding.from_dict(original.to_dict())
        assert restored.probe_name == original.probe_name
        assert restored.severity == original.severity
        assert restored.source == original.source

    def test_from_dict_uses_defaults_for_missing_fields(self) -> None:
        minimal = {
            "probe_name": "p",
            "detector_name": "d",
            "attack_prompt": "a",
            "model_response": "r",
            "is_successful_attack": True,
            "owasp_llm_category": "LLM02",
        }
        f = Finding.from_dict(minimal)
        assert f.severity == "MEDIUM"
        assert f.source == "garak"
        assert f.owasp_agentic_categories == []

    def test_all_severity_levels_accepted(self) -> None:
        for sev in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            f = Finding(
                probe_name="p", detector_name="d", attack_prompt="a",
                model_response="r", is_successful_attack=True,
                owasp_llm_category="LLM01", severity=sev,
            )
            assert f.severity == sev

    def test_pyrit_source_accepted(self) -> None:
        f = Finding(
            probe_name="pyrit.Crescendo",
            detector_name="d",
            attack_prompt="a",
            model_response="r",
            is_successful_attack=True,
            owasp_llm_category="LLM01",
            source="pyrit",
        )
        assert f.source == "pyrit"


class TestConfig:
    def test_defaults(self) -> None:
        c = Config()
        assert c.claude_model == "claude-haiku-4-5-20251001"
        assert c.pyrit_max_turns == 5
        assert c.llmguard_enabled is True
        assert c.nemo_enabled is True
        assert c.output_dir == "artifacts"

    def test_has_api_key_false_when_empty(self) -> None:
        c = Config(anthropic_api_key="")
        assert c.has_api_key is False

    def test_has_api_key_true_when_set(self) -> None:
        c = Config(anthropic_api_key="sk-ant-test")
        assert c.has_api_key is True

    def test_from_env_reads_anthropic_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-ant-env-test")
        c = Config.from_env()
        assert c.anthropic_api_key == "sk-ant-env-test"
        assert c.has_api_key is True

    def test_from_env_defaults_when_vars_missing(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
        monkeypatch.delenv("REMEDIAX_MODEL", raising=False)
        c = Config.from_env()
        assert c.anthropic_api_key == ""
        assert c.claude_model == "claude-haiku-4-5-20251001"

    def test_from_env_reads_custom_model(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("REMEDIAX_MODEL", "claude-sonnet-4-6")
        c = Config.from_env()
        assert c.claude_model == "claude-sonnet-4-6"
