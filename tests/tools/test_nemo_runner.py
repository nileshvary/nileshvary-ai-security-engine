"""Tests for tools/nemo_runner.py."""

from __future__ import annotations

import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest
import yaml

from tools.nemo_runner import NemoRunner
from schemas.finding import Finding


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_finding(owasp: str = "LLM01", **kwargs) -> Finding:
    defaults = dict(
        probe_name=f"probe.{owasp}",
        detector_name="test.detector",
        attack_prompt="test attack",
        model_response="test response",
        is_successful_attack=True,
        owasp_llm_category=owasp,
        owasp_agentic_categories=[],
        severity="MEDIUM",
        source="pyrit",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


# ---------------------------------------------------------------------------
# Tests: config generation
# ---------------------------------------------------------------------------


class TestGenerateConfig:
    def test_returns_string(self):
        runner = NemoRunner()
        findings = [_make_finding("LLM01")]
        config = runner.generate_config(findings)
        assert isinstance(config, str)
        assert len(config) > 0

    def test_config_contains_rails_key(self):
        runner = NemoRunner()
        findings = [_make_finding("LLM01")]
        config_str = runner.generate_config(findings)
        # Strip comment lines for YAML parse
        yaml_part = "\n".join(
            line for line in config_str.splitlines() if not line.startswith("#")
        )
        parsed = yaml.safe_load(yaml_part)
        assert "rails" in parsed

    def test_llm01_finding_produces_input_rail(self):
        runner = NemoRunner()
        findings = [_make_finding("LLM01")]
        config_str = runner.generate_config(findings)
        assert "llm01" in config_str.lower()

    def test_llm02_finding_produces_output_rail(self):
        runner = NemoRunner()
        findings = [_make_finding("LLM02")]
        config_str = runner.generate_config(findings)
        assert "llm02" in config_str.lower()

    def test_empty_findings_produces_valid_yaml(self):
        runner = NemoRunner()
        config_str = runner.generate_config([])
        yaml_part = "\n".join(
            line for line in config_str.splitlines() if not line.startswith("#")
        )
        parsed = yaml.safe_load(yaml_part)
        assert "rails" in parsed

    def test_multiple_categories_all_appear(self):
        runner = NemoRunner()
        findings = [_make_finding("LLM01"), _make_finding("LLM05"), _make_finding("LLM08")]
        config_str = runner.generate_config(findings)
        assert "llm01" in config_str.lower()
        assert "llm05" in config_str.lower()
        assert "llm08" in config_str.lower()

    def test_duplicate_categories_deduplicated(self):
        runner = NemoRunner()
        findings = [_make_finding("LLM01") for _ in range(5)]
        config_str = runner.generate_config(findings)
        assert config_str.lower().count("llm01") < 5


# ---------------------------------------------------------------------------
# Tests: save_config
# ---------------------------------------------------------------------------


class TestSaveConfig:
    def test_save_config_writes_file(self):
        runner = NemoRunner()
        findings = [_make_finding("LLM01")]
        config_str = runner.generate_config(findings)
        with tempfile.TemporaryDirectory() as tmp:
            dest = Path(tmp) / "nemo_guardrails.yaml"
            result_path = runner.save_config(config_str, dest)
            assert result_path.exists()
            content = result_path.read_text(encoding="utf-8")
            assert "rails" in content


# ---------------------------------------------------------------------------
# Tests: import guard
# ---------------------------------------------------------------------------


class TestImportGuard:
    def test_raises_import_error_when_nemo_missing(self):
        with patch.dict(sys.modules, {"nemoguardrails": None}):
            with pytest.raises(ImportError, match="nemoguardrails is not installed"):
                NemoRunner()
