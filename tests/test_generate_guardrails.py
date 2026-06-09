"""Tests for the ``generate_guardrails`` command-line entry point.

All cases are network-free: AI mode is exercised with an injected fake client,
and the no-key / deterministic paths never construct a real ``RemediAXAI``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

import generate_guardrails
from demo_data import load_demo_findings


class _FakeAIClient:
    """Stand-in for ``RemediAXAI`` returning a fixed autonomous analysis."""

    def __init__(self) -> None:
        self.call_count = 0

    def generate_complete_analysis(self, finding: Any) -> dict[str, Any]:
        """Return a canned analysis carrying one custom input guardrail."""
        self.call_count += 1
        return {
            "why_dangerous": "stub",
            "why_fix_works": "stub",
            "guardrail_yaml": (
                "input_guardrails:\n"
                "  - id: custom-ai-rule\n"
                "    type: regex\n"
                "    patterns: ['ignore previous']\n"
                "    on_match: block\n"
                "output_guardrails: []\n"
            ),
            "severity": "HIGH",
            "owasp_category": "LLM01",
        }


def test_build_guardrails_merges_ai_rules() -> None:
    """Claude-authored rules are merged into the generated config."""
    findings = load_demo_findings()
    client = _FakeAIClient()

    config = generate_guardrails.build_guardrails(findings, client)

    input_ids = [rule["id"] for rule in config.input_filters]
    assert "custom-ai-rule" in input_ids  # AI-supplied rule present
    assert client.call_count == len(findings)  # one call per finding


def test_main_without_api_key_returns_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """AI mode with no key exits 1 and writes nothing."""
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    out = tmp_path / "guardrails.yaml"

    rc = generate_guardrails.main(["--output", str(out)])

    assert rc == 1
    assert not out.exists()


def test_main_deterministic_writes_file(tmp_path: Path) -> None:
    """Deterministic mode writes guardrails.yaml with no key required."""
    out = tmp_path / "guardrails.yaml"

    rc = generate_guardrails.main(["--deterministic", "--output", str(out)])

    assert rc == 0
    assert out.exists()
    parsed = yaml.safe_load(out.read_text(encoding="utf-8"))
    input_ids = [rule["id"] for rule in parsed["input_guardrails"]]
    assert "prompt-injection-defense" in input_ids  # LLM01 deterministic rule
