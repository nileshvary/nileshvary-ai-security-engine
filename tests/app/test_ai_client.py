"""Tests for the Claude AI wrapper — mocked Anthropic client."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from components import ai_client as ai_client_module
from components.ai_client import RemediAXAI

from tests.remediation_engine.fixtures.sample_findings import make_finding
from tests.verifier.fixtures.sample_remediation_results import (
    make_remediation_result,
)


def _fake_anthropic_response(text: str) -> SimpleNamespace:
    """Build a SimpleNamespace shaped like Anthropic's response object."""
    return SimpleNamespace(content=[SimpleNamespace(text=text)])


@pytest.fixture
def ai_client(monkeypatch: pytest.MonkeyPatch) -> RemediAXAI:
    """Return a RemediAXAI whose underlying messages.create is a MagicMock."""
    mock_client = MagicMock()
    mock_client.messages.create.return_value = _fake_anthropic_response("ok")

    fake_module = SimpleNamespace(Anthropic=MagicMock(return_value=mock_client))
    monkeypatch.setitem(__import__("sys").modules, "anthropic", fake_module)
    return RemediAXAI(api_key="sk-test")


def test_explain_finding_returns_text(ai_client: RemediAXAI) -> None:
    ai_client.client.messages.create.return_value = _fake_anthropic_response(
        "this is dangerous"
    )
    result = ai_client.explain_finding(make_finding("LLM01"))
    assert result == "this is dangerous"
    call = ai_client.client.messages.create.call_args
    assert call.kwargs["model"] == "claude-haiku-4-5-20251001"
    assert call.kwargs["max_tokens"] == 150
    assert call.kwargs["temperature"] == 0.3
    payload = call.kwargs["messages"][0]["content"]
    assert "LLM01" in payload
    assert "Severity" in payload


def test_explain_fix_includes_strategy(ai_client: RemediAXAI) -> None:
    ai_client.client.messages.create.return_value = _fake_anthropic_response(
        "the fix works"
    )
    result = ai_client.explain_fix(make_remediation_result("LLM01"))
    assert result == "the fix works"
    payload = ai_client.client.messages.create.call_args.kwargs["messages"][0][
        "content"
    ]
    assert "Strategy" in payload


def test_summarize_scan_counts_categories(ai_client: RemediAXAI) -> None:
    ai_client.client.messages.create.return_value = _fake_anthropic_response("ok")
    findings = [make_finding("LLM01"), make_finding("LLM02"), make_finding("LLM02")]
    result = ai_client.summarize_scan(findings)
    assert result == "ok"
    payload = ai_client.client.messages.create.call_args.kwargs["messages"][0][
        "content"
    ]
    assert "'LLM01': 1" in payload or "\"LLM01\": 1" in payload
    assert "'LLM02': 2" in payload or "\"LLM02\": 2" in payload


def test_summarize_decisions_includes_counts(ai_client: RemediAXAI) -> None:
    ai_client.client.messages.create.return_value = _fake_anthropic_response("ok")
    ai_client.summarize_decisions(approved=5, skipped=2)
    payload = ai_client.client.messages.create.call_args.kwargs["messages"][0][
        "content"
    ]
    assert "5" in payload
    assert "2" in payload


def test_call_returns_none_on_exception(ai_client: RemediAXAI) -> None:
    ai_client.client.messages.create.side_effect = RuntimeError("boom")
    assert ai_client.explain_finding(make_finding("LLM01")) is None
    assert ai_client.explain_fix(make_remediation_result("LLM01")) is None
    assert ai_client.summarize_scan([make_finding("LLM01")]) is None
    assert ai_client.summarize_decisions(1, 1) is None


def test_constructor_default_parameters(ai_client: RemediAXAI) -> None:
    assert ai_client.model == "claude-haiku-4-5-20251001"
    assert ai_client.max_tokens == 150
    assert ai_client.temperature == 0.3
