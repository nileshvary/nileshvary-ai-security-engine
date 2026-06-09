"""Tests for ``RemediationOrchestrator`` routing and out-of-band behavior."""

from __future__ import annotations

import logging
from unittest.mock import MagicMock

import pytest

from remediation_engine.models import RemediationStrategy
from remediation_engine.orchestrator import RemediationOrchestrator

from tests.remediation_engine.fixtures.sample_findings import (
    all_category_findings,
    make_finding,
    out_of_band_findings,
)


# ---------------------------------------------------------------------------
# Routing: every category maps to the expected strategy.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("category", "expected_strategy"),
    [
        ("LLM01", RemediationStrategy.HARDEN),
        ("LLM02", RemediationStrategy.SANITIZE),
        ("LLM03", RemediationStrategy.LOG_ONLY),
        ("LLM04", RemediationStrategy.LOG_ONLY),
        ("LLM05", RemediationStrategy.SANITIZE),
        ("LLM06", RemediationStrategy.LOG_ONLY),
        ("LLM07", RemediationStrategy.HARDEN),
        ("LLM08", RemediationStrategy.LOG_ONLY),
        ("LLM09", RemediationStrategy.LOG_ONLY),
        ("LLM10", RemediationStrategy.GUARDRAIL),
    ],
)
def test_routing_strategy_per_category(
    orchestrator: RemediationOrchestrator,
    category: str,
    expected_strategy: RemediationStrategy,
) -> None:
    finding = make_finding(category)
    [result] = orchestrator.remediate_findings(
        [finding], original_prompt="You are a helpful assistant."
    )
    assert result.strategy is expected_strategy


# ---------------------------------------------------------------------------
# Confidence: severity table for in-band; 0.0 override for out-of-band.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("severity", "expected_confidence"),
    [
        ("CRITICAL", 0.95),
        ("HIGH", 0.85),
        ("MEDIUM", 0.70),
        ("LOW", 0.50),
        ("UNKNOWN", 0.50),
    ],
)
def test_confidence_from_severity_in_band(
    orchestrator: RemediationOrchestrator,
    severity: str,
    expected_confidence: float,
) -> None:
    finding = make_finding("LLM02", severity=severity)
    [result] = orchestrator.remediate_findings([finding])
    assert result.confidence == pytest.approx(expected_confidence)


@pytest.mark.parametrize("category", ["LLM03", "LLM04", "LLM08", "LLM09"])
@pytest.mark.parametrize("severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
def test_out_of_band_confidence_pinned_to_zero(
    orchestrator: RemediationOrchestrator,
    category: str,
    severity: str,
) -> None:
    finding = make_finding(category, severity=severity)
    [result] = orchestrator.remediate_findings([finding])
    assert result.confidence == 0.0


# ---------------------------------------------------------------------------
# Out-of-band notes content.
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("category", "expected_tool_keyword"),
    [
        ("LLM03", "Sigstore"),
        ("LLM04", "Neural Cleanse"),
        ("LLM08", "Pinecone"),
        ("LLM09", "SelfCheckGPT"),
    ],
)
def test_out_of_band_notes_reference_recommended_tool(
    orchestrator: RemediationOrchestrator,
    category: str,
    expected_tool_keyword: str,
) -> None:
    [result] = orchestrator.remediate_findings([make_finding(category)])
    assert result.notes, "out-of-band result must include notes"
    assert any(
        "runtime remediation not applicable" in n for n in result.notes
    ), "first note should explain why runtime remediation does not apply"
    joined = "\n".join(result.notes)
    assert expected_tool_keyword in joined


@pytest.mark.parametrize("category", ["LLM03", "LLM04", "LLM08", "LLM09"])
def test_out_of_band_artifacts_are_none(
    orchestrator: RemediationOrchestrator, category: str
) -> None:
    [result] = orchestrator.remediate_findings([make_finding(category)])
    assert result.prompt_patch is None
    assert result.response_sanitization is None


# ---------------------------------------------------------------------------
# Module wiring: prompt + response remediators actually run.
# ---------------------------------------------------------------------------


def test_llm01_finding_gets_prompt_patch_when_prompt_provided(
    orchestrator: RemediationOrchestrator,
) -> None:
    [result] = orchestrator.remediate_findings(
        [make_finding("LLM01")], original_prompt="You are a helpful assistant."
    )
    assert result.strategy is RemediationStrategy.HARDEN
    assert result.prompt_patch is not None
    assert "<user_input>" in result.prompt_patch.patched_prompt


def test_llm01_finding_downgraded_when_no_prompt(
    orchestrator: RemediationOrchestrator,
    caplog: pytest.LogCaptureFixture,
) -> None:
    with caplog.at_level(logging.WARNING, logger="remediation_engine.orchestrator"):
        [result] = orchestrator.remediate_findings([make_finding("LLM01")])
    assert result.strategy is RemediationStrategy.LOG_ONLY
    assert result.prompt_patch is None
    assert any("prompt patch skipped" in n for n in result.notes)
    assert any("downgraded to LOG_ONLY" in rec.message for rec in caplog.records)


def test_llm02_finding_gets_response_sanitization(
    orchestrator: RemediationOrchestrator,
) -> None:
    finding = make_finding(
        "LLM02",
        model_response="SSN: 123-45-6789",
    )
    [result] = orchestrator.remediate_findings([finding])
    assert result.response_sanitization is not None
    assert "[REDACTED-SSN]" in result.response_sanitization.sanitized_response


def test_llm06_finding_gets_flag_only_sanitization(
    orchestrator: RemediationOrchestrator,
) -> None:
    finding = make_finding(
        "LLM06",
        model_response="calling tool: shell_exec",
    )
    [result] = orchestrator.remediate_findings([finding])
    assert result.response_sanitization is not None
    # flag-only: sanitized_response equals the original.
    assert (
        result.response_sanitization.sanitized_response
        == result.response_sanitization.original_response
    )
    assert len(result.response_sanitization.detected_issues) >= 1


# ---------------------------------------------------------------------------
# Whole-batch behavior.
# ---------------------------------------------------------------------------


def test_every_finding_produces_exactly_one_result(
    orchestrator: RemediationOrchestrator,
) -> None:
    findings = all_category_findings()
    results = orchestrator.remediate_findings(
        findings, original_prompt="You are a helpful assistant."
    )
    assert len(results) == len(findings) == 10


def test_global_guardrail_config_same_instance_everywhere(
    orchestrator: RemediationOrchestrator,
) -> None:
    findings = all_category_findings()
    results = orchestrator.remediate_findings(findings)
    configs = [r.guardrail_config for r in results]
    assert all(c is configs[0] for c in configs)
    assert configs[0] is not None


def test_empty_findings_produces_empty_results(
    orchestrator: RemediationOrchestrator,
) -> None:
    results = orchestrator.remediate_findings([])
    assert results == []


def test_out_of_band_batch_all_get_notes(
    orchestrator: RemediationOrchestrator,
) -> None:
    results = orchestrator.remediate_findings(out_of_band_findings())
    assert len(results) == 4
    for result in results:
        assert result.strategy is RemediationStrategy.LOG_ONLY
        assert result.confidence == 0.0
        assert result.notes


# ---------------------------------------------------------------------------
# Claude API: ai_client forwarded to GuardrailGenerator.
# ---------------------------------------------------------------------------


def test_ai_client_forwarded_to_guardrail_generator() -> None:
    mock_ai = MagicMock()
    mock_ai.generate_complete_analysis.return_value = None
    orchestrator = RemediationOrchestrator(ai_client=mock_ai)
    orchestrator.remediate_findings([make_finding("LLM01")])
    mock_ai.generate_complete_analysis.assert_called_once()


def test_no_ai_client_still_produces_results() -> None:
    orchestrator = RemediationOrchestrator(ai_client=None)
    results = orchestrator.remediate_findings([make_finding("LLM01")])
    assert len(results) == 1
    assert results[0].guardrail_config is not None
