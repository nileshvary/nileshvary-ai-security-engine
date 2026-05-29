"""Shared pytest fixtures for output-stage tests."""

from __future__ import annotations

import pytest

from remediation_engine.guardrail_generator.generator import GuardrailGenerator
from remediation_engine.models import GuardrailConfig, RemediationResult
from verifier.models import VerificationReport
from verifier.orchestrator import VerificationOrchestrator

from tests.remediation_engine.fixtures.sample_findings import all_category_findings
from tests.verifier.fixtures.sample_remediation_results import all_category_results


@pytest.fixture
def sample_findings_list() -> list:
    """Ten findings, one per OWASP LLM Top 10 category."""
    return all_category_findings()


@pytest.fixture
def sample_remediation_results() -> list[RemediationResult]:
    """Ten RemediationResults, one per category."""
    return all_category_results()


@pytest.fixture
def sample_verification_report(
    sample_remediation_results: list[RemediationResult],
) -> VerificationReport:
    """A verification report produced from the sample remediation results."""
    return VerificationOrchestrator().verify_all(
        sample_remediation_results, mode="quick"
    )


@pytest.fixture
def sample_guardrail_config(
    sample_findings_list: list,
) -> GuardrailConfig:
    """A guardrail config built from the sample findings list."""
    return GuardrailGenerator().generate(sample_findings_list, output_format="portkey")
