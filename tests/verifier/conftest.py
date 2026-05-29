"""Shared pytest fixtures for verifier tests."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from remediation_engine.models import RemediationResult
from verifier.orchestrator import VerificationOrchestrator
from verifier.quick_verifier import QuickVerifier

from tests.verifier.fixtures.sample_remediation_results import (
    all_category_results,
    make_remediation_result,
)


@pytest.fixture
def sample_results() -> list[RemediationResult]:
    """Ten ``RemediationResult``s, one per OWASP LLM Top 10 category."""
    return all_category_results()


@pytest.fixture
def result_factory() -> Callable[..., RemediationResult]:
    """Direct handle to ``make_remediation_result`` for ad-hoc construction."""
    return make_remediation_result


@pytest.fixture
def quick_verifier() -> QuickVerifier:
    """A fresh ``QuickVerifier`` instance."""
    return QuickVerifier()


@pytest.fixture
def verifier_orchestrator() -> VerificationOrchestrator:
    """A fresh ``VerificationOrchestrator`` with default sub-components."""
    return VerificationOrchestrator()
