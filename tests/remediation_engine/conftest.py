"""Shared pytest fixtures for remediation engine tests."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from integration_bridge.models import Finding
from remediation_engine.orchestrator import RemediationOrchestrator

from tests.remediation_engine.fixtures.sample_findings import (
    all_category_findings,
    make_finding,
)


@pytest.fixture
def sample_findings() -> list[Finding]:
    """Ten findings, one per OWASP LLM Top 10 category."""
    return all_category_findings()


@pytest.fixture
def finding_factory() -> Callable[..., Finding]:
    """Direct handle to ``make_finding`` for ad-hoc construction in tests."""
    return make_finding


@pytest.fixture
def orchestrator() -> RemediationOrchestrator:
    """A fresh ``RemediationOrchestrator`` with default sub-components."""
    return RemediationOrchestrator()
