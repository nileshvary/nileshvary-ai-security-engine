"""Tests for the 10-finding demo factory."""

from __future__ import annotations

from collections import Counter

import pytest

from demo_data import load_demo_findings

from integration_bridge.models import Finding


_VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}


@pytest.fixture
def demo_findings() -> list[Finding]:
    return load_demo_findings()


def test_returns_exactly_ten_findings(demo_findings: list[Finding]) -> None:
    assert len(demo_findings) == 10


def test_covers_every_owasp_llm_category(demo_findings: list[Finding]) -> None:
    codes = [f.owasp_llm_category for f in demo_findings]
    assert set(codes) == {f"LLM{i:02d}" for i in range(1, 11)}
    # No duplicates either.
    counts = Counter(codes)
    assert all(c == 1 for c in counts.values())


@pytest.mark.parametrize("idx", range(10))
def test_each_finding_has_non_empty_strings(
    demo_findings: list[Finding], idx: int
) -> None:
    f = demo_findings[idx]
    assert f.probe_name
    assert f.detector_name
    assert f.attack_prompt
    assert f.model_response
    assert f.severity in _VALID_SEVERITIES


def test_findings_are_real_dataclass_instances(demo_findings: list[Finding]) -> None:
    for f in demo_findings:
        assert isinstance(f, Finding)
        assert f.is_successful_attack is True


def test_demo_run_id_consistent(demo_findings: list[Finding]) -> None:
    for f in demo_findings:
        assert f.raw_data.get("run_id") == "demo-run"


def test_demo_findings_route_correctly_through_pipeline(
    demo_findings: list[Finding],
) -> None:
    """Smoke: feeding the demo through the real engine yields 10 results."""
    from remediation_engine import RemediationOrchestrator
    from verifier import VerificationOrchestrator

    results = RemediationOrchestrator().remediate_findings(
        demo_findings, original_prompt="You are a helpful assistant."
    )
    assert len(results) == 10
    report = VerificationOrchestrator().verify_all(results, mode="quick")
    assert report.total_findings == 10
