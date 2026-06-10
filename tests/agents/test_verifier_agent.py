"""Tests for agents/verifier_agent.py (Agent 4 — Verifier)."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Path setup — ensure src/ is on sys.path before importing agents
# ---------------------------------------------------------------------------
_ROOT = Path(__file__).parent.parent.parent
_SRC = _ROOT / "src"
for _p in (_ROOT, str(_SRC)):
    if str(_p) not in sys.path:
        sys.path.insert(0, str(_p))

from agents.verifier_agent import VerifierAgent, _report_to_dict, _result_to_dict


# ---------------------------------------------------------------------------
# Helpers: build minimal mock objects shaped like real dataclasses
# ---------------------------------------------------------------------------


def _make_finding(
    probe_name: str = "probe.LLM01",
    owasp: str = "LLM01",
    severity: str = "HIGH",
) -> MagicMock:
    f = MagicMock()
    f.probe_name = probe_name
    f.owasp_llm_category = owasp
    f.severity = severity
    f.to_dict.return_value = {
        "probe_name": probe_name,
        "owasp_llm_category": owasp,
        "severity": severity,
    }
    return f


def _make_remediation_result(finding: Any, strategy: str = "HARDEN") -> MagicMock:
    rr = MagicMock()
    rr.finding = finding
    rr.strategy = strategy
    rr.notes = ["recommended: check logs"]
    gc = MagicMock()
    gc.yaml_export = "input_guardrails:\n  - id: test\n"
    rr.guardrail_config = gc
    return rr


def _make_verification_result(
    remediation_result: Any,
    status: str = "VERIFIED",
    before: float = 0.85,
    after: float = 0.05,
) -> MagicMock:
    vr = MagicMock()
    vr.remediation_result = remediation_result
    vr.mode = "quick"
    vr.verification_status = status
    vr.before_success_rate = before
    vr.after_success_rate = after
    vr.improvement_percent = (before - after) / before * 100 if before > 0 else None
    vr.confidence = 0.9
    vr.notes = ["heuristic check: prompt patch applied"]
    return vr


def _make_report(
    n_verified: int = 2,
    n_failed: int = 0,
    n_unverifiable: int = 1,
) -> MagicMock:
    results = []
    for i in range(n_verified):
        f = _make_finding(probe_name=f"probe.v{i}", owasp="LLM01")
        rr = _make_remediation_result(f)
        results.append(_make_verification_result(rr, status="VERIFIED"))
    for i in range(n_failed):
        f = _make_finding(probe_name=f"probe.f{i}", owasp="LLM07")
        rr = _make_remediation_result(f)
        results.append(_make_verification_result(rr, status="FAILED", before=0.55, after=0.55))
    for i in range(n_unverifiable):
        f = _make_finding(probe_name=f"probe.u{i}", owasp="LLM03")
        rr = _make_remediation_result(f)
        vr = MagicMock()
        vr.remediation_result = rr
        vr.mode = "skipped"
        vr.verification_status = "UNVERIFIABLE"
        vr.before_success_rate = None
        vr.after_success_rate = None
        vr.improvement_percent = None
        vr.confidence = 0.0
        vr.notes = ["verification skipped for LLM03"]
        results.append(vr)

    report = MagicMock()
    report.results = results
    report.total_findings = len(results)
    report.verified_count = n_verified
    report.partial_count = 0
    report.failed_count = n_failed
    report.unverifiable_count = n_unverifiable
    report.overall_improvement_percent = 94.1
    report.summary = {"LLM01": n_verified, "LLM03": n_unverifiable}
    if n_failed:
        report.summary["LLM07"] = n_failed
    return report


# ---------------------------------------------------------------------------
# Tests: VerifierAgent construction and DI
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_default_construction_creates_orchestrator(self):
        agent = VerifierAgent()
        assert agent._orchestrator is not None

    def test_injected_orchestrator_is_used(self):
        mock_orch = MagicMock()
        agent = VerifierAgent(orchestrator=mock_orch)
        assert agent._orchestrator is mock_orch

    def test_default_mode_is_quick(self):
        agent = VerifierAgent()
        assert agent._default_mode == "quick"

    def test_custom_default_mode(self):
        agent = VerifierAgent(mode="full")
        assert agent._default_mode == "full"

    def test_quick_verifier_passed_when_no_orchestrator(self):
        mock_qv = MagicMock()
        agent = VerifierAgent(quick_verifier=mock_qv)
        # The orchestrator should have received the quick_verifier
        assert agent._orchestrator is not None


# ---------------------------------------------------------------------------
# Tests: verify() delegates to orchestrator
# ---------------------------------------------------------------------------


class TestVerify:
    def test_verify_calls_orchestrator_verify_all(self):
        mock_orch = MagicMock()
        mock_orch.verify_all.return_value = _make_report()
        agent = VerifierAgent(orchestrator=mock_orch)
        findings = [_make_remediation_result(_make_finding())]
        agent.verify(findings)
        mock_orch.verify_all.assert_called_once_with(findings, mode="quick")

    def test_verify_returns_report(self):
        mock_report = _make_report()
        mock_orch = MagicMock()
        mock_orch.verify_all.return_value = mock_report
        agent = VerifierAgent(orchestrator=mock_orch)
        result = agent.verify([_make_remediation_result(_make_finding())])
        assert result is mock_report

    def test_verify_passes_mode_override(self):
        mock_orch = MagicMock()
        mock_orch.verify_all.return_value = _make_report()
        agent = VerifierAgent(orchestrator=mock_orch, mode="quick")
        findings = [_make_remediation_result(_make_finding())]
        agent.verify(findings, mode="full")
        mock_orch.verify_all.assert_called_once_with(findings, mode="full")

    def test_verify_uses_default_mode_when_none_given(self):
        mock_orch = MagicMock()
        mock_orch.verify_all.return_value = _make_report()
        agent = VerifierAgent(orchestrator=mock_orch, mode="quick")
        agent.verify([])
        mock_orch.verify_all.assert_called_once_with([], mode="quick")

    def test_verify_empty_list_does_not_crash(self):
        mock_orch = MagicMock()
        mock_orch.verify_all.return_value = _make_report(0, 0, 0)
        agent = VerifierAgent(orchestrator=mock_orch)
        report = agent.verify([])
        assert report is not None


# ---------------------------------------------------------------------------
# Tests: ci_passed()
# ---------------------------------------------------------------------------


class TestCiGate:
    def test_ci_passed_true_when_no_failures(self):
        agent = VerifierAgent(orchestrator=MagicMock())
        report = _make_report(n_verified=3, n_failed=0, n_unverifiable=1)
        assert agent.ci_passed(report) is True

    def test_ci_passed_false_when_failures_exist(self):
        agent = VerifierAgent(orchestrator=MagicMock())
        report = _make_report(n_verified=2, n_failed=1, n_unverifiable=0)
        assert agent.ci_passed(report) is False

    def test_ci_passed_true_for_all_unverifiable(self):
        agent = VerifierAgent(orchestrator=MagicMock())
        report = _make_report(n_verified=0, n_failed=0, n_unverifiable=4)
        assert agent.ci_passed(report) is True

    def test_ci_passed_false_multiple_failures(self):
        agent = VerifierAgent(orchestrator=MagicMock())
        report = _make_report(n_verified=1, n_failed=3, n_unverifiable=0)
        assert agent.ci_passed(report) is False


# ---------------------------------------------------------------------------
# Tests: save_report() and load_report()
# ---------------------------------------------------------------------------


class TestSaveAndLoad:
    def test_save_report_writes_file(self):
        agent = VerifierAgent(orchestrator=MagicMock())
        report = _make_report()
        with tempfile.TemporaryDirectory() as tmp:
            path = agent.save_report(report, Path(tmp) / "benchmark.json")
            assert path.exists()

    def test_save_report_returns_path(self):
        agent = VerifierAgent(orchestrator=MagicMock())
        report = _make_report()
        with tempfile.TemporaryDirectory() as tmp:
            path = agent.save_report(report, Path(tmp) / "benchmark.json")
            assert isinstance(path, Path)

    def test_save_report_to_directory_appends_filename(self):
        agent = VerifierAgent(orchestrator=MagicMock())
        report = _make_report()
        with tempfile.TemporaryDirectory() as tmp:
            path = agent.save_report(report, tmp)
            assert path.name == "benchmark.json"
            assert path.exists()

    def test_save_report_valid_json(self):
        agent = VerifierAgent(orchestrator=MagicMock())
        report = _make_report(n_verified=1, n_failed=0, n_unverifiable=1)
        with tempfile.TemporaryDirectory() as tmp:
            path = agent.save_report(report, Path(tmp) / "b.json")
            data = json.loads(path.read_text())
            assert "total_findings" in data
            assert "ci_passed" in data
            assert "results" in data

    def test_load_report_returns_dict(self):
        agent = VerifierAgent(orchestrator=MagicMock())
        report = _make_report()
        with tempfile.TemporaryDirectory() as tmp:
            path = agent.save_report(report, Path(tmp) / "b.json")
            loaded = VerifierAgent.load_report(path)
            assert isinstance(loaded, dict)
            assert loaded["ci_passed"] is True

    def test_roundtrip_ci_failed(self):
        agent = VerifierAgent(orchestrator=MagicMock())
        report = _make_report(n_verified=1, n_failed=2, n_unverifiable=0)
        with tempfile.TemporaryDirectory() as tmp:
            path = agent.save_report(report, tmp)
            loaded = VerifierAgent.load_report(path)
            assert loaded["failed_count"] == 2
            assert loaded["ci_passed"] is False

    def test_save_creates_parent_dirs(self):
        agent = VerifierAgent(orchestrator=MagicMock())
        report = _make_report()
        with tempfile.TemporaryDirectory() as tmp:
            deep = Path(tmp) / "a" / "b" / "c" / "benchmark.json"
            path = agent.save_report(report, deep)
            assert path.exists()

    def test_load_report_accepts_string_path(self):
        agent = VerifierAgent(orchestrator=MagicMock())
        report = _make_report()
        with tempfile.TemporaryDirectory() as tmp:
            saved = agent.save_report(report, tmp)
            loaded = VerifierAgent.load_report(str(saved))
            assert "total_findings" in loaded


# ---------------------------------------------------------------------------
# Tests: serialisation helpers
# ---------------------------------------------------------------------------


class TestSerialisation:
    def test_report_to_dict_keys(self):
        report = _make_report(n_verified=2, n_failed=0, n_unverifiable=1)
        d = _report_to_dict(report)
        expected_keys = {
            "total_findings",
            "verified_count",
            "partial_count",
            "failed_count",
            "unverifiable_count",
            "overall_improvement_percent",
            "ci_passed",
            "summary",
            "results",
        }
        assert expected_keys.issubset(d.keys())

    def test_report_to_dict_ci_passed_flag_no_failures(self):
        report = _make_report(n_verified=3, n_failed=0)
        d = _report_to_dict(report)
        assert d["ci_passed"] is True

    def test_report_to_dict_ci_passed_flag_with_failures(self):
        report = _make_report(n_verified=1, n_failed=1)
        d = _report_to_dict(report)
        assert d["ci_passed"] is False

    def test_result_to_dict_keys(self):
        f = _make_finding()
        rr = _make_remediation_result(f)
        vr = _make_verification_result(rr)
        d = _result_to_dict(vr)
        assert "finding" in d
        assert "verification_status" in d
        assert "improvement_percent" in d
        assert "confidence" in d

    def test_result_to_dict_none_improvement(self):
        f = _make_finding(owasp="LLM03")
        rr = _make_remediation_result(f)
        vr = MagicMock()
        vr.remediation_result = rr
        vr.mode = "skipped"
        vr.verification_status = "UNVERIFIABLE"
        vr.before_success_rate = None
        vr.after_success_rate = None
        vr.improvement_percent = None
        vr.confidence = 0.0
        vr.notes = ["skipped"]
        d = _result_to_dict(vr)
        assert d["improvement_percent"] is None

    def test_result_to_dict_uses_to_dict_when_available(self):
        f = _make_finding()
        rr = _make_remediation_result(f)
        vr = _make_verification_result(rr)
        d = _result_to_dict(vr)
        f.to_dict.assert_called()
        assert d["finding"]["probe_name"] == f.probe_name

    def test_result_to_dict_fallback_without_to_dict(self):
        f = MagicMock(spec=[])  # spec=[] means no attributes defined
        f.probe_name = "probe.x"
        f.owasp_llm_category = "LLM02"
        f.severity = "MEDIUM"
        rr = _make_remediation_result(f)
        vr = _make_verification_result(rr)
        d = _result_to_dict(vr)
        assert d["finding"]["probe_name"] == "probe.x"

    def test_improvement_percent_rounded(self):
        f = _make_finding()
        rr = _make_remediation_result(f)
        vr = _make_verification_result(rr, before=0.85, after=0.05)
        d = _result_to_dict(vr)
        assert isinstance(d["improvement_percent"], float)
        assert abs(d["improvement_percent"] - round(vr.improvement_percent, 2)) < 0.001
