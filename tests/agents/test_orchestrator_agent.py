"""Tests for agents/orchestrator.py (Agent 5 — Orchestrator)."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, call

import pytest

# ---------------------------------------------------------------------------
# Path setup — ensure project root and src/ are on sys.path before importing
# ---------------------------------------------------------------------------
_ROOT = Path(__file__).parent.parent.parent
_SRC = _ROOT / "src"
for _p in (str(_ROOT), str(_SRC)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from agents.orchestrator import OrchestratorAgent, PipelineResult, _result_to_dict


# ---------------------------------------------------------------------------
# Helpers — build mock agents with all required return values set
# ---------------------------------------------------------------------------


def _make_finding(probe: str = "probe.LLM01", owasp: str = "LLM01") -> MagicMock:
    f = MagicMock()
    f.probe_name = probe
    f.owasp_llm_category = owasp
    f.severity = "HIGH"
    return f


def _make_remediation_result(finding: MagicMock | None = None) -> MagicMock:
    rr = MagicMock()
    rr.finding = finding or _make_finding()
    rr.strategy = "HARDEN"
    return rr


def _make_mock_report(
    verified: int = 2,
    partial: int = 0,
    failed: int = 0,
    unverifiable: int = 1,
    improvement: float = 87.5,
) -> MagicMock:
    r = MagicMock()
    r.verified_count = verified
    r.partial_count = partial
    r.failed_count = failed
    r.unverifiable_count = unverifiable
    r.overall_improvement_percent = improvement
    return r


def _make_mock_scanner(
    findings: list | None = None,
) -> MagicMock:
    m = MagicMock()
    m.scan.return_value = findings if findings is not None else [_make_finding()]
    m.save_findings.return_value = Path("/tmp/findings.json")
    return m


def _make_mock_remediator(
    results: list | None = None,
) -> MagicMock:
    m = MagicMock()
    m.remediate.return_value = results if results is not None else [_make_remediation_result()]
    m.save_results.return_value = Path("/tmp/remediation_results.json")
    return m


def _make_mock_reporter(html: str = "<html>report</html>") -> MagicMock:
    m = MagicMock()
    m.generate_report.return_value = html
    m.save_report.return_value = Path("/tmp/summary.html")
    return m


def _make_mock_verifier(
    verified: int = 2,
    partial: int = 0,
    failed: int = 0,
    unverifiable: int = 1,
    improvement: float = 87.5,
) -> MagicMock:
    report = _make_mock_report(verified, partial, failed, unverifiable, improvement)
    m = MagicMock()
    m.verify.return_value = report
    m.ci_passed.return_value = failed == 0
    m.save_report.return_value = Path("/tmp/benchmark.json")
    return m


def _make_agent(
    findings: list | None = None,
    results: list | None = None,
    html: str = "<html>report</html>",
    verified: int = 2,
    failed: int = 0,
) -> OrchestratorAgent:
    """Return an OrchestratorAgent with all four sub-agents mocked."""
    return OrchestratorAgent(
        scanner=_make_mock_scanner(findings),
        remediator=_make_mock_remediator(results),
        reporter=_make_mock_reporter(html),
        verifier=_make_mock_verifier(verified=verified, failed=failed),
    )


def _make_pipeline_result(
    target: str = "openai:gpt-4o",
    finding_count: int = 4,
    remediation_count: int = 4,
    verified_count: int = 2,
    partial_count: int = 1,
    failed_count: int = 0,
    unverifiable_count: int = 1,
    overall_improvement_percent: float = 87.5,
    ci_passed: bool = True,
    artifacts: dict | None = None,
) -> PipelineResult:
    return PipelineResult(
        target=target,
        finding_count=finding_count,
        remediation_count=remediation_count,
        verified_count=verified_count,
        partial_count=partial_count,
        failed_count=failed_count,
        unverifiable_count=unverifiable_count,
        overall_improvement_percent=overall_improvement_percent,
        ci_passed=ci_passed,
        artifacts=artifacts or {"findings": "/tmp/f.json"},
    )


# ---------------------------------------------------------------------------
# Tests: OrchestratorAgent construction and DI
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_injected_scanner_is_used(self):
        mock_scanner = _make_mock_scanner()
        agent = OrchestratorAgent(scanner=mock_scanner, remediator=MagicMock(),
                                   reporter=MagicMock(), verifier=MagicMock())
        assert agent._scanner is mock_scanner

    def test_injected_all_four_agents_stored(self):
        sc = _make_mock_scanner()
        rm = _make_mock_remediator()
        rp = _make_mock_reporter()
        vr = _make_mock_verifier()
        agent = OrchestratorAgent(scanner=sc, remediator=rm, reporter=rp, verifier=vr)
        assert agent._scanner is sc
        assert agent._remediator is rm
        assert agent._reporter is rp
        assert agent._verifier is vr

    def test_artifacts_dir_stored_as_path(self):
        agent = OrchestratorAgent(
            scanner=MagicMock(), remediator=MagicMock(),
            reporter=MagicMock(), verifier=MagicMock(),
            artifacts_dir="my_artifacts",
        )
        assert agent._artifacts_dir == Path("my_artifacts")

    def test_artifacts_dir_path_object_accepted(self):
        agent = OrchestratorAgent(
            scanner=MagicMock(), remediator=MagicMock(),
            reporter=MagicMock(), verifier=MagicMock(),
            artifacts_dir=Path("some/dir"),
        )
        assert agent._artifacts_dir == Path("some/dir")

    def test_default_artifacts_dir_is_artifacts(self):
        agent = OrchestratorAgent(
            scanner=MagicMock(), remediator=MagicMock(),
            reporter=MagicMock(), verifier=MagicMock(),
        )
        assert agent._artifacts_dir == Path("artifacts")


# ---------------------------------------------------------------------------
# Tests: run() delegates to each sub-agent in order
# ---------------------------------------------------------------------------


class TestRun:
    def test_run_calls_scanner_scan(self):
        scanner = _make_mock_scanner()
        agent = OrchestratorAgent(
            scanner=scanner,
            remediator=_make_mock_remediator(),
            reporter=_make_mock_reporter(),
            verifier=_make_mock_verifier(),
        )
        agent.run("target-x", save_artifacts=False)
        scanner.scan.assert_called_once()

    def test_run_calls_remediator_with_findings(self):
        findings = [_make_finding("p.LLM01"), _make_finding("p.LLM07")]
        scanner = _make_mock_scanner(findings)
        remediator = _make_mock_remediator()
        agent = OrchestratorAgent(
            scanner=scanner, remediator=remediator,
            reporter=_make_mock_reporter(), verifier=_make_mock_verifier(),
        )
        agent.run("t", save_artifacts=False)
        remediator.remediate.assert_called_once_with(findings, "")

    def test_run_calls_reporter_with_findings_and_results(self):
        findings = [_make_finding()]
        results = [_make_remediation_result()]
        scanner = _make_mock_scanner(findings)
        remediator = _make_mock_remediator(results)
        reporter = _make_mock_reporter()
        agent = OrchestratorAgent(
            scanner=scanner, remediator=remediator,
            reporter=reporter, verifier=_make_mock_verifier(),
        )
        agent.run("tgt", save_artifacts=False)
        reporter.generate_report.assert_called_once_with(findings, results, "tgt")

    def test_run_calls_verifier_with_results(self):
        results = [_make_remediation_result()]
        remediator = _make_mock_remediator(results)
        verifier = _make_mock_verifier()
        agent = OrchestratorAgent(
            scanner=_make_mock_scanner(), remediator=remediator,
            reporter=_make_mock_reporter(), verifier=verifier,
        )
        agent.run("t", save_artifacts=False)
        verifier.verify.assert_called_once_with(results)

    def test_run_returns_pipeline_result(self):
        agent = _make_agent()
        result = agent.run("openai:gpt-4o", save_artifacts=False)
        assert isinstance(result, PipelineResult)

    def test_run_save_artifacts_false_skips_file_writes(self):
        scanner = _make_mock_scanner()
        remediator = _make_mock_remediator()
        reporter = _make_mock_reporter()
        verifier = _make_mock_verifier()
        agent = OrchestratorAgent(
            scanner=scanner, remediator=remediator,
            reporter=reporter, verifier=verifier,
        )
        result = agent.run("t", save_artifacts=False)
        scanner.save_findings.assert_not_called()
        remediator.save_results.assert_not_called()
        reporter.save_report.assert_not_called()
        verifier.save_report.assert_not_called()
        assert result.artifacts == {}

    def test_run_empty_findings_does_not_crash(self):
        agent = OrchestratorAgent(
            scanner=_make_mock_scanner([]),
            remediator=_make_mock_remediator([]),
            reporter=_make_mock_reporter(),
            verifier=_make_mock_verifier(verified=0, unverifiable=0),
        )
        result = agent.run("t", save_artifacts=False)
        assert result.finding_count == 0
        assert result.remediation_count == 0

    def test_run_system_prompt_forwarded_to_remediator(self):
        scanner = _make_mock_scanner([_make_finding()])
        remediator = _make_mock_remediator()
        agent = OrchestratorAgent(
            scanner=scanner, remediator=remediator,
            reporter=_make_mock_reporter(), verifier=_make_mock_verifier(),
        )
        agent.run("t", system_prompt="You are a helpful AI.", save_artifacts=False)
        remediator.remediate.assert_called_once_with(
            scanner.scan.return_value,
            "You are a helpful AI.",
        )


# ---------------------------------------------------------------------------
# Tests: ci_passed()
# ---------------------------------------------------------------------------


class TestCiGate:
    def test_ci_passed_true_when_failed_zero(self):
        agent = _make_agent(failed=0)
        result = agent.run("t", save_artifacts=False)
        assert agent.ci_passed(result) is True

    def test_ci_passed_false_when_failed_nonzero(self):
        agent = _make_agent(failed=1)
        result = agent.run("t", save_artifacts=False)
        assert agent.ci_passed(result) is False

    def test_ci_passed_delegates_to_pipeline_result(self):
        pr_pass = _make_pipeline_result(ci_passed=True)
        pr_fail = _make_pipeline_result(ci_passed=False)
        agent = _make_agent()
        assert agent.ci_passed(pr_pass) is True
        assert agent.ci_passed(pr_fail) is False

    def test_ci_passed_consistent_with_failed_count(self):
        agent = _make_agent()
        pr = _make_pipeline_result(failed_count=0, ci_passed=True)
        assert agent.ci_passed(pr) == (pr.failed_count == 0)


# ---------------------------------------------------------------------------
# Tests: save_pipeline_result() and load_pipeline_result()
# ---------------------------------------------------------------------------


class TestSaveAndLoad:
    def test_save_pipeline_result_writes_file(self):
        agent = _make_agent()
        pr = _make_pipeline_result()
        with tempfile.TemporaryDirectory() as tmp:
            path = agent.save_pipeline_result(pr, Path(tmp) / "ps.json")
            assert path.exists()

    def test_save_pipeline_result_returns_path(self):
        agent = _make_agent()
        pr = _make_pipeline_result()
        with tempfile.TemporaryDirectory() as tmp:
            path = agent.save_pipeline_result(pr, Path(tmp) / "ps.json")
            assert isinstance(path, Path)

    def test_save_to_directory_appends_filename(self):
        agent = _make_agent()
        pr = _make_pipeline_result()
        with tempfile.TemporaryDirectory() as tmp:
            path = agent.save_pipeline_result(pr, tmp)
            assert path.name == "pipeline_summary.json"
            assert path.exists()

    def test_save_produces_valid_json(self):
        agent = _make_agent()
        pr = _make_pipeline_result()
        with tempfile.TemporaryDirectory() as tmp:
            path = agent.save_pipeline_result(pr, Path(tmp) / "ps.json")
            data = json.loads(path.read_text())
            assert "ci_passed" in data
            assert "finding_count" in data
            assert "artifacts" in data

    def test_load_returns_dict(self):
        agent = _make_agent()
        pr = _make_pipeline_result()
        with tempfile.TemporaryDirectory() as tmp:
            path = agent.save_pipeline_result(pr, tmp)
            loaded = OrchestratorAgent.load_pipeline_result(path)
            assert isinstance(loaded, dict)
            assert loaded["ci_passed"] is True

    def test_roundtrip_ci_failed(self):
        agent = _make_agent()
        pr = _make_pipeline_result(failed_count=2, ci_passed=False)
        with tempfile.TemporaryDirectory() as tmp:
            path = agent.save_pipeline_result(pr, tmp)
            loaded = OrchestratorAgent.load_pipeline_result(path)
            assert loaded["failed_count"] == 2
            assert loaded["ci_passed"] is False

    def test_save_creates_parent_directories(self):
        agent = _make_agent()
        pr = _make_pipeline_result()
        with tempfile.TemporaryDirectory() as tmp:
            deep = Path(tmp) / "a" / "b" / "c" / "ps.json"
            path = agent.save_pipeline_result(pr, deep)
            assert path.exists()


# ---------------------------------------------------------------------------
# Tests: _result_to_dict serialisation helper
# ---------------------------------------------------------------------------


class TestSerialization:
    def test_result_to_dict_has_all_keys(self):
        pr = _make_pipeline_result()
        d = _result_to_dict(pr)
        expected = {
            "target", "finding_count", "remediation_count",
            "verified_count", "partial_count", "failed_count",
            "unverifiable_count", "overall_improvement_percent",
            "ci_passed", "artifacts",
        }
        assert expected.issubset(d.keys())

    def test_result_to_dict_ci_passed_present(self):
        pr = _make_pipeline_result(ci_passed=True)
        d = _result_to_dict(pr)
        assert d["ci_passed"] is True

    def test_result_to_dict_finding_count_matches(self):
        pr = _make_pipeline_result(finding_count=7)
        d = _result_to_dict(pr)
        assert d["finding_count"] == 7

    def test_result_to_dict_artifacts_dict_included(self):
        pr = _make_pipeline_result(artifacts={"findings": "/tmp/f.json"})
        d = _result_to_dict(pr)
        assert isinstance(d["artifacts"], dict)
        assert "findings" in d["artifacts"]

    def test_result_to_dict_improvement_percent_is_float(self):
        pr = _make_pipeline_result(overall_improvement_percent=72.3)
        d = _result_to_dict(pr)
        assert isinstance(d["overall_improvement_percent"], float)

    def test_result_to_dict_no_nested_dataclasses(self):
        pr = _make_pipeline_result()
        d = _result_to_dict(pr)
        # All values should be JSON-native: str, int, float, bool, dict
        for v in d.values():
            assert isinstance(v, (str, int, float, bool, dict)), (
                f"Non-JSON-native value for key: {v!r}"
            )
