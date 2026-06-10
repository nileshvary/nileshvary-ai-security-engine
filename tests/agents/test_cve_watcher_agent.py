"""Tests for agents/cve_watcher.py (Agent 6 — CVE Watcher)."""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

# ---------------------------------------------------------------------------
# Path setup
# ---------------------------------------------------------------------------
_ROOT = Path(__file__).parent.parent.parent
_SRC = _ROOT / "src"
for _p in (str(_ROOT), str(_SRC)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from datetime import datetime, timezone

from agents.cve_watcher import (
    CveEntry,
    CveWatcherAgent,
    TargetConfig,
    WatchResult,
    _entry_to_dict,
    _map_severity,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_nvd_response(vulnerabilities: list[dict] | None = None) -> MagicMock:
    """Build a mock requests.Response shaped like the NVD REST API 2.0."""
    resp = MagicMock()
    resp.raise_for_status.return_value = None
    resp.json.return_value = {"vulnerabilities": vulnerabilities or []}
    return resp


def _today_iso() -> str:
    """Return today's UTC datetime as an NVD-format string."""
    return datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def _nvd_vuln(
    cve_id: str = "CVE-2024-12345",
    description: str = "A prompt injection vulnerability in an LLM chatbot.",
    cvss_score: float = 7.5,
    published: str | None = None,
) -> dict:
    if published is None:
        published = _today_iso()
    """Build a single NVD vulnerability dict."""
    return {
        "cve": {
            "id": cve_id,
            "published": published,
            "descriptions": [{"lang": "en", "value": description}],
            "metrics": {
                "cvssMetricV31": [
                    {"cvssData": {"baseScore": cvss_score}}
                ]
            },
        }
    }


def _make_entry(
    cve_id: str = "CVE-2024-99999",
    owasp: str = "LLM01",
    severity: str = "HIGH",
    description: str = "A prompt injection flaw.",
) -> CveEntry:
    return CveEntry(
        cve_id=cve_id,
        source="nvd",
        published_date="2024-09-10T00:00:00.000",
        description=description,
        owasp_category=owasp,
        severity=severity,
        probe_generated=False,
    )


def _make_mock_scanner(findings: list | None = None) -> MagicMock:
    m = MagicMock()
    m.scan.return_value = findings or []
    return m


def _make_agent_with_nvd(
    vulns: list[dict] | None = None,
    scanner: MagicMock | None = None,
) -> tuple[CveWatcherAgent, MagicMock]:
    """Return a CveWatcherAgent and its mock nvd_client."""
    nvd_client = MagicMock()
    nvd_client.get.return_value = _make_nvd_response(vulns)
    agent = CveWatcherAgent(
        scanner=scanner,
        nvd_client=nvd_client,
        github_client=MagicMock(),
    )
    return agent, nvd_client


# ---------------------------------------------------------------------------
# Tests: construction and DI
# ---------------------------------------------------------------------------


class TestConstruction:
    def test_injected_nvd_client_is_stored(self):
        mock_client = MagicMock()
        agent = CveWatcherAgent(nvd_client=mock_client)
        assert agent._nvd_client is mock_client

    def test_injected_scanner_is_stored(self):
        scanner = _make_mock_scanner()
        agent = CveWatcherAgent(scanner=scanner, nvd_client=MagicMock())
        assert agent._scanner is scanner

    def test_scanner_is_optional(self):
        agent = CveWatcherAgent(nvd_client=MagicMock())
        assert agent._scanner is None

    def test_artifacts_dir_stored_as_path(self):
        agent = CveWatcherAgent(nvd_client=MagicMock(), artifacts_dir="my_dir")
        assert agent._artifacts_dir == Path("my_dir")

    def test_nvd_api_key_from_explicit_arg(self):
        agent = CveWatcherAgent(nvd_client=MagicMock(), nvd_api_key="test-key")
        assert agent._nvd_api_key == "test-key"


# ---------------------------------------------------------------------------
# Tests: fetch_new_cves()
# ---------------------------------------------------------------------------


class TestFetchNewCves:
    def test_calls_nvd_client_get(self):
        agent, nvd_client = _make_agent_with_nvd([
            _nvd_vuln("CVE-2024-00001", "prompt injection in LLM")
        ])
        agent.fetch_new_cves(days_back=1)
        nvd_client.get.assert_called_once()

    def test_returns_list_of_cve_entries(self):
        agent, _ = _make_agent_with_nvd([
            _nvd_vuln("CVE-2024-00001", "LLM prompt injection flaw")
        ])
        entries = agent.fetch_new_cves()
        assert isinstance(entries, list)
        assert len(entries) == 1
        assert isinstance(entries[0], CveEntry)

    def test_keyword_filter_excludes_non_llm_cves(self):
        agent, _ = _make_agent_with_nvd([
            _nvd_vuln("CVE-2024-00001", "SQL injection in web application database"),
            _nvd_vuln("CVE-2024-00002", "Buffer overflow in kernel driver"),
        ])
        entries = agent.fetch_new_cves()
        assert len(entries) == 0

    def test_keyword_filter_keeps_llm_cves(self):
        agent, _ = _make_agent_with_nvd([
            _nvd_vuln("CVE-2024-00001", "Prompt injection in LLM chatbot allows bypass"),
            _nvd_vuln("CVE-2024-00002", "SQL injection unrelated"),
        ])
        entries = agent.fetch_new_cves()
        assert len(entries) == 1
        assert entries[0].cve_id == "CVE-2024-00001"

    def test_api_error_returns_empty_list(self):
        nvd_client = MagicMock()
        nvd_client.get.side_effect = Exception("Connection refused")
        agent = CveWatcherAgent(nvd_client=nvd_client)
        entries = agent.fetch_new_cves()
        assert entries == []

    def test_dedup_by_cve_id(self):
        agent, _ = _make_agent_with_nvd([
            _nvd_vuln("CVE-2024-99999", "LLM prompt injection flaw"),
            _nvd_vuln("CVE-2024-99999", "LLM prompt injection flaw duplicate"),
        ])
        entries = agent.fetch_new_cves()
        assert len(entries) == 1
        assert entries[0].cve_id == "CVE-2024-99999"

    def test_empty_nvd_response_returns_empty_list(self):
        agent, _ = _make_agent_with_nvd([])
        entries = agent.fetch_new_cves()
        assert entries == []

    def test_severity_mapped_from_cvss(self):
        agent, _ = _make_agent_with_nvd([
            _nvd_vuln("CVE-2024-00001", "LLM prompt injection", cvss_score=9.5)
        ])
        entries = agent.fetch_new_cves()
        assert entries[0].severity == "CRITICAL"


# ---------------------------------------------------------------------------
# Tests: _map_to_owasp() keyword routing
# ---------------------------------------------------------------------------


class TestCveMapping:
    def setup_method(self):
        self.agent = CveWatcherAgent(nvd_client=MagicMock())

    def test_prompt_injection_maps_to_llm01(self):
        assert self.agent._map_to_owasp("Prompt injection attack on LLM") == "LLM01"

    def test_jailbreak_maps_to_llm01(self):
        assert self.agent._map_to_owasp("jailbreak technique bypasses safety") == "LLM01"

    def test_system_prompt_maps_to_llm07(self):
        assert self.agent._map_to_owasp("system prompt disclosure vulnerability") == "LLM07"

    def test_denial_of_service_maps_to_llm10(self):
        assert self.agent._map_to_owasp("denial of service via resource exhaustion") == "LLM10"

    def test_no_keyword_returns_unknown(self):
        assert self.agent._map_to_owasp("unrelated software vulnerability") == "UNKNOWN"

    def test_case_insensitive_match(self):
        assert self.agent._map_to_owasp("PROMPT INJECTION IN LANGUAGE MODEL") == "LLM01"


# ---------------------------------------------------------------------------
# Tests: watch_and_rescan()
# ---------------------------------------------------------------------------


class TestWatchAndRescan:
    def test_auto_rescan_false_skips_scanner(self):
        scanner = _make_mock_scanner()
        agent, _ = _make_agent_with_nvd(
            [_nvd_vuln("CVE-2024-00001", "LLM prompt injection flaw")],
            scanner=scanner,
        )
        agent.watch_and_rescan(auto_rescan=False)
        scanner.scan.assert_not_called()

    def test_auto_rescan_true_calls_scanner(self):
        scanner = _make_mock_scanner([MagicMock()])
        agent, _ = _make_agent_with_nvd(
            [_nvd_vuln("CVE-2024-00001", "LLM prompt injection flaw")],
            scanner=scanner,
        )
        with tempfile.TemporaryDirectory() as tmp:
            agent._artifacts_dir = Path(tmp)
            agent.watch_and_rescan(auto_rescan=True)
        scanner.scan.assert_called_once()

    def test_new_probes_forwarded_to_scanner(self):
        scanner = _make_mock_scanner()
        agent, _ = _make_agent_with_nvd(
            [_nvd_vuln("CVE-2024-00001", "LLM prompt injection flaw")],
            scanner=scanner,
        )
        with tempfile.TemporaryDirectory() as tmp:
            agent._artifacts_dir = Path(tmp)
            agent.watch_and_rescan(auto_rescan=True)
        call_kwargs = scanner.scan.call_args
        assert "pyrit_probes" in call_kwargs.kwargs or len(call_kwargs.args) > 0

    def test_returns_watch_result(self):
        agent, _ = _make_agent_with_nvd(
            [_nvd_vuln("CVE-2024-00001", "LLM prompt injection flaw")]
        )
        with tempfile.TemporaryDirectory() as tmp:
            agent._artifacts_dir = Path(tmp)
            result = agent.watch_and_rescan()
        assert isinstance(result, WatchResult)

    def test_rescan_finding_count_zero_when_no_rescan(self):
        agent, _ = _make_agent_with_nvd(
            [_nvd_vuln("CVE-2024-00001", "LLM prompt injection flaw")]
        )
        with tempfile.TemporaryDirectory() as tmp:
            agent._artifacts_dir = Path(tmp)
            result = agent.watch_and_rescan(auto_rescan=False)
        assert result.rescan_finding_count == 0

    def test_saves_cve_database_when_cves_found(self):
        agent, _ = _make_agent_with_nvd(
            [_nvd_vuln("CVE-2024-00001", "LLM prompt injection flaw")]
        )
        with tempfile.TemporaryDirectory() as tmp:
            agent._artifacts_dir = Path(tmp)
            result = agent.watch_and_rescan()
        assert "cve_database" in result.artifacts

    def test_empty_cves_returns_empty_watch_result(self):
        agent, _ = _make_agent_with_nvd([])
        result = agent.watch_and_rescan()
        assert result.new_cve_count == 0
        assert result.new_probe_count == 0
        assert result.cve_ids == []

    def test_scanner_called_with_probe_list(self):
        scanner = _make_mock_scanner()
        agent, _ = _make_agent_with_nvd(
            [_nvd_vuln("CVE-2024-00001", "LLM prompt injection flaw")],
            scanner=scanner,
        )
        with tempfile.TemporaryDirectory() as tmp:
            agent._artifacts_dir = Path(tmp)
            agent.watch_and_rescan(auto_rescan=True)
        args, kwargs = scanner.scan.call_args
        probes = kwargs.get("pyrit_probes") or (args[0] if args else None)
        assert isinstance(probes, list)

    def test_watch_result_new_cve_count_correct(self):
        agent, _ = _make_agent_with_nvd([
            _nvd_vuln("CVE-2024-00001", "LLM prompt injection flaw"),
            _nvd_vuln("CVE-2024-00002", "AI language model jailbreak attack"),
        ])
        with tempfile.TemporaryDirectory() as tmp:
            agent._artifacts_dir = Path(tmp)
            result = agent.watch_and_rescan()
        assert result.new_cve_count == 2


# ---------------------------------------------------------------------------
# Tests: save_cve_database() and load_cve_database()
# ---------------------------------------------------------------------------


class TestSaveAndLoad:
    def test_save_cve_database_writes_file(self):
        agent = CveWatcherAgent(nvd_client=MagicMock())
        entries = [_make_entry()]
        with tempfile.TemporaryDirectory() as tmp:
            path = agent.save_cve_database(entries, Path(tmp) / "cve_database.json")
            assert path.exists()

    def test_save_returns_path(self):
        agent = CveWatcherAgent(nvd_client=MagicMock())
        entries = [_make_entry()]
        with tempfile.TemporaryDirectory() as tmp:
            path = agent.save_cve_database(entries, tmp)
            assert isinstance(path, Path)

    def test_save_to_directory_appends_filename(self):
        agent = CveWatcherAgent(nvd_client=MagicMock())
        entries = [_make_entry()]
        with tempfile.TemporaryDirectory() as tmp:
            path = agent.save_cve_database(entries, tmp)
            assert path.name == "cve_database.json"
            assert path.exists()

    def test_save_produces_valid_json(self):
        agent = CveWatcherAgent(nvd_client=MagicMock())
        entries = [_make_entry()]
        with tempfile.TemporaryDirectory() as tmp:
            path = agent.save_cve_database(entries, tmp)
            data = json.loads(path.read_text())
            assert isinstance(data, list)
            assert data[0]["cve_id"] == "CVE-2024-99999"

    def test_load_returns_list_of_dicts(self):
        agent = CveWatcherAgent(nvd_client=MagicMock())
        entries = [_make_entry()]
        with tempfile.TemporaryDirectory() as tmp:
            path = agent.save_cve_database(entries, tmp)
            loaded = CveWatcherAgent.load_cve_database(path)
            assert isinstance(loaded, list)
            assert loaded[0]["owasp_category"] == "LLM01"

    def test_merge_dedup_existing_entries(self):
        agent = CveWatcherAgent(nvd_client=MagicMock())
        entry_a = _make_entry("CVE-2024-00001")
        entry_b = _make_entry("CVE-2024-00002")
        with tempfile.TemporaryDirectory() as tmp:
            agent.save_cve_database([entry_a], tmp)
            agent.save_cve_database([entry_a, entry_b], tmp)  # entry_a is duplicate
            loaded = CveWatcherAgent.load_cve_database(Path(tmp) / "cve_database.json")
            ids = [e["cve_id"] for e in loaded]
            assert ids.count("CVE-2024-00001") == 1
            assert "CVE-2024-00002" in ids

    def test_save_creates_parent_directories(self):
        agent = CveWatcherAgent(nvd_client=MagicMock())
        entries = [_make_entry()]
        with tempfile.TemporaryDirectory() as tmp:
            deep = Path(tmp) / "a" / "b" / "c" / "cve_database.json"
            path = agent.save_cve_database(entries, deep)
            assert path.exists()


# ---------------------------------------------------------------------------
# Tests: TargetConfig.from_string()
# ---------------------------------------------------------------------------


class TestTargetConfig:
    def test_parse_openai_target(self):
        tc = TargetConfig.from_string("openai:gpt-4o")
        assert tc.provider == "openai"
        assert tc.model == "gpt-4o"
        assert tc.api_key_env == "OPENAI_API_KEY"

    def test_parse_anthropic_target(self):
        tc = TargetConfig.from_string("anthropic:claude-opus-4-8")
        assert tc.provider == "anthropic"
        assert tc.model == "claude-opus-4-8"
        assert tc.api_key_env == "ANTHROPIC_API_KEY"

    def test_parse_http_url_target(self):
        tc = TargetConfig.from_string("https://my-app.com/chat")
        assert tc.provider == "custom_http"
        assert tc.endpoint_url == "https://my-app.com/chat"
        assert tc.api_key_env == ""

    def test_parse_localhost_target(self):
        tc = TargetConfig.from_string("http://localhost:8080")
        assert tc.provider == "custom_http"
        assert tc.endpoint_url == "http://localhost:8080"

    def test_unknown_provider_has_empty_api_key_env(self):
        tc = TargetConfig.from_string("myvendor:my-model")
        assert tc.provider == "myvendor"
        assert tc.api_key_env == ""
