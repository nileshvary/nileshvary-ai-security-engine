"""Tests for ``ResponseRemediator`` PII/secret/XSS/SQLi/agent detection."""

from __future__ import annotations

import pytest

from remediation_engine.response_remediator.remediator import ResponseRemediator

from tests.remediation_engine.fixtures.sample_findings import (
    make_finding,
    malicious_response_pii,
    malicious_response_xss,
    tool_invocation_response,
)


@pytest.fixture
def remediator() -> ResponseRemediator:
    return ResponseRemediator()


class TestLLM02PiiAndSecrets:
    def test_ssn_redacted(self, remediator: ResponseRemediator) -> None:
        s = remediator.sanitize_response(
            make_finding("LLM02"), "SSN: 123-45-6789 here."
        )
        assert "[REDACTED-SSN]" in s.sanitized_response
        assert "123-45-6789" not in s.sanitized_response
        assert "SSN detected" in s.detected_issues

    def test_email_redacted(self, remediator: ResponseRemediator) -> None:
        s = remediator.sanitize_response(
            make_finding("LLM02"), "Email me at alice@example.com"
        )
        assert "[REDACTED-EMAIL]" in s.sanitized_response
        assert "alice@example.com" not in s.sanitized_response

    def test_aws_key_redacted(self, remediator: ResponseRemediator) -> None:
        s = remediator.sanitize_response(
            make_finding("LLM02"), "Key: AKIAIOSFODNN7EXAMPLE rotated."
        )
        assert "[REDACTED-AWS-KEY]" in s.sanitized_response
        assert "AKIAIOSFODNN7EXAMPLE" not in s.sanitized_response

    def test_combined_response_redacts_multiple(
        self, remediator: ResponseRemediator
    ) -> None:
        s = remediator.sanitize_response(
            make_finding("LLM02"), malicious_response_pii()
        )
        out = s.sanitized_response
        assert "123-45-6789" not in out
        assert "user@example.com" not in out
        assert "AKIAIOSFODNN7EXAMPLE" not in out
        assert len(s.detected_issues) >= 3
        assert len(s.actions_taken) >= 3

    def test_clean_response_no_changes(self, remediator: ResponseRemediator) -> None:
        clean = "Hello, here is some perfectly safe content."
        s = remediator.sanitize_response(make_finding("LLM02"), clean)
        assert s.sanitized_response == clean
        assert s.detected_issues == []
        assert s.actions_taken == []


class TestLLM05XssAndSqli:
    def test_script_tag_removed(self, remediator: ResponseRemediator) -> None:
        s = remediator.sanitize_response(
            make_finding("LLM05"), "<script>alert(1)</script>"
        )
        assert "<script>" not in s.sanitized_response
        assert "alert(1)" not in s.sanitized_response  # entire tag stripped
        assert any("XSS script tag" in i for i in s.detected_issues)

    def test_javascript_uri_removed(self, remediator: ResponseRemediator) -> None:
        s = remediator.sanitize_response(
            make_finding("LLM05"), "Click <a href=\"javascript:evil()\">here</a>"
        )
        assert "javascript:" not in s.sanitized_response

    def test_sqli_pattern_removed(self, remediator: ResponseRemediator) -> None:
        s = remediator.sanitize_response(
            make_finding("LLM05"), "Bad query: ' OR 1=1 --"
        )
        assert "[REMOVED-SQLI]" in s.sanitized_response

    def test_html_escaped_after_removal(
        self, remediator: ResponseRemediator
    ) -> None:
        s = remediator.sanitize_response(
            make_finding("LLM05"), "<div>safe content</div>"
        )
        # No XSS pattern matched, but html.escape still runs and escapes <>
        assert "&lt;div&gt;" in s.sanitized_response
        assert "<div>" not in s.sanitized_response

    def test_combined_response(self, remediator: ResponseRemediator) -> None:
        s = remediator.sanitize_response(
            make_finding("LLM05"), malicious_response_xss()
        )
        out = s.sanitized_response
        assert "<script>" not in out
        assert "javascript:" not in out
        assert "OR 1=1" not in out
        assert len(s.detected_issues) >= 2


class TestLLM06FlagOnly:
    def test_tool_invocation_flagged_not_modified(
        self, remediator: ResponseRemediator
    ) -> None:
        response = tool_invocation_response()
        s = remediator.sanitize_response(make_finding("LLM06"), response)
        assert s.sanitized_response == response  # unchanged
        assert len(s.detected_issues) >= 1
        assert any("tool call" in i or "execute" in i for i in s.detected_issues)

    def test_clean_response_no_flags(self, remediator: ResponseRemediator) -> None:
        s = remediator.sanitize_response(
            make_finding("LLM06"), "Hello, how can I help today?"
        )
        assert s.detected_issues == []
        assert s.actions_taken == []
        assert s.sanitized_response == "Hello, how can I help today?"


class TestUnhandledCategory:
    @pytest.mark.parametrize("code", ["LLM01", "LLM07", "LLM10"])
    def test_returns_noop(self, remediator: ResponseRemediator, code: str) -> None:
        original = "some response text"
        s = remediator.sanitize_response(make_finding(code), original)
        assert s.sanitized_response == original
        assert s.detected_issues == []
        assert s.actions_taken == []
