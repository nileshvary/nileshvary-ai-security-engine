"""Sample Finding factories for remediation engine tests.

Python factories (not JSONL) because Finding is a frozen dataclass and
the tests benefit from explicit, typed inputs.
"""

from __future__ import annotations

from typing import Any

from integration_bridge.models import Finding


_DEFAULT_AGENTIC: dict[str, list[str]] = {
    "LLM01": ["ASI01"],
    "LLM02": [],
    "LLM03": ["ASI04"],
    "LLM04": ["ASI06"],
    "LLM05": ["ASI05"],
    "LLM06": ["ASI03"],
    "LLM07": ["ASI01", "ASI03"],
    "LLM08": ["ASI06"],
    "LLM09": ["ASI09"],
    "LLM10": ["ASI08"],
}


def make_finding(
    llm_code: str,
    severity: str = "HIGH",
    **overrides: Any,
) -> Finding:
    """Build a Finding with sensible defaults; ``overrides`` replace fields."""
    defaults: dict[str, Any] = {
        "probe_name": f"sample.{llm_code}",
        "detector_name": "sample.detector",
        "attack_prompt": f"sample attack prompt for {llm_code}",
        "model_response": f"sample model response for {llm_code}",
        "is_successful_attack": True,
        "owasp_llm_category": llm_code,
        "owasp_agentic_categories": list(_DEFAULT_AGENTIC.get(llm_code, [])),
        "severity": severity,
        "raw_data": {"probe": f"sample.{llm_code}", "score": 1.0},
    }
    defaults.update(overrides)
    return Finding(**defaults)


def all_category_findings() -> list[Finding]:
    """Return exactly 10 findings, one per LLM01..LLM10."""
    return [make_finding(f"LLM{i:02d}") for i in range(1, 11)]


def out_of_band_findings() -> list[Finding]:
    """Return the four out-of-band findings (LLM03, LLM04, LLM08, LLM09)."""
    return [make_finding(code) for code in ("LLM03", "LLM04", "LLM08", "LLM09")]


def malicious_response_pii() -> str:
    """A response embedding several PII / secret items for redaction tests."""
    return (
        "Customer SSN is 123-45-6789, email user@example.com, "
        "and AWS key AKIAIOSFODNN7EXAMPLE was leaked. "
        "Call them at (555) 123-4567 to confirm."
    )


def malicious_response_xss() -> str:
    """A response embedding XSS + SQLi vectors for sanitization tests."""
    return (
        "Here is a snippet: <script>alert('xss')</script>. "
        "Click <a href=\"javascript:steal()\">here</a> or use onclick=\"evil()\". "
        "Try the query: ' OR 1=1 --"
    )


def tool_invocation_response() -> str:
    """A response that looks like an autonomous agent invoking a tool."""
    return "I will now execute: rm -rf /. Calling tool: shell_exec with the above command."
