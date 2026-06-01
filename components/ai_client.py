"""Thin Claude wrapper for RemediAX's optional AI-enhanced explanations.

Every public method returns ``None`` when the underlying API call fails,
so callers can fall back to the pre-written ``OWASP_CONTENT`` strings
without crashing the UI.
"""

from __future__ import annotations

import logging

from integration_bridge.models import Finding
from remediation_engine.models import RemediationResult

logger = logging.getLogger(__name__)


_MODEL = "claude-haiku-4-5-20251001"
_MAX_TOKENS = 150
_TEMPERATURE = 0.3


class RemediAXAI:
    """Best-effort Claude wrapper. All methods are ``str | None``."""

    def __init__(self, api_key: str) -> None:
        """Build a client bound to a user-supplied API key.

        Args:
            api_key: The user's Anthropic API key. Never logged. The
                key is stored only on this instance — caller controls
                its lifetime via Streamlit session state.
        """
        import anthropic  # local import keeps cold-start cheap when AI mode is off

        self.client = anthropic.Anthropic(api_key=api_key)
        self.model = _MODEL
        self.max_tokens = _MAX_TOKENS
        self.temperature = _TEMPERATURE

    def explain_finding(self, finding: Finding) -> str | None:
        """Return a 3-sentence danger explanation, or ``None`` on failure."""
        prompt = (
            "You are a security expert.\n"
            "Explain this LLM vulnerability in 3 sentences.\n"
            f"Category: {finding.owasp_llm_category}\n"
            f"Severity: {finding.severity}\n"
            f"Attack: {finding.attack_prompt[:200]}\n"
            f"Response: {finding.model_response[:200]}\n"
            "Why is this dangerous? Be direct."
        )
        return self._call(prompt)

    def explain_fix(self, result: RemediationResult) -> str | None:
        """Return a 2-sentence fix explanation, or ``None`` on failure."""
        notes_str = " | ".join(result.notes)[:300]
        prompt = (
            "You are a security expert.\n"
            "Explain why this fix works in 2 sentences.\n"
            f"Strategy: {result.strategy}\n"
            f"Notes: {notes_str}\n"
            "Be practical and clear."
        )
        return self._call(prompt)

    def summarize_scan(self, findings: list[Finding]) -> str | None:
        """Return a 2-sentence scan-level summary for the security team."""
        counts: dict[str, int] = {}
        for finding in findings:
            counts[finding.owasp_llm_category] = (
                counts.get(finding.owasp_llm_category, 0) + 1
            )
        prompt = (
            f"Security scan found: {counts}\n"
            "Summarize in 2 sentences for a security team.\n"
            "Be direct and actionable."
        )
        return self._call(prompt)

    def summarize_decisions(self, approved: int, skipped: int) -> str | None:
        """Return a 2-sentence security-posture summary after review."""
        prompt = (
            f"Security review: {approved} patches approved, "
            f"{skipped} findings skipped.\n"
            "Give a 2-sentence security posture assessment."
        )
        return self._call(prompt)

    def _call(self, prompt: str) -> str | None:
        """Run a single one-shot Claude call. Returns ``None`` on any error."""
        try:
            msg = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                temperature=self.temperature,
                messages=[{"role": "user", "content": prompt}],
            )
            return msg.content[0].text
        except Exception as exc:
            logger.warning("Claude call failed; falling back to basic mode: %s", exc)
            return None
