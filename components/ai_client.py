"""Thin Claude wrapper for RemediAX's optional AI-enhanced explanations.

Every public method returns ``None`` when the underlying API call fails,
so callers can fall back to the pre-written ``OWASP_CONTENT`` strings
without crashing the UI.

The prompts are deliberately attack-specific — they pass the actual
attack prompt, the model response, AND the resolved OWASP category
(by code AND human name) so Claude can produce per-finding rather than
per-category boilerplate. Each method narrows Claude's task to one
concrete output (danger explanation, fix justification, guardrail
pattern, severity assessment) so responses stay short and on-topic.
"""

from __future__ import annotations

import logging

from integration_bridge.models import Finding
from integration_bridge.owasp_taxonomy import AGENTIC_TOP_10, LLM_TOP_10
from remediation_engine.models import RemediationResult, RemediationStrategy

logger = logging.getLogger(__name__)


_MODEL = "claude-haiku-4-5-20251001"
_MAX_TOKENS = 400
_TEMPERATURE = 0.3
# Per-attack context excerpts. Generous enough that Claude can read
# the actual exploit instead of pattern-matching off the category
# name, but bounded so token usage stays predictable.
_PROMPT_EXCERPT_CHARS = 500
_RESPONSE_EXCERPT_CHARS = 500


def _owasp_category_name(code: str) -> str:
    """Return the human-readable OWASP category name for ``code``.

    Falls back to the bare code (``"LLM07"``) when the code isn't
    present in the taxonomy — defensive only, since the parser
    already validates against ``VALID_LLM_CATEGORIES``.
    """
    entry = LLM_TOP_10.get(code)
    if entry is None:
        return code
    return f"{code} ({entry.name})"


def _agentic_category_names(codes: list[str]) -> str:
    """Format an ASI code list as ``"ASI02 (Tool Misuse...), ASI10 (Rogue Agents)"``.

    Returns the literal ``"(none)"`` when the list is empty so the
    prompt context stays readable instead of trailing into a blank.
    """
    if not codes:
        return "(none)"
    parts: list[str] = []
    for code in codes:
        entry = AGENTIC_TOP_10.get(code)
        if entry is None:
            parts.append(code)
        else:
            parts.append(f"{code} ({entry.name})")
    return ", ".join(parts)


# Pre-rendered reference tables shared across prompts so Claude has
# the full OWASP vocabulary (LLM Top 10 + Agentic Top 10) in scope.
# Computed once at import time — both dicts are immutable taxonomy
# constants, so this is safe.
def _build_taxonomy_index() -> str:
    llm_lines = [
        f"  {code} = {entry.name}" for code, entry in LLM_TOP_10.items()
    ]
    asi_lines = [
        f"  {code} = {entry.name}" for code, entry in AGENTIC_TOP_10.items()
    ]
    return (
        "OWASP TAXONOMY REFERENCE (use these exact codes and names):\n"
        "LLM Top 10:\n"
        + "\n".join(llm_lines)
        + "\n"
        "Agentic Top 10:\n"
        + "\n".join(asi_lines)
    )


_TAXONOMY_INDEX: str = _build_taxonomy_index()


def _attack_context_block(finding: Finding) -> str:
    """Format the per-attack context block shared across every prompt.

    Always includes both the LLM Top 10 and Agentic Top 10 attributions
    so Claude can produce accurate per-finding analysis using the right
    category names instead of guessing.
    """
    return (
        f"OWASP LLM Category: {_owasp_category_name(finding.owasp_llm_category)}\n"
        f"OWASP Agentic Categories: "
        f"{_agentic_category_names(list(finding.owasp_agentic_categories))}\n"
        f"Severity (parser estimate): {finding.severity}\n"
        f"Probe: {finding.probe_name}\n"
        f"Detector: {finding.detector_name}\n"
        f"Attack prompt:\n{finding.attack_prompt[:_PROMPT_EXCERPT_CHARS]}\n"
        f"Model response:\n{finding.model_response[:_RESPONSE_EXCERPT_CHARS]}"
    )


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
        """Why is THIS specific attack dangerous? 3 sentences, or ``None`` on failure.

        Anchors Claude in the actual prompt / response / OWASP
        category so the answer is concrete to the incident rather than
        a re-statement of the category description.
        """
        prompt = (
            f"{_TAXONOMY_INDEX}\n\n"
            "You are an LLM security expert reviewing a specific "
            "incident from a garak scan.\n\n"
            f"{_attack_context_block(finding)}\n\n"
            "In 3 short sentences, explain why THIS specific attack "
            "on THIS specific response is dangerous. Be concrete — "
            "reference the actual content, not generic category "
            "boilerplate."
        )
        return self._call(prompt)

    def explain_fix(
        self,
        result: RemediationResult,
        finding: Finding | None = None,
    ) -> str | None:
        """Why does this fix work for THIS attack? 2-3 sentences, or ``None``.

        Two branches:

        * **LOG_ONLY strategy** — there is no runtime patch to
          explain (the vulnerability lives in an external system the
          remediator can't touch), so asking Claude "why does this
          fix work" makes it ask clarifying questions. Instead, the
          prompt asks Claude to recommend guardrails the system owner
          should implement against this specific attack pattern.
        * **All other strategies** — explain why the generated patch
          blocks the specific attack.

        Backward-compatible: callers that only have the
        ``RemediationResult`` (no finding) still get a response, just
        without the per-attack context.
        """
        if result.strategy == RemediationStrategy.LOG_ONLY:
            return self._explain_log_only(result, finding)

        notes_str = " | ".join(result.notes)[:300]
        context = (
            f"{_attack_context_block(finding)}\n\n"
            if finding is not None
            else ""
        )
        prompt = (
            f"{_TAXONOMY_INDEX}\n\n"
            "You are an LLM security expert explaining a remediation.\n\n"
            f"{context}"
            f"Remediation strategy: {result.strategy}\n"
            f"Implementation notes: {notes_str}\n\n"
            "In 2 short sentences, explain why this fix BLOCKS the "
            "specific attack above. Be practical and tied to the "
            "actual exploit."
        )
        return self._call(prompt)

    def _explain_log_only(
        self,
        result: RemediationResult,
        finding: Finding | None,
    ) -> str | None:
        """Recommend guardrails for a LOG_ONLY (no runtime patch) finding.

        Uses the product-spec prompt verbatim when a finding is
        supplied. When no finding is available (legacy call path)
        falls back to the implementation notes so Claude still has
        something concrete to anchor on.
        """
        if finding is not None:
            attack_excerpt = finding.attack_prompt[:_PROMPT_EXCERPT_CHARS]
            response_excerpt = finding.model_response[:_RESPONSE_EXCERPT_CHARS]
            category_label = _owasp_category_name(finding.owasp_llm_category)
            prompt = (
                f"{_TAXONOMY_INDEX}\n\n"
                "This finding has LOG_ONLY strategy meaning the "
                "vulnerability was found in an external system that "
                "cannot be directly patched.\n\n"
                "Based on this specific attack:\n"
                f"Attack: {attack_excerpt}\n"
                f"Response: {response_excerpt}\n"
                f"Category: {category_label}\n\n"
                "Explain in 2-3 sentences what guardrails the system "
                "owner should implement to prevent this type of "
                "attack. Be specific to this exact attack pattern."
            )
        else:
            notes_str = " | ".join(result.notes)[:300]
            prompt = (
                f"{_TAXONOMY_INDEX}\n\n"
                "This finding has LOG_ONLY strategy meaning the "
                "vulnerability was found in an external system that "
                "cannot be directly patched.\n\n"
                f"Implementation notes: {notes_str}\n\n"
                "Explain in 2-3 sentences what guardrails the system "
                "owner should implement to prevent this type of "
                "attack."
            )
        return self._call(prompt)

    def generate_guardrail(self, finding: Finding) -> str | None:
        """Return a per-attack guardrail pattern, or ``None`` on failure.

        Output is intentionally short and oriented at policy authors
        — what to add to an input/output filter, not a multi-page
        threat model.
        """
        prompt = (
            f"{_TAXONOMY_INDEX}\n\n"
            "You are an LLM security engineer authoring a guardrail "
            "rule for THIS specific incident.\n\n"
            f"{_attack_context_block(finding)}\n\n"
            "Propose a concrete guardrail pattern that would block "
            "this attack. Include:\n"
            "1. WHERE to enforce (input filter, output filter, "
            "system prompt, tool-call layer).\n"
            "2. A precise pattern, regex, or check phrased so an "
            "engineer can implement it directly.\n"
            "Keep it under 6 lines total. Avoid generic OWASP advice."
        )
        return self._call(prompt)

    def assess_severity(self, finding: Finding) -> str | None:
        """Return a 1–2 sentence severity rationale, or ``None``.

        The parser already attaches a heuristic severity from the
        attack success rate; this method asks Claude whether the
        per-incident facts justify a different rating and why.
        """
        prompt = (
            f"{_TAXONOMY_INDEX}\n\n"
            "You are an LLM security analyst assigning final severity.\n\n"
            f"{_attack_context_block(finding)}\n\n"
            "In 1–2 sentences: confirm or revise the parser's "
            "severity above for THIS specific incident, with a brief "
            "reason. Use one of: LOW, MEDIUM, HIGH, CRITICAL. Lead "
            "with the chosen label."
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
