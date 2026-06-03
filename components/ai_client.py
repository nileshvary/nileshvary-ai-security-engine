"""Thin Claude wrapper for RemediAX's optional AI-enhanced explanations.

Every public method returns ``None`` when the underlying API call fails,
so callers can fall back to the pre-written ``OWASP_CONTENT`` strings
without crashing the UI.

Prompt design: each method ships the actual attack prompt + response +
resolved OWASP category (with the human-readable name appended) and
asks Claude for ONE concrete output. The prompt text is the product
spec verbatim, deliberately terse, so responses stay short and on-
topic instead of devolving into clarifying questions.

The previous version of this module prepended a global "OWASP
TAXONOMY REFERENCE" table to every call. That was dropped — the per-
prompt ``Category: LLMnn (Name)`` line is enough for Claude and saves
roughly 300 tokens per call.
"""

from __future__ import annotations

import logging

from integration_bridge.models import Finding
from integration_bridge.owasp_taxonomy import LLM_TOP_10
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
    already validates against ``VALID_LLM_CATEGORIES``. The format
    ``"LLM07 (System Prompt Leakage)"`` is what every prompt below
    feeds Claude so the model can name the category correctly even
    while reasoning from the bare code.
    """
    entry = LLM_TOP_10.get(code)
    if entry is None:
        return code
    return f"{code} ({entry.name})"


def _owasp_short_name(code: str) -> str:
    """Bare human-readable name (no code prefix) for use in fallback text.

    Used by the LOG_ONLY clarifying-question fallback so the
    sentence reads naturally — ``"To prevent this Prompt Injection
    attack..."`` rather than ``"To prevent this LLM01 (Prompt
    Injection) attack..."``.
    """
    entry = LLM_TOP_10.get(code)
    if entry is None:
        return code
    return entry.name


# Phrases that indicate Claude is asking for clarification instead
# of producing the requested explanation. Case-insensitive substring
# match — if any of these appear in a fix-explanation response we
# treat it as a failed call and fall back to pre-written content so
# the user never sees a clarifying question.
_CLARIFYING_QUESTION_MARKERS: tuple[str, ...] = (
    "i need",
    "clarify",
    "specify",
    "which owasp",
    "haven't specified",
    "could you",
)


def _looks_like_clarifying_question(text: str) -> bool:
    """True when ``text`` reads like Claude asking what to explain."""
    if not text:
        return False
    lowered = text.lower()
    return any(marker in lowered for marker in _CLARIFYING_QUESTION_MARKERS)


def _logonly_fallback_text(category_name: str) -> str:
    """Spec-mandated fallback shown when Claude punts on a LOG_ONLY finding.

    Generic but actionable — tells the operator where and how to add
    a guardrail without pretending to know specifics Claude couldn't
    derive. ``category_name`` is the bare short name (e.g.
    ``"Excessive Agency"``).
    """
    return (
        f"To prevent this {category_name} attack, implement input "
        "guardrails blocking the specific attack pattern used. "
        "Deploy at the LLM gateway layer before requests reach the "
        "model. Monitor for similar extraction attempts in logs."
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
        """Why is THIS specific response dangerous? 2 sentences, or ``None``.

        Uses the spec's terse 4-line context format so Claude doesn't
        spend tokens restating the category description.
        """
        prompt = (
            "You are an LLM security expert.\n"
            "This exact attack succeeded:\n"
            f"Attack: {finding.attack_prompt[:_PROMPT_EXCERPT_CHARS]}\n"
            f"Response: {finding.model_response[:_RESPONSE_EXCERPT_CHARS]}\n"
            f"Category: {_owasp_category_name(finding.owasp_llm_category)}\n"
            "In 2 sentences explain why THIS specific response is "
            "dangerous. Be concrete."
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
            response = self._explain_log_only(result, finding)
        else:
            response = self._explain_patch_fix(result, finding)

        # Spec safety net: if Claude responded with a clarifying
        # question instead of an explanation, never surface it to
        # the user. For LOG_ONLY findings substitute the spec-
        # mandated fallback (gives the operator concrete guardrail
        # guidance). For other strategies return None so the caller
        # falls back to OWASP_CONTENT[code]["fix_explanation"] (the
        # same pre-written text Basic mode shows).
        if response and _looks_like_clarifying_question(response):
            logger.info(
                "explain_fix: discarding Claude clarifying-question response "
                "(strategy=%s, finding=%s)",
                result.strategy,
                finding.owasp_llm_category if finding is not None else "n/a",
            )
            if result.strategy == RemediationStrategy.LOG_ONLY:
                code = (
                    finding.owasp_llm_category if finding is not None else ""
                )
                return _logonly_fallback_text(_owasp_short_name(code))
            return None
        return response

    def _explain_patch_fix(
        self,
        result: RemediationResult,
        finding: Finding | None,
    ) -> str | None:
        """Why does the runtime patch block this exact attack?"""
        notes_str = " | ".join(result.notes)[:300]
        if finding is not None:
            prompt = (
                "You are an LLM security expert.\n"
                "This exact attack was patched:\n"
                f"Attack: {finding.attack_prompt[:_PROMPT_EXCERPT_CHARS]}\n"
                f"Response: {finding.model_response[:_RESPONSE_EXCERPT_CHARS]}\n"
                f"Category: {_owasp_category_name(finding.owasp_llm_category)}\n"
                f"Remediation strategy: {result.strategy}\n"
                f"Implementation notes: {notes_str}\n"
                "In 2 sentences explain why this fix BLOCKS the "
                "exact attack above."
            )
        else:
            prompt = (
                "You are an LLM security expert.\n"
                f"Remediation strategy: {result.strategy}\n"
                f"Implementation notes: {notes_str}\n"
                "In 2 sentences explain why this fix works."
            )
        return self._call(prompt)

    def _explain_log_only(
        self,
        result: RemediationResult,
        finding: Finding | None,
    ) -> str | None:
        """Recommend an input guardrail for a LOG_ONLY (no patch) finding.

        Uses the product-spec prompt with the actual OWASP category
        name substituted in (so an LLM03 Supply Chain finding gets a
        Supply-Chain-specific guardrail, not a System-Prompt-Leakage
        one). Falls back to the implementation notes when no finding
        is supplied so the legacy call path still works.
        """
        if finding is not None:
            category_name = _owasp_category_name(finding.owasp_llm_category)
            prompt = (
                "You are an LLM security expert.\n"
                f"A {category_name} attack was found:\n"
                f"Attack prompt: {finding.attack_prompt[:_PROMPT_EXCERPT_CHARS]}\n"
                f"Model response: {finding.model_response[:_RESPONSE_EXCERPT_CHARS]}\n"
                f"OWASP Category: {category_name}\n"
                "In 2 sentences explain what input guardrail pattern "
                "would prevent this exact attack."
            )
        else:
            notes_str = " | ".join(result.notes)[:300]
            prompt = (
                "You are an LLM security expert.\n"
                f"Strategy: {result.strategy} (no runtime patch generated)\n"
                f"Implementation notes: {notes_str}\n"
                "In 2 sentences explain what input guardrail pattern "
                "would prevent this exact attack."
            )
        return self._call(prompt)

    def generate_guardrail(self, finding: Finding) -> str | None:
        """Return ONE regex pattern that blocks this exact attack, or ``None``.

        The spec asks for a bare regex line so the output can be
        dropped straight into a guardrail config. We strip a single
        leading/trailing line of whitespace from Claude's reply but
        otherwise return it verbatim — extracting "just the regex"
        is the caller's job if they need to defend against chatty
        responses.
        """
        prompt = (
            "Generate ONE regex pattern that blocks this exact attack:\n"
            f"Attack prompt: {finding.attack_prompt[:_PROMPT_EXCERPT_CHARS]}\n"
            "Return ONLY the regex pattern, nothing else.\n"
            "Example format: repeat.*words.*above"
        )
        return self._call(prompt)

    def assess_severity(self, finding: Finding) -> str | None:
        """Return ONE word: LOW / MEDIUM / HIGH / CRITICAL, or ``None``.

        Constrained to a single token so the caller can use it
        directly as a severity label without parsing prose.
        """
        prompt = (
            "Rate severity of this attack as one of:\n"
            "LOW, MEDIUM, HIGH, CRITICAL\n"
            f"Attack: {finding.attack_prompt[:_PROMPT_EXCERPT_CHARS]}\n"
            f"Response: {finding.model_response[:_RESPONSE_EXCERPT_CHARS]}\n"
            f"Category: {_owasp_category_name(finding.owasp_llm_category)}\n"
            "Return ONLY one word: LOW/MEDIUM/HIGH/CRITICAL"
        )
        return self._call(prompt)

    def summarize_scan(
        self,
        findings: list[Finding],
        target: str | None = None,
    ) -> str | None:
        """Return a 2-sentence scan-level summary, or ``None`` on failure.

        ``target`` is the model / system that was scanned (e.g.
        ``"gpt-2"``). It's optional so existing callers continue to
        work; when omitted we render the line as ``Target: unknown``
        so Claude still has a complete template to reason from.

        Categories are auto-derived from the findings using their
        canonical OWASP names (LLM01 → ``"Prompt Injection"``,
        etc.) — the spec prompt insists on correct OWASP names only,
        so we resolve them server-side rather than asking Claude to
        guess from codes.
        """
        category_names: list[str] = []
        seen: set[str] = set()
        for finding in findings:
            code = finding.owasp_llm_category
            if code in seen:
                continue
            seen.add(code)
            entry = LLM_TOP_10.get(code)
            category_names.append(entry.name if entry is not None else code)
        categories_label = ", ".join(category_names) if category_names else "(none)"
        prompt = (
            "Summarize this security scan in 2 sentences:\n"
            f"Target: {target or 'unknown'}\n"
            f"Findings: {len(findings)} vulnerabilities\n"
            f"Categories: {categories_label}\n"
            "Use correct OWASP names only.\n"
            "Be specific and professional."
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
