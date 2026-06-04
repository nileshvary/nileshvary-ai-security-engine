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

import hashlib
import json
import logging
import re
from typing import Any

from integration_bridge.models import Finding
from integration_bridge.owasp_mapper import VALID_LLM_CATEGORIES
from integration_bridge.owasp_taxonomy import LLM_TOP_10
from remediation_engine.models import RemediationResult, RemediationStrategy

logger = logging.getLogger(__name__)


_MODEL = "claude-haiku-4-5-20251001"
_MAX_TOKENS = 400
_TEMPERATURE = 0.3

# The autonomous-analysis call returns a JSON blob with prose +
# embedded YAML, so it needs significantly more output budget than
# the terse explain_* methods.
_AUTONOMOUS_MAX_TOKENS = 2000

# Allowed severity values for the autonomous-analysis response.
# Anything outside this set falls back to the parser-supplied
# severity on the finding.
_VALID_SEVERITIES: frozenset[str] = frozenset(
    {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
)


def finding_cache_key(finding: Finding) -> str:
    """SHA-256 cache key derived from a finding's content.

    Stable across sessions and re-uploads of the same file. Independent
    of any field that isn't on the canonical ``Finding`` dataclass (no
    ``uuid`` is needed; identity comes from the actual attack content).
    """
    payload = (
        f"{finding.probe_name}|{finding.attack_prompt}|{finding.model_response}"
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def _strip_code_fences(text: str) -> str:
    """Strip markdown ``` / ```json fences and surrounding prose.

    Claude routinely wraps JSON in fenced code blocks even when asked
    not to. Be permissive: if a fenced block exists, return only its
    interior; otherwise return the input unchanged. Also trims any
    leading prose before the first ``{`` and trailing prose after the
    last ``}`` so a JSON-like substring can be extracted from a
    chatty response.
    """
    s = text.strip()
    fence_match = re.search(
        r"```(?:json)?\s*\n?(.*?)\n?```", s, flags=re.DOTALL
    )
    if fence_match:
        return fence_match.group(1).strip()
    first_brace = s.find("{")
    last_brace = s.rfind("}")
    if first_brace >= 0 and last_brace > first_brace:
        return s[first_brace : last_brace + 1].strip()
    return s


def _parse_analysis_response(text: str) -> dict[str, Any] | None:
    """Coerce a Claude response into the analysis dict, or ``None`` on failure.

    Tries strict ``json.loads`` first; falls back to swapping single
    quotes for double quotes (the spec example used single quotes —
    Claude will occasionally mirror that style). Returns ``None`` if
    neither strategy yields a dict — callers fall back to pre-written
    text.
    """
    if not text:
        return None
    stripped = _strip_code_fences(text)
    for candidate in (stripped, stripped.replace("'", '"')):
        try:
            parsed = json.loads(candidate)
        except (ValueError, TypeError):
            continue
        if isinstance(parsed, dict):
            return parsed
    return None
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
        # Per-instance counter so callers can show "AI calls this
        # session" without reaching into st.session_state. The
        # autonomous-mode finding card also writes this through to
        # st.session_state.ai_call_count for the sidebar widget.
        self.call_count: int = 0

    # ------------------------------------------------------------------
    # Autonomous analysis — ONE Claude call returns everything we
    # need for a finding card (danger explanation, fix explanation,
    # guardrail YAML, refined severity, refined OWASP category).
    # ------------------------------------------------------------------

    def generate_complete_analysis(
        self,
        finding: Finding,
    ) -> dict[str, Any] | None:
        """Return the full per-finding analysis dict, or ``None`` on failure.

        Schema (all keys may be missing if the parse goes sideways —
        callers must defend against absent fields):

            why_dangerous: str
            why_fix_works: str
            guardrail_yaml: str           (raw YAML text)
            severity: "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
            owasp_category: "LLMnn"

        ``severity`` and ``owasp_category`` are validated against the
        canonical sets; invalid values are stripped before return so
        downstream consumers can trust them.

        Caller is expected to cache the result by
        ``finding_cache_key(finding)`` so we don't re-spend tokens on
        the same finding across reruns. ``self.call_count`` is
        incremented per HTTP call regardless of cache hits at the
        caller layer.
        """
        target_hint = "AI system"
        if isinstance(finding.raw_data, dict):
            # Best-effort target name from the underlying garak record;
            # the spec referenced ``finding.notes.get('target', ...)``
            # which doesn't exist on our schema. ``raw_data`` is the
            # closest equivalent.
            target_hint = str(
                finding.raw_data.get("target")
                or finding.raw_data.get("target_name")
                or finding.raw_data.get("model_name")
                or "AI system"
            )
        prompt = (
            "You are an expert AI security researcher.\n"
            "Analyze this vulnerability finding:\n\n"
            f"Target: {target_hint}\n"
            f"OWASP Category: {finding.owasp_llm_category}\n"
            f"Attack Probe: {finding.probe_name}\n"
            f"Attack Prompt: {finding.attack_prompt[:_PROMPT_EXCERPT_CHARS]}\n"
            f"Model Response: {finding.model_response[:_RESPONSE_EXCERPT_CHARS]}\n"
            f"Severity: {finding.severity}\n\n"
            "Return a JSON object with these exact keys:\n"
            "{\n"
            '  "why_dangerous": "3 sentences explaining why this '
            'specific attack is dangerous",\n'
            '  "why_fix_works": "3 sentences explaining what '
            'guardrail prevents this attack",\n'
            '  "guardrail_yaml": "complete YAML guardrail with '
            "input_guardrails and output_guardrails specific to "
            'this exact attack pattern",\n'
            '  "severity": "LOW or MEDIUM or HIGH or CRITICAL",\n'
            '  "owasp_category": "correct LLM category code"\n'
            "}\n\n"
            "Return ONLY valid JSON. No explanation."
        )
        response = self._call(prompt, max_tokens=_AUTONOMOUS_MAX_TOKENS)
        if response is None:
            return None
        parsed = _parse_analysis_response(response)
        if parsed is None:
            logger.warning(
                "generate_complete_analysis: could not parse JSON from Claude "
                "(probe=%s len=%d). Falling back to pre-written content.",
                finding.probe_name,
                len(response),
            )
            return None
        # Validate the constrained fields. Unknown values are scrubbed
        # so downstream code can safely treat them as authoritative.
        severity = str(parsed.get("severity", "")).strip().upper()
        if severity not in _VALID_SEVERITIES:
            parsed.pop("severity", None)
        else:
            parsed["severity"] = severity
        category = str(parsed.get("owasp_category", "")).strip().upper()
        if category not in VALID_LLM_CATEGORIES:
            parsed.pop("owasp_category", None)
        else:
            parsed["owasp_category"] = category
        return parsed

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

    def _call(self, prompt: str, *, max_tokens: int | None = None) -> str | None:
        """Run a single one-shot Claude call. Returns ``None`` on any error.

        Increments ``self.call_count`` on every HTTP attempt — even
        failures count, because the user-visible cost reflects API
        usage not successful parses.
        """
        self.call_count += 1
        try:
            msg = self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens or self.max_tokens,
                temperature=self.temperature,
                messages=[{"role": "user", "content": prompt}],
            )
            return msg.content[0].text
        except Exception as exc:
            logger.warning("Claude call failed; falling back to basic mode: %s", exc)
            return None
