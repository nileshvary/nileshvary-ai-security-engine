"""Detection + redaction for model responses flagged by garak.

Three modes, picked from ``Finding.owasp_llm_category``:

- **LLM02** — PII and secrets: SSN, email, phone, credit card, AWS access
  key, JWT, generic API key. Each match is replaced with a typed
  ``[REDACTED-*]`` token.
- **LLM05** — improper output handling: XSS (script tags, ``javascript:``
  URIs, event handlers), SQL injection markers, then a final ``html.escape``
  pass over the result.
- **LLM06** — excessive agency: flag-only mode. Detects tool/action
  invocation language without modifying the response.

All other categories return a no-op ``ResponseSanitization`` so callers
that route blindly never crash.
"""

from __future__ import annotations

import html
import logging
import re
from re import Pattern

from integration_bridge.models import Finding

from remediation_engine.models import ResponseSanitization

logger = logging.getLogger(__name__)


_PII_PATTERNS: tuple[tuple[str, Pattern[str], str], ...] = (
    ("SSN",   re.compile(r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b"),                               "[REDACTED-SSN]"),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),            "[REDACTED-EMAIL]"),
    ("phone", re.compile(r"\b(?:\+?\d{1,2}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"), "[REDACTED-PHONE]"),
    ("credit card", re.compile(r"\b(?:\d[ -]*?){13,19}\b"),                                 "[REDACTED-CC]"),
)

_SECRET_PATTERNS: tuple[tuple[str, Pattern[str], str], ...] = (
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}"),                                                    "[REDACTED-AWS-KEY]"),
    ("JWT",            re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),              "[REDACTED-JWT]"),
    ("API key",        re.compile(r"\b(?:sk|pk|api[-_]?key)[-_]?[A-Za-z0-9]{20,}\b", re.IGNORECASE),      "[REDACTED-API-KEY]"),
)

_XSS_PATTERNS: tuple[tuple[str, Pattern[str], str], ...] = (
    ("XSS script tag",      re.compile(r"<script[^>]*>.*?</script>", re.IGNORECASE | re.DOTALL), "[REMOVED-SCRIPT]"),
    ("javascript: URI",     re.compile(r"javascript:", re.IGNORECASE),                           "[REMOVED-JS-URI]"),
    ("XSS event handler",   re.compile(r"\bon\w+\s*=", re.IGNORECASE),                           "[REMOVED-HANDLER]"),
)

_SQLI_PATTERNS: tuple[tuple[str, Pattern[str], str], ...] = (
    (
        "SQL injection",
        re.compile(
            r"(?:'\s*OR\s*'?\d+'?\s*=\s*'?\d+|;\s*DROP\s+TABLE\s+\w+|UNION\s+SELECT)",
            re.IGNORECASE,
        ),
        "[REMOVED-SQLI]",
    ),
)

_TOOL_INVOCATION_PATTERNS: tuple[tuple[str, Pattern[str]], ...] = (
    ("tool call",     re.compile(r"\bcalling\s+tool\s*:", re.IGNORECASE)),
    ("function call", re.compile(r"\bfunction[_\s]call\s*:", re.IGNORECASE)),
    ("execute",       re.compile(r"\b(?:I\s+will\s+now\s+)?execut(?:e|ing)\b\s*:?", re.IGNORECASE)),
    ("invoke",        re.compile(r"\binvoking\s+(?:action|tool|api)\b", re.IGNORECASE)),
)


def _apply_pattern_group(
    text: str,
    patterns: tuple[tuple[str, Pattern[str], str], ...],
    detected: list[str],
    actions: list[str],
) -> str:
    """Apply each (label, pattern, replacement) tuple in order.

    Updates ``detected`` and ``actions`` in place with one entry per
    pattern that matched at least once.
    """
    for label, pattern, replacement in patterns:
        matches = pattern.findall(text)
        if not matches:
            continue
        count = len(matches)
        text = pattern.sub(replacement, text)
        detected.append(f"{label} detected")
        action = (
            f"redacted {count} {label}(s)"
            if replacement.startswith("[REDACTED")
            else f"removed {count} {label}(s)"
        )
        actions.append(action)
        logger.debug("Matched %s x%d in response", label, count)
    return text


class ResponseRemediator:
    """Detects and redacts unsafe content in model responses."""

    def sanitize_response(
        self, finding: Finding, response: str
    ) -> ResponseSanitization:
        """Return a sanitization for ``response`` chosen by category.

        Args:
            finding: The Finding whose ``owasp_llm_category`` selects the
                detection / redaction mode.
            response: The model response text to inspect.

        Returns:
            A ``ResponseSanitization`` carrying the redacted output (or
            the original text for flag-only / unhandled categories) plus
            human-readable lists of detected issues and applied actions.
        """
        category = finding.owasp_llm_category
        detected: list[str] = []
        actions: list[str] = []

        if category == "LLM02":
            sanitized = _apply_pattern_group(response, _PII_PATTERNS, detected, actions)
            sanitized = _apply_pattern_group(sanitized, _SECRET_PATTERNS, detected, actions)
            logger.info(
                "LLM02 sanitization for probe '%s': %d issue(s) redacted",
                finding.probe_name,
                len(detected),
            )
            return ResponseSanitization(
                original_response=response,
                sanitized_response=sanitized,
                detected_issues=detected,
                actions_taken=actions,
            )

        if category == "LLM05":
            sanitized = _apply_pattern_group(response, _XSS_PATTERNS, detected, actions)
            sanitized = _apply_pattern_group(sanitized, _SQLI_PATTERNS, detected, actions)
            escaped = html.escape(sanitized, quote=True)
            if escaped != sanitized:
                actions.append("HTML-escaped residual markup")
            sanitized = escaped
            logger.info(
                "LLM05 sanitization for probe '%s': %d issue(s) removed",
                finding.probe_name,
                len(detected),
            )
            return ResponseSanitization(
                original_response=response,
                sanitized_response=sanitized,
                detected_issues=detected,
                actions_taken=actions,
            )

        if category == "LLM06":
            for label, pattern in _TOOL_INVOCATION_PATTERNS:
                matches = pattern.findall(response)
                if matches:
                    detected.append(f"{label} pattern detected")
                    actions.append(f"flagged {len(matches)} {label} occurrence(s)")
                    logger.debug("LLM06 flagged %s x%d", label, len(matches))
            logger.info(
                "LLM06 flag-only scan for probe '%s': %d pattern(s) flagged",
                finding.probe_name,
                len(detected),
            )
            return ResponseSanitization(
                original_response=response,
                sanitized_response=response,
                detected_issues=detected,
                actions_taken=actions,
            )

        logger.debug(
            "Category %s is not handled by ResponseRemediator; returning no-op",
            category,
        )
        return ResponseSanitization(
            original_response=response,
            sanitized_response=response,
            detected_issues=[],
            actions_taken=[],
        )
