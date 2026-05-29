"""Generates AI-gateway guardrail configs from a set of findings.

Output formats:

- ``portkey``  — Portkey AI Gateway shape (``input_guardrails``,
  ``output_guardrails``, ``rate_limits``).
- ``litellm``  — LiteLLM ``guardrails`` list under a single key, with
  ``router_settings`` for rate limits.
- ``generic``  — vendor-neutral nested mapping.

All formats are produced by mapping the same in-memory rule objects
through a per-format renderer, then serializing with ``yaml.safe_dump``.
"""

from __future__ import annotations

import logging
from typing import Any

import yaml

from integration_bridge.models import Finding

from remediation_engine.models import GuardrailConfig

logger = logging.getLogger(__name__)


_VALID_FORMATS: frozenset[str] = frozenset({"portkey", "litellm", "generic"})

_PROMPT_INJECTION_PATTERNS: list[str] = [
    r"ignore (?:all |the )?previous instructions",
    r"you are now (?:DAN|in developer mode)",
    r"pretend you have no rules",
    r"act as (?:a |an )?(?:unrestricted|uncensored)",
    r"jailbreak",
    r"grandma (?:exploit|trick)",
]

_PII_AND_SECRET_PATTERNS: list[str] = [
    r"\b\d{3}[-\s]?\d{2}[-\s]?\d{4}\b",
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    r"\b(?:\+?\d{1,2}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
    r"\b(?:\d[ -]*?){13,19}\b",
    r"AKIA[0-9A-Z]{16}",
    r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b",
    r"\b(?:sk|pk|api[-_]?key)[-_]?[A-Za-z0-9]{20,}\b",
]

_XSS_AND_SQLI_PATTERNS: list[str] = [
    r"<script[^>]*>.*?</script>",
    r"javascript:",
    r"\bon\w+\s*=",
    r"'\s*OR\s*'?\d+'?\s*=\s*'?\d+",
    r";\s*DROP\s+TABLE\s+\w+",
    r"UNION\s+SELECT",
]

_RATE_LIMITS: dict[str, int] = {
    "requests_per_minute": 60,
    "tokens_per_minute": 100_000,
}


class GuardrailGenerator:
    """Builds a ``GuardrailConfig`` from a batch of ``Finding`` objects."""

    def generate(
        self,
        findings: list[Finding],
        output_format: str = "portkey",
    ) -> GuardrailConfig:
        """Build a ``GuardrailConfig`` covering every category in ``findings``.

        Args:
            findings: The full batch of findings; the *set* of distinct
                ``owasp_llm_category`` values determines which rules
                appear in the output.
            output_format: One of ``"portkey"``, ``"litellm"``, ``"generic"``.

        Returns:
            A ``GuardrailConfig`` with the same data presented as parsed
            rule lists/dicts AND serialized YAML.

        Raises:
            ValueError: If ``output_format`` is not a supported format.
        """
        if output_format not in _VALID_FORMATS:
            raise ValueError(
                f"unsupported output_format {output_format!r}; "
                f"expected one of {sorted(_VALID_FORMATS)}"
            )

        categories = {f.owasp_llm_category for f in findings}
        logger.info(
            "Generating %s guardrail config covering categories: %s",
            output_format,
            sorted(categories),
        )

        input_rules: list[dict[str, Any]] = []
        output_rules: list[dict[str, Any]] = []
        rate_limits: dict[str, Any] = {}

        if "LLM01" in categories:
            input_rules.append(
                {
                    "id": "prompt-injection-defense",
                    "type": "regex",
                    "patterns": list(_PROMPT_INJECTION_PATTERNS),
                    "on_match": "block",
                }
            )
        if "LLM02" in categories:
            output_rules.append(
                {
                    "id": "pii-and-secrets-redaction",
                    "type": "regex",
                    "patterns": list(_PII_AND_SECRET_PATTERNS),
                    "on_match": "redact",
                }
            )
        if "LLM05" in categories:
            output_rules.append(
                {
                    "id": "xss-and-sqli-sanitization",
                    "type": "regex",
                    "patterns": list(_XSS_AND_SQLI_PATTERNS),
                    "on_match": "redact",
                }
            )
        if "LLM10" in categories:
            rate_limits = dict(_RATE_LIMITS)

        rendered = self._render(output_format, input_rules, output_rules, rate_limits, categories)
        yaml_export = yaml.safe_dump(rendered, sort_keys=False, default_flow_style=False)

        return GuardrailConfig(
            format=output_format,
            input_filters=input_rules,
            output_filters=output_rules,
            rate_limits=rate_limits,
            yaml_export=yaml_export,
        )

    def _render(
        self,
        output_format: str,
        input_rules: list[dict[str, Any]],
        output_rules: list[dict[str, Any]],
        rate_limits: dict[str, Any],
        categories: set[str],
    ) -> dict[str, Any]:
        """Reshape the rule lists into the per-format top-level dict."""
        covered = sorted(categories)

        if output_format == "portkey":
            return {
                "version": 1,
                "covered_owasp_categories": covered,
                "input_guardrails": input_rules,
                "output_guardrails": output_rules,
                "rate_limits": rate_limits,
            }

        if output_format == "litellm":
            litellm_rules: list[dict[str, Any]] = []
            for rule in input_rules:
                litellm_rules.append(
                    {
                        "guardrail_name": rule["id"],
                        "litellm_params": {
                            "guardrail": rule["type"],
                            "mode": "pre_call",
                            "on_match": rule["on_match"],
                        },
                        "patterns": rule["patterns"],
                    }
                )
            for rule in output_rules:
                litellm_rules.append(
                    {
                        "guardrail_name": rule["id"],
                        "litellm_params": {
                            "guardrail": rule["type"],
                            "mode": "post_call",
                            "on_match": rule["on_match"],
                        },
                        "patterns": rule["patterns"],
                    }
                )
            router_settings: dict[str, Any] = {}
            if rate_limits:
                router_settings = {
                    "rpm": rate_limits.get("requests_per_minute"),
                    "tpm": rate_limits.get("tokens_per_minute"),
                }
            return {
                "version": 1,
                "covered_owasp_categories": covered,
                "guardrails": litellm_rules,
                "router_settings": router_settings,
            }

        return {
            "version": 1,
            "covered_owasp_categories": covered,
            "input_filters": input_rules,
            "output_filters": output_rules,
            "rate_limits": rate_limits,
        }
