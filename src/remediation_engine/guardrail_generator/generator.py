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


# OWASP Agentic Top 10 (2026) — textual policy rules for the three
# categories that the spec calls out explicitly. These are policies
# rather than regex patterns: there's no single substring that
# uniformly identifies "agent invokes a tool outside its scope",
# so we ship a description that a policy engine or a human reviewer
# can implement. Format mirrors the LLM rules (id / type / patterns
# / on_match) so the YAML output is uniform.
_ASI_INPUT_POLICIES: dict[str, dict[str, Any]] = {
    "ASI02": {
        "id": "asi02-tool-authorization",
        "type": "policy",
        "patterns": [
            "block unauthorized tool calls",
            "validate tool permissions before execution",
            "require explicit tool authorization",
        ],
        "on_match": "block",
    },
    "ASI07": {
        "id": "asi07-inter-agent-trust",
        "type": "policy",
        "patterns": [
            "validate agent identity before trust",
            "verify message signatures between agents",
            "block unauthenticated agent commands",
        ],
        "on_match": "block",
    },
    "ASI10": {
        "id": "asi10-behavioral-monitoring",
        "type": "policy",
        "patterns": [
            "monitor agent behavior patterns",
            "detect goal deviation from original task",
            "block unauthorized autonomous decisions",
        ],
        "on_match": "block",
    },
}

_ASI_OUTPUT_POLICIES: dict[str, dict[str, Any]] = {
    "ASI02": {
        "id": "asi02-tool-call-audit",
        "type": "policy",
        "patterns": [
            "detect unexpected tool invocations",
            "flag unauthorized API calls",
        ],
        "on_match": "flag",
    },
    "ASI07": {
        "id": "asi07-cross-agent-audit",
        "type": "policy",
        "patterns": [
            "detect unverified agent instructions",
            "flag cross-agent data leakage",
        ],
        "on_match": "flag",
    },
    "ASI10": {
        "id": "asi10-action-approval",
        "type": "policy",
        "patterns": [
            "flag unexpected agent actions",
            "require human approval for high-impact decisions",
        ],
        "on_match": "flag",
    },
}


class GuardrailGenerator:
    """Builds a ``GuardrailConfig`` from a batch of ``Finding`` objects."""

    def generate(
        self,
        findings: list[Finding],
        output_format: str = "portkey",
        *,
        ai_client: Any | None = None,
    ) -> GuardrailConfig:
        """Build a ``GuardrailConfig`` covering every category in ``findings``.

        Args:
            findings: The full batch of findings; the *set* of distinct
                ``owasp_llm_category`` values determines which rules
                appear in the output.
            output_format: One of ``"portkey"``, ``"litellm"``, ``"generic"``.
            ai_client: Optional ``RemediAXAI``. When supplied AND
                Claude returns a parseable analysis per finding, the
                generator merges each finding's ``guardrail_yaml``
                into the output (concatenated input/output rule lists
                with de-duplication by ``id``, rate limits use the
                minimum value seen across findings). When ``None``,
                or when every Claude call fails to parse, falls back
                to the deterministic hardcoded rules below — that
                path is what every existing test exercises and is
                fully backward compatible.

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
        # Collect agentic codes too — the 2026 Agentic Top 10
        # additions surface specific policy rules per category that
        # sit alongside the LLM regex rules.
        agentic_categories: set[str] = set()
        for finding in findings:
            agentic_categories.update(finding.owasp_agentic_categories)
        logger.info(
            "Generating %s guardrail config covering LLM=%s agentic=%s",
            output_format,
            sorted(categories),
            sorted(agentic_categories),
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

        # Append ASI policy rules in canonical ASI01..ASI10 order so
        # the YAML output is deterministic regardless of finding-list
        # ordering.
        for asi_code in sorted(agentic_categories):
            if asi_code in _ASI_INPUT_POLICIES:
                # Defensive copy so callers mutating the rule list
                # can't poison module-level constants.
                input_rules.append({**_ASI_INPUT_POLICIES[asi_code],
                                    "patterns": list(_ASI_INPUT_POLICIES[asi_code]["patterns"])})
            if asi_code in _ASI_OUTPUT_POLICIES:
                output_rules.append({**_ASI_OUTPUT_POLICIES[asi_code],
                                     "patterns": list(_ASI_OUTPUT_POLICIES[asi_code]["patterns"])})

        # Autonomous mode — merge per-finding Claude-generated YAML.
        if ai_client is not None and findings:
            self._merge_autonomous_yaml(
                ai_client, findings, input_rules, output_rules, rate_limits
            )

        rendered = self._render(output_format, input_rules, output_rules, rate_limits, categories, agentic_categories)
        yaml_export = yaml.safe_dump(rendered, sort_keys=False, default_flow_style=False)

        return GuardrailConfig(
            format=output_format,
            input_filters=input_rules,
            output_filters=output_rules,
            rate_limits=rate_limits,
            yaml_export=yaml_export,
        )

    def _merge_autonomous_yaml(
        self,
        ai_client: Any,
        findings: list[Finding],
        input_rules: list[dict[str, Any]],
        output_rules: list[dict[str, Any]],
        rate_limits: dict[str, Any],
    ) -> None:
        """Append Claude-generated per-finding rules into the running lists.

        For each finding we ask Claude for a complete analysis (one
        call per finding, see ``ai_client.generate_complete_analysis``).
        The returned ``guardrail_yaml`` field is parsed as YAML; any
        ``input_guardrails`` / ``output_guardrails`` lists found are
        appended to the running rule lists with de-duplication keyed
        on the ``id`` field. ``rate_limits`` use the minimum value
        seen across findings (strictest wins, per the design
        chosen during the spec call).

        All failures (Claude call error, JSON parse error, YAML parse
        error, schema surprise) are swallowed — the deterministic
        rules accumulated by ``generate`` above remain the floor.
        """
        # Pre-index existing rules so duplicate ``id`` values from
        # Claude don't bloat the YAML on top of what we already have.
        seen_input_ids = {r.get("id") for r in input_rules if r.get("id")}
        seen_output_ids = {r.get("id") for r in output_rules if r.get("id")}

        for finding in findings:
            try:
                analysis = ai_client.generate_complete_analysis(finding)
            except Exception as exc:  # pragma: no cover - safety net
                logger.warning(
                    "generate_complete_analysis raised for probe %s: %s",
                    finding.probe_name,
                    exc,
                )
                continue
            if not analysis:
                continue
            raw_yaml = analysis.get("guardrail_yaml")
            if not raw_yaml or not isinstance(raw_yaml, str):
                continue
            try:
                parsed = yaml.safe_load(raw_yaml)
            except yaml.YAMLError as exc:
                logger.warning(
                    "Discarding malformed guardrail_yaml for probe %s: %s",
                    finding.probe_name,
                    exc,
                )
                continue
            if not isinstance(parsed, dict):
                continue

            for rule in self._coerce_rule_list(parsed.get("input_guardrails")):
                rid = rule.get("id")
                if rid and rid in seen_input_ids:
                    continue
                if rid:
                    seen_input_ids.add(rid)
                input_rules.append(rule)

            for rule in self._coerce_rule_list(parsed.get("output_guardrails")):
                rid = rule.get("id")
                if rid and rid in seen_output_ids:
                    continue
                if rid:
                    seen_output_ids.add(rid)
                output_rules.append(rule)

            for key, value in self._coerce_rate_limits(parsed.get("rate_limits")).items():
                if key in rate_limits:
                    try:
                        rate_limits[key] = min(int(rate_limits[key]), int(value))
                    except (TypeError, ValueError):
                        # Non-numeric — leave the existing value.
                        continue
                else:
                    rate_limits[key] = value

    @staticmethod
    def _coerce_rule_list(value: Any) -> list[dict[str, Any]]:
        """Return ``value`` as a list of rule dicts, dropping bad entries."""
        if not isinstance(value, list):
            return []
        return [item for item in value if isinstance(item, dict)]

    @staticmethod
    def _coerce_rate_limits(value: Any) -> dict[str, Any]:
        """Return ``value`` as a flat dict of numeric rate limits."""
        if not isinstance(value, dict):
            return {}
        out: dict[str, Any] = {}
        for k, v in value.items():
            if isinstance(k, str):
                out[k] = v
        return out

    def _render(
        self,
        output_format: str,
        input_rules: list[dict[str, Any]],
        output_rules: list[dict[str, Any]],
        rate_limits: dict[str, Any],
        categories: set[str],
        agentic_categories: set[str],
    ) -> dict[str, Any]:
        """Reshape the rule lists into the per-format top-level dict."""
        covered = sorted(categories)
        covered_agentic = sorted(agentic_categories)

        if output_format == "portkey":
            return {
                "version": 1,
                "covered_owasp_categories": covered,
                "covered_agentic_categories": covered_agentic,
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
                "covered_agentic_categories": covered_agentic,
                "guardrails": litellm_rules,
                "router_settings": router_settings,
            }

        return {
            "version": 1,
            "covered_owasp_categories": covered,
            "covered_agentic_categories": covered_agentic,
            "input_filters": input_rules,
            "output_filters": output_rules,
            "rate_limits": rate_limits,
        }
