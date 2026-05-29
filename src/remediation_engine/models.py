"""Data models for the remediation engine.

Defines the unified ``RemediationResult`` contract produced by
``RemediationOrchestrator`` and consumed by downstream stages
(``verifier``, ``output``), plus the three artifact dataclasses
(``PromptPatch``, ``ResponseSanitization``, ``GuardrailConfig``)
that one or more results may carry.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any

from integration_bridge.models import Finding


class RemediationStrategy(StrEnum):
    """High-level remediation approach chosen for a finding."""

    BLOCK = "block"
    SANITIZE = "sanitize"
    HARDEN = "harden"
    LOG_ONLY = "log_only"
    GUARDRAIL = "guardrail"


@dataclass(frozen=True, slots=True)
class PromptPatch:
    """A patched system prompt that resists a specific attack class.

    Attributes:
        original_prompt: The caller-supplied system prompt prior to patching.
        patched_prompt: The patched prompt, ready to drop into the LLM call.
        patch_explanation: One-sentence rationale for why the patch helps.
        injection_resistance_techniques: Named techniques composed into the
            patch, e.g. ``["instruction-hierarchy", "delimiter-tagging"]``.
    """

    original_prompt: str
    patched_prompt: str
    patch_explanation: str
    injection_resistance_techniques: list[str]


@dataclass(frozen=True, slots=True)
class ResponseSanitization:
    """The result of running a model response through detection + redaction.

    Attributes:
        original_response: The raw model response prior to sanitization.
        sanitized_response: The response with detected issues redacted or
            escaped. Equal to ``original_response`` for flag-only modes.
        detected_issues: Human-readable list of issue types found, e.g.
            ``["SSN detected", "AWS access key detected"]``.
        actions_taken: Human-readable list of actions applied, e.g.
            ``["redacted 2 SSN(s)", "removed inline javascript: URI"]``.
    """

    original_response: str
    sanitized_response: str
    detected_issues: list[str]
    actions_taken: list[str]


@dataclass(frozen=True, slots=True)
class GuardrailConfig:
    """A vendor-targeted guardrail configuration produced from many findings.

    Attributes:
        format: One of ``"portkey"``, ``"litellm"``, ``"generic"``.
        input_filters: Parsed input-side rules (kept alongside YAML so
            consumers don't have to re-parse).
        output_filters: Parsed output-side rules.
        rate_limits: Rate-limit settings (per-format key shape).
        yaml_export: The full config serialized to YAML, ready to write
            to disk or pipe into a gateway loader.
    """

    format: str
    input_filters: list[dict[str, Any]]
    output_filters: list[dict[str, Any]]
    rate_limits: dict[str, Any]
    yaml_export: str


@dataclass(frozen=True, slots=True)
class RemediationResult:
    """The unified per-finding output of the remediation engine.

    Every ``Finding`` fed to the orchestrator produces exactly one
    ``RemediationResult`` — no silent drops. Categories that cannot be
    remediated at runtime (LLM03, LLM04, LLM08, LLM09) still produce a
    result, with ``strategy=LOG_ONLY``, ``confidence=0.0``, and
    external-tool recommendations in ``notes``.

    Attributes:
        finding: The originating ``Finding`` from the integration bridge.
        strategy: The remediation strategy chosen for this finding.
        prompt_patch: Set when a system-prompt patch is applicable
            (LLM01, LLM07); ``None`` otherwise.
        response_sanitization: Set when an output sanitization is applied
            (LLM02, LLM05, LLM06); ``None`` otherwise.
        guardrail_config: The single, shared global guardrail config built
            from the full findings batch; attached to every result so any
            one of them can be used to retrieve the global view.
        confidence: 0.0-1.0 confidence that the remediation is appropriate.
            Derived from finding severity for in-band categories; pinned
            to 0.0 for out-of-band categories.
        notes: Free-form contextual messages (skip reasons, fallbacks,
            external-tool recommendations).
    """

    finding: Finding
    strategy: RemediationStrategy
    prompt_patch: PromptPatch | None
    response_sanitization: ResponseSanitization | None
    guardrail_config: GuardrailConfig | None
    confidence: float
    notes: list[str]
