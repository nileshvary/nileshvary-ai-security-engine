"""Factories for ``RemediationResult`` objects used by verifier tests.

Building results directly (instead of round-tripping through Phase 3's
orchestrator) keeps the tests isolated and lets us pin specific
artifact shapes (e.g., "LLM01 with only 2 of 4 techniques present").
"""

from __future__ import annotations

from remediation_engine.models import (
    GuardrailConfig,
    PromptPatch,
    RemediationResult,
    RemediationStrategy,
    ResponseSanitization,
)

from tests.remediation_engine.fixtures.sample_findings import make_finding


_OUT_OF_BAND_NOTES: dict[str, list[str]] = {
    "LLM03": [
        "runtime remediation not applicable: supply-chain compromises must be caught before deployment",
        "recommended: model signature verification (Sigstore / cosign), HuggingFace attestations",
    ],
    "LLM04": [
        "runtime remediation not applicable: poisoning is a training-time threat",
        "recommended: backdoor detection scans (Neural Cleanse, STRIP, ABS) before deployment",
    ],
    "LLM08": [
        "runtime remediation not applicable: vector-store weaknesses require infrastructure-level controls",
        "recommended: vector-store access controls + multi-tenancy (Pinecone RBAC, Weaviate ACLs)",
    ],
    "LLM09": [
        "runtime remediation not applicable: hallucination/bias mitigation requires grounding + UX changes",
        "recommended: hallucination detection (SelfCheckGPT, FActScore)",
    ],
}

_DEFAULT_TECHNIQUES: dict[str, list[str]] = {
    "LLM01": [
        "instruction-hierarchy",
        "delimiter-tagging",
        "role-confirmation",
        "refusal-patterns",
    ],
    "LLM07": ["non-disclosure-clause", "meta-question-refusal"],
}

_DEFAULT_STRATEGY_FOR: dict[str, RemediationStrategy] = {
    "LLM01": RemediationStrategy.HARDEN,
    "LLM02": RemediationStrategy.SANITIZE,
    "LLM03": RemediationStrategy.LOG_ONLY,
    "LLM04": RemediationStrategy.LOG_ONLY,
    "LLM05": RemediationStrategy.SANITIZE,
    "LLM06": RemediationStrategy.LOG_ONLY,
    "LLM07": RemediationStrategy.HARDEN,
    "LLM08": RemediationStrategy.LOG_ONLY,
    "LLM09": RemediationStrategy.LOG_ONLY,
    "LLM10": RemediationStrategy.GUARDRAIL,
}


def _empty_guardrail_config(rate_limits: dict | None = None) -> GuardrailConfig:
    return GuardrailConfig(
        format="portkey",
        input_filters=[],
        output_filters=[],
        rate_limits=rate_limits or {},
        yaml_export="version: 1\n",
    )


def make_remediation_result(
    llm_code: str,
    severity: str = "HIGH",
    *,
    techniques: list[str] | None = None,
    detected_issues: list[str] | None = None,
    actions_taken: list[str] | None = None,
    rate_limits: dict[str, int] | None = None,
    include_patch: bool = True,
    include_sanitization: bool = True,
    include_guardrail: bool = True,
    notes: list[str] | None = None,
    confidence: float | None = None,
) -> RemediationResult:
    """Build a ``RemediationResult`` for testing the verifier.

    Args:
        llm_code: The finding's OWASP LLM category.
        severity: Severity for the underlying finding.
        techniques: Override the patch's ``injection_resistance_techniques``.
            Defaults to the full canonical list for LLM01/LLM07.
        detected_issues: Override the sanitization's detected issues.
        actions_taken: Override the sanitization's actions taken.
        rate_limits: Rate-limit dict to put on the guardrail config.
            Defaults to a populated map for LLM10, empty otherwise.
        include_patch: If False, ``prompt_patch`` is ``None``
            (simulates the orchestrator's LOG_ONLY downgrade).
        include_sanitization: If False, ``response_sanitization`` is
            ``None``.
        include_guardrail: If False, ``guardrail_config`` is ``None``.
        notes: Override the notes list. Defaults to the out-of-band
            recommendation list for LLM03/04/08/09, ``[]`` otherwise.
        confidence: Override the per-result confidence. Defaults to
            ``0.0`` for out-of-band, ``0.85`` for in-band HIGH severity.
    """
    finding = make_finding(llm_code, severity=severity)
    strategy = _DEFAULT_STRATEGY_FOR.get(llm_code, RemediationStrategy.LOG_ONLY)

    if include_patch and llm_code in {"LLM01", "LLM07"}:
        patch_techniques = (
            techniques if techniques is not None else list(_DEFAULT_TECHNIQUES[llm_code])
        )
        prompt_patch = PromptPatch(
            original_prompt="You are a helpful assistant.",
            patched_prompt="<<patched>> You are a helpful assistant.",
            patch_explanation=f"patch for {llm_code}",
            injection_resistance_techniques=patch_techniques,
        )
    else:
        prompt_patch = None

    if include_sanitization and llm_code in {"LLM02", "LLM05", "LLM06"}:
        d_issues = (
            detected_issues
            if detected_issues is not None
            else ["sample issue detected"]
        )
        a_taken = (
            actions_taken
            if actions_taken is not None
            else (
                []
                if llm_code == "LLM06"
                else ["sample action taken"]
            )
        )
        sanitization = ResponseSanitization(
            original_response=finding.model_response,
            sanitized_response=finding.model_response,
            detected_issues=d_issues,
            actions_taken=a_taken,
        )
    else:
        sanitization = None

    if include_guardrail:
        rl = rate_limits
        if rl is None:
            rl = (
                {"requests_per_minute": 60, "tokens_per_minute": 100_000}
                if llm_code == "LLM10"
                else {}
            )
        guardrail = _empty_guardrail_config(rl)
    else:
        guardrail = None

    if notes is None:
        notes = list(_OUT_OF_BAND_NOTES.get(llm_code, []))

    if confidence is None:
        confidence = 0.0 if llm_code in _OUT_OF_BAND_NOTES else 0.85

    return RemediationResult(
        finding=finding,
        strategy=strategy,
        prompt_patch=prompt_patch,
        response_sanitization=sanitization,
        guardrail_config=guardrail,
        confidence=confidence,
        notes=notes,
    )


def all_category_results() -> list[RemediationResult]:
    """Return exactly 10 ``RemediationResult``s, one per LLM01..LLM10."""
    return [make_remediation_result(f"LLM{i:02d}") for i in range(1, 11)]
