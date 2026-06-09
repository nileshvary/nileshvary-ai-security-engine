"""Routes findings to the appropriate remediation modules and builds results.

The orchestrator is the single entry point for Phase 3. It:

1. Generates one global ``GuardrailConfig`` from the full findings batch.
2. Dispatches each finding to the appropriate remediator based on its
   OWASP LLM category (see ``_ROUTING_TABLE``).
3. Computes a confidence score from finding severity, with a hard
   override to ``0.0`` for the four out-of-band categories
   (LLM03, LLM04, LLM08, LLM09).
4. Returns one ``RemediationResult`` per input finding — never drops.
"""

from __future__ import annotations

import logging
from typing import Any, Final

from integration_bridge.models import Finding

from remediation_engine.guardrail_generator.generator import GuardrailGenerator
from remediation_engine.models import (
    GuardrailConfig,
    PromptPatch,
    RemediationResult,
    RemediationStrategy,
    ResponseSanitization,
)
from remediation_engine.prompt_remediator.remediator import PromptRemediator
from remediation_engine.response_remediator.remediator import ResponseRemediator

logger = logging.getLogger(__name__)


_SEVERITY_TO_CONFIDENCE: Final[dict[str, float]] = {
    "CRITICAL": 0.95,
    "HIGH": 0.85,
    "MEDIUM": 0.70,
    "LOW": 0.50,
}
_DEFAULT_CONFIDENCE: Final[float] = 0.50

_PROMPT_CATEGORIES: Final[frozenset[str]] = frozenset({"LLM01", "LLM07"})
_RESPONSE_CATEGORIES: Final[frozenset[str]] = frozenset({"LLM02", "LLM05", "LLM06"})
_GUARDRAIL_CATEGORIES: Final[frozenset[str]] = frozenset({"LLM10"})
_OUT_OF_BAND_CATEGORIES: Final[frozenset[str]] = frozenset({"LLM03", "LLM04", "LLM08", "LLM09"})

_STRATEGY_BY_CATEGORY: Final[dict[str, RemediationStrategy]] = {
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

_OUT_OF_BAND_NOTES: Final[dict[str, list[str]]] = {
    "LLM03": [
        "runtime remediation not applicable: supply-chain compromises must be caught before deployment",
        "recommended: model signature verification (Sigstore / cosign), HuggingFace attestations",
        "recommended: dependency scanning (pip-audit, Snyk, Dependabot)",
        "recommended: ML-BOM / SBOM tracking (CycloneDX, SPDX)",
    ],
    "LLM04": [
        "runtime remediation not applicable: poisoning is a training-time threat",
        "recommended: dataset provenance + hashing, data lineage tracking (MLflow, DVC)",
        "recommended: backdoor detection scans (Neural Cleanse, STRIP, ABS) before deployment",
        "recommended: differential-privacy training (Opacus, TF Privacy) for sensitive corpora",
    ],
    "LLM08": [
        "runtime remediation not applicable: vector-store weaknesses require infrastructure-level controls",
        "recommended: vector-store access controls + multi-tenancy (Pinecone RBAC, Weaviate ACLs)",
        "recommended: RAG observability + retrieval auditing (Langfuse, LangSmith)",
        "recommended: encrypted embeddings / private retrieval for sensitive corpora",
    ],
    "LLM09": [
        "runtime remediation not applicable: hallucination/bias mitigation requires grounding + UX changes",
        "recommended: grounded generation with citation requirements (RAG with verified sources)",
        "recommended: hallucination detection (SelfCheckGPT, FActScore)",
        "recommended: bias evaluation suites (BBQ, BOLD, StereoSet) in pre-deployment testing",
        "recommended: UX cues that signal model uncertainty to end users",
    ],
}


def _confidence_for(finding: Finding) -> float:
    """Return the confidence score for a finding based on its severity."""
    if finding.owasp_llm_category in _OUT_OF_BAND_CATEGORIES:
        return 0.0
    return _SEVERITY_TO_CONFIDENCE.get(finding.severity, _DEFAULT_CONFIDENCE)


class RemediationOrchestrator:
    """Routes findings to remediators and produces unified ``RemediationResult`` objects."""

    def __init__(
        self,
        prompt_remediator: PromptRemediator | None = None,
        response_remediator: ResponseRemediator | None = None,
        guardrail_generator: GuardrailGenerator | None = None,
        guardrail_format: str = "portkey",
        ai_client: Any | None = None,
    ) -> None:
        """Initialize the orchestrator.

        Args:
            prompt_remediator: Optional ``PromptRemediator`` instance;
                defaults to a fresh one.
            response_remediator: Optional ``ResponseRemediator`` instance;
                defaults to a fresh one.
            guardrail_generator: Optional ``GuardrailGenerator`` instance;
                defaults to a fresh one.
            guardrail_format: One of ``"portkey"``, ``"litellm"``,
                ``"generic"`` — the format used when building the global
                guardrail config.
            ai_client: Optional ``RemediAXAI`` instance. When supplied,
                ``GuardrailGenerator`` calls Claude per finding to produce
                custom guardrail patterns on top of the hardcoded rules.
        """
        self.prompt_remediator = prompt_remediator or PromptRemediator()
        self.response_remediator = response_remediator or ResponseRemediator()
        self.guardrail_generator = guardrail_generator or GuardrailGenerator()
        self.guardrail_format = guardrail_format
        self.ai_client = ai_client

    def remediate_findings(
        self,
        findings: list[Finding],
        original_prompt: str | None = None,
    ) -> list[RemediationResult]:
        """Produce one ``RemediationResult`` per input ``Finding``.

        Args:
            findings: The batch of findings to remediate. May be empty.
            original_prompt: The caller's system prompt; required for
                LLM01 / LLM07 patching. When ``None``, those findings are
                downgraded to ``LOG_ONLY`` with a note explaining the
                skip (no exception raised).

        Returns:
            A list of ``RemediationResult`` of the same length as
            ``findings``. Every result carries the same global
            ``guardrail_config`` instance.
        """
        global_config: GuardrailConfig = self.guardrail_generator.generate(
            findings, self.guardrail_format, ai_client=self.ai_client
        )

        results: list[RemediationResult] = []
        for finding in findings:
            results.append(self._remediate_one(finding, original_prompt, global_config))
        logger.info(
            "Produced %d RemediationResult(s) for %d finding(s)",
            len(results),
            len(findings),
        )
        return results

    def _remediate_one(
        self,
        finding: Finding,
        original_prompt: str | None,
        global_config: GuardrailConfig,
    ) -> RemediationResult:
        """Build a single ``RemediationResult`` for one finding."""
        category = finding.owasp_llm_category
        strategy = _STRATEGY_BY_CATEGORY.get(category, RemediationStrategy.LOG_ONLY)
        confidence = _confidence_for(finding)
        notes: list[str] = []
        prompt_patch: PromptPatch | None = None
        response_sanitization: ResponseSanitization | None = None

        if category in _OUT_OF_BAND_CATEGORIES:
            notes.extend(_OUT_OF_BAND_NOTES[category])
            logger.info(
                "Out-of-band category %s for probe '%s' — strategy=LOG_ONLY, confidence=0.0",
                category,
                finding.probe_name,
            )
        elif category in _PROMPT_CATEGORIES:
            if original_prompt is None:
                strategy = RemediationStrategy.LOG_ONLY
                notes.append("prompt patch skipped: no original_prompt provided")
                logger.warning(
                    "%s finding for probe '%s' downgraded to LOG_ONLY: "
                    "no original_prompt supplied to remediate_findings()",
                    category,
                    finding.probe_name,
                )
            else:
                prompt_patch = self.prompt_remediator.patch_prompt(finding, original_prompt)
                logger.info(
                    "%s finding for probe '%s' patched (strategy=HARDEN)",
                    category,
                    finding.probe_name,
                )
        elif category in _RESPONSE_CATEGORIES:
            response_sanitization = self.response_remediator.sanitize_response(
                finding, finding.model_response
            )
            logger.info(
                "%s finding for probe '%s' sanitized (strategy=%s)",
                category,
                finding.probe_name,
                strategy.value,
            )
        elif category in _GUARDRAIL_CATEGORIES:
            logger.info(
                "%s finding for probe '%s' handled by global guardrail config",
                category,
                finding.probe_name,
            )
        else:
            notes.append(f"unknown OWASP category {category!r}; defaulted to LOG_ONLY")
            logger.warning("Unknown OWASP category %r for probe '%s'", category, finding.probe_name)

        logger.debug(
            "Routing decision: category=%s strategy=%s confidence=%.2f",
            category,
            strategy.value,
            confidence,
        )

        return RemediationResult(
            finding=finding,
            strategy=strategy,
            prompt_patch=prompt_patch,
            response_sanitization=response_sanitization,
            guardrail_config=global_config,
            confidence=confidence,
            notes=notes,
        )
