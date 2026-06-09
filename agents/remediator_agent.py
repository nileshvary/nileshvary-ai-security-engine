"""Agent 2 — Remediator: applies fixes and generates guardrails for each Finding.

This is the second stage of the RemediAX v2.0 pipeline:

    Scanner → findings.json → Remediator → remediation_results.json → Reporter

The RemediatorAgent wraps the existing ``src/remediation_engine/`` package
(already fully built and tested) and optionally enriches results with LLM Guard
and NeMo Guardrails via dependency injection.

Connection to Agent 1 (two modes):

Mode A — direct object passing (in-process):
    findings = scanner_agent.scan()
    results  = remediator_agent.remediate(findings)

Mode B — JSON handoff (decoupled / CI):
    findings = ScannerAgent.load_findings("artifacts/findings.json")
    results  = remediator_agent.remediate(findings)
    remediator_agent.save_results(results, "artifacts/remediation_results.json")
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Ensure src/ is on the path for remediation_engine imports
_SRC = Path(__file__).parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))


class RemediatorAgent:
    """Coordinate LLM Guard, NeMo, Claude API, and the remediation engine for each finding.

    Args:
        llmguard_runner: Optional ``LLMGuardRunner`` instance. When provided,
                         each finding is scanned for injection/bypass patterns
                         before remediation.
        nemo_runner:     Optional ``NemoRunner`` instance. When provided, a NeMo
                         Guardrails ``config.yml`` is generated and saved alongside
                         the remediation results.
        config:          Optional ``Config`` instance.  Defaults to ``Config()``.
        guardrail_format: Vendor format for the guardrail YAML — one of
                         ``"portkey"``, ``"litellm"``, ``"generic"``.
                         Defaults to ``"generic"`` (vendor-neutral).
        nemo_output_path: Where to save the NeMo config YAML when
                          ``nemo_runner`` is provided.
        ai_client:       Optional ``RemediAXAI`` instance. When supplied,
                         Claude generates custom guardrail patterns per finding
                         on top of the hardcoded deterministic rules.
        anthropic_api_key: Convenience shortcut — if ``ai_client`` is not given
                           but this key is provided, a ``RemediAXAI`` client is
                           constructed automatically. Ignored when ``ai_client``
                           is already set.
    """

    def __init__(
        self,
        llmguard_runner: Any | None = None,
        nemo_runner: Any | None = None,
        config: Any | None = None,
        guardrail_format: str = "generic",
        nemo_output_path: str = "artifacts/nemo_guardrails.yaml",
        ai_client: Any | None = None,
        anthropic_api_key: str | None = None,
    ) -> None:
        self._llmguard = llmguard_runner
        self._nemo = nemo_runner
        self._config = config
        self._guardrail_format = guardrail_format
        self._nemo_output_path = Path(nemo_output_path)

        if ai_client is not None:
            self._ai_client = ai_client
        elif anthropic_api_key:
            from components.ai_client import RemediAXAI
            self._ai_client = RemediAXAI(api_key=anthropic_api_key)
        else:
            self._ai_client = None

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def remediate(
        self,
        findings: list[Any],
        original_system_prompt: str = "",
    ) -> list[Any]:
        """Produce one RemediationResult per Finding.

        Args:
            findings: List of ``schemas.finding.Finding`` objects from Agent 1.
            original_system_prompt: The caller's system prompt; required for
                                    LLM01 / LLM07 patch generation.

        Returns:
            List of ``RemediationResult`` objects, one per input finding.
        """
        if not findings:
            logger.info("RemediatorAgent: no findings to remediate")
            return []

        # Optional: LLM Guard enrichment scan
        if self._llmguard is not None:
            try:
                llmguard_results = self._llmguard.scan_findings(findings)
                logger.info(
                    "RemediatorAgent: LLM Guard scanned %d findings, "
                    "%d flagged by input scanner, %d flagged by output scanner",
                    len(llmguard_results),
                    sum(1 for r in llmguard_results if not r.get("input_is_valid", True)),
                    sum(1 for r in llmguard_results if not r.get("output_is_valid", True)),
                )
            except Exception as exc:
                logger.warning("RemediatorAgent: LLM Guard scan failed, continuing: %s", exc)

        # Optional: NeMo Guardrails config generation
        if self._nemo is not None:
            try:
                nemo_config = self._nemo.generate_config(findings)
                self._nemo.save_config(nemo_config, self._nemo_output_path)
                logger.info("RemediatorAgent: NeMo config saved to %s", self._nemo_output_path)
            except Exception as exc:
                logger.warning("RemediatorAgent: NeMo config generation failed, continuing: %s", exc)

        # Core remediation via existing RemediationOrchestrator
        from remediation_engine.orchestrator import RemediationOrchestrator

        orchestrator = RemediationOrchestrator(
            guardrail_format=self._guardrail_format,
            ai_client=self._ai_client,
        )
        results = orchestrator.remediate_findings(
            findings,
            original_prompt=original_system_prompt or None,
        )

        logger.info(
            "RemediatorAgent: produced %d RemediationResult(s) for %d finding(s)",
            len(results),
            len(findings),
        )
        return results

    def save_results(
        self,
        results: list[Any],
        output_path: str | Path,
    ) -> Path:
        """Serialize RemediationResults to JSON.

        Args:
            results: The list returned by ``remediate()``.
            output_path: File path (or directory — ``remediation_results.json``
                         is appended when a directory is given).

        Returns:
            The resolved ``Path`` that was written.
        """
        dest = Path(output_path)
        if dest.is_dir():
            dest = dest / "remediation_results.json"

        dest.parent.mkdir(parents=True, exist_ok=True)
        payload = [_result_to_dict(r) for r in results]
        dest.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        logger.info("RemediatorAgent: wrote %d results to %s", len(results), dest)
        return dest

    @staticmethod
    def load_results(source_path: str | Path) -> list[Any]:
        """Load results previously written by ``save_results()``.

        Args:
            source_path: Path to a ``remediation_results.json`` file.

        Returns:
            List of ``RemediationResult`` objects.
        """
        from schemas.finding import Finding
        from remediation_engine.models import (
            GuardrailConfig,
            PromptPatch,
            RemediationResult,
            RemediationStrategy,
            ResponseSanitization,
        )

        raw_list = json.loads(Path(source_path).read_text(encoding="utf-8"))
        results: list[Any] = []

        for item in raw_list:
            finding = Finding.from_dict(item["finding"])

            prompt_patch = None
            if item.get("prompt_patch"):
                pp = item["prompt_patch"]
                prompt_patch = PromptPatch(
                    original_prompt=pp["original_prompt"],
                    patched_prompt=pp["patched_prompt"],
                    patch_explanation=pp["patch_explanation"],
                    injection_resistance_techniques=list(pp["injection_resistance_techniques"]),
                )

            response_san = None
            if item.get("response_sanitization"):
                rs = item["response_sanitization"]
                response_san = ResponseSanitization(
                    original_response=rs["original_response"],
                    sanitized_response=rs["sanitized_response"],
                    detected_issues=list(rs["detected_issues"]),
                    actions_taken=list(rs["actions_taken"]),
                )

            guardrail_config = None
            if item.get("guardrail_config"):
                gc = item["guardrail_config"]
                guardrail_config = GuardrailConfig(
                    format=gc["format"],
                    input_filters=gc.get("input_filters", []),
                    output_filters=gc.get("output_filters", []),
                    rate_limits=gc.get("rate_limits", {}),
                    yaml_export=gc["yaml_export"],
                )

            results.append(
                RemediationResult(
                    finding=finding,
                    strategy=RemediationStrategy(item["strategy"]),
                    prompt_patch=prompt_patch,
                    response_sanitization=response_san,
                    guardrail_config=guardrail_config,
                    confidence=float(item["confidence"]),
                    notes=list(item.get("notes", [])),
                )
            )

        logger.info("RemediatorAgent: loaded %d results from %s", len(results), source_path)
        return results


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------

def _result_to_dict(result: Any) -> dict[str, Any]:
    """Serialize a RemediationResult to a JSON-safe dict."""
    finding = result.finding

    if hasattr(finding, "to_dict"):
        finding_dict = finding.to_dict()
    else:
        finding_dict = {
            "probe_name": finding.probe_name,
            "detector_name": finding.detector_name,
            "attack_prompt": finding.attack_prompt,
            "model_response": finding.model_response,
            "is_successful_attack": finding.is_successful_attack,
            "owasp_llm_category": finding.owasp_llm_category,
            "owasp_agentic_categories": list(finding.owasp_agentic_categories),
            "severity": finding.severity,
            "source": getattr(finding, "source", "garak"),
            "raw_data": dict(finding.raw_data) if finding.raw_data else {},
        }

    patch_dict = None
    if result.prompt_patch is not None:
        pp = result.prompt_patch
        patch_dict = {
            "original_prompt": pp.original_prompt,
            "patched_prompt": pp.patched_prompt,
            "patch_explanation": pp.patch_explanation,
            "injection_resistance_techniques": list(pp.injection_resistance_techniques),
        }

    san_dict = None
    if result.response_sanitization is not None:
        rs = result.response_sanitization
        san_dict = {
            "original_response": rs.original_response,
            "sanitized_response": rs.sanitized_response,
            "detected_issues": list(rs.detected_issues),
            "actions_taken": list(rs.actions_taken),
        }

    gc_dict = None
    if result.guardrail_config is not None:
        gc = result.guardrail_config
        gc_dict = {
            "format": gc.format,
            "input_filters": gc.input_filters,
            "output_filters": gc.output_filters,
            "rate_limits": gc.rate_limits,
            "yaml_export": gc.yaml_export,
        }

    strategy = result.strategy
    strategy_str = strategy.value if hasattr(strategy, "value") else str(strategy)

    return {
        "finding": finding_dict,
        "strategy": strategy_str,
        "prompt_patch": patch_dict,
        "response_sanitization": san_dict,
        "guardrail_config": gc_dict,
        "confidence": result.confidence,
        "notes": list(result.notes),
    }
