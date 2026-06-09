"""Agent 1 — Scanner: runs Garak and PyRIT, normalizes results to Finding objects.

This is the first stage in the RemediAX v2.0 pipeline:

    Scanner → findings.json → Remediator → Reporter → Verifier

The ScannerAgent accepts an already-constructed GarakRunner and/or
PyRITRunner (dependency injection), so each scanner can be mocked in tests
without touching the file system or spawning subprocesses.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from schemas.finding import Finding

logger = logging.getLogger(__name__)


class ScannerAgent:
    """Coordinate Garak and PyRIT scanners and emit normalized Finding objects.

    Args:
        garak_runner: An optional GarakRunner instance. If provided,
                      ``scan()`` will include Garak findings.
        pyrit_runner: An optional PyRITRunner instance. If provided,
                      ``scan()`` will include PyRIT multi-turn findings.
    """

    def __init__(
        self,
        garak_runner: Any | None = None,
        pyrit_runner: Any | None = None,
    ) -> None:
        self._garak = garak_runner
        self._pyrit = pyrit_runner

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def scan(
        self,
        garak_probes: list[str] | None = None,
        pyrit_probes: list[dict[str, str]] | None = None,
        pyrit_max_turns: int = 5,
    ) -> list[Finding]:
        """Run all enabled scanners and return a unified finding list.

        Args:
            garak_probes: Garak probe families (e.g. ``["dan", "promptleak"]``).
                          Passed through to GarakRunner. ``None`` means all probes.
            pyrit_probes: PyRIT probe definitions. ``None`` uses
                          ``tools.pyrit_runner.DEFAULT_PROBES``.
            pyrit_max_turns: Max conversation turns per PyRIT probe.

        Returns:
            List of ``Finding`` objects from all active scanners, deduped by
            (probe_name, attack_prompt) pair.
        """
        findings: list[Finding] = []

        if self._garak is not None:
            findings.extend(self._run_garak(garak_probes))

        if self._pyrit is not None:
            findings.extend(self._run_pyrit(pyrit_probes, pyrit_max_turns))

        return self._deduplicate(findings)

    def save_findings(self, findings: list[Finding], output_path: str | Path) -> Path:
        """Serialize findings to ``findings.json``.

        Args:
            findings: The list returned by ``scan()``.
            output_path: File path (or directory — ``findings.json`` is
                         appended when a directory is given).

        Returns:
            The resolved ``Path`` that was written.
        """
        dest = Path(output_path)
        if dest.is_dir():
            dest = dest / "findings.json"

        dest.parent.mkdir(parents=True, exist_ok=True)
        payload = [f.to_dict() for f in findings]
        dest.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        logger.info("Wrote %d findings to %s", len(findings), dest)
        return dest

    @staticmethod
    def load_findings(source_path: str | Path) -> list[Finding]:
        """Load findings previously written by ``save_findings()``.

        Args:
            source_path: Path to a ``findings.json`` file.

        Returns:
            List of ``Finding`` objects.
        """
        raw = json.loads(Path(source_path).read_text(encoding="utf-8"))
        return [Finding.from_dict(item) for item in raw]

    # ------------------------------------------------------------------ #
    #  Private helpers                                                     #
    # ------------------------------------------------------------------ #

    def _run_garak(self, probes: list[str] | None) -> list[Finding]:
        """Run GarakRunner and convert results to Finding objects."""
        try:
            from src.integration_bridge.parser import GarakParser
            from src.integration_bridge.models import Finding as BridgeFinding
        except ImportError:
            logger.warning("integration_bridge not importable — skipping Garak")
            return []

        raw_findings: list[BridgeFinding] = []
        try:
            # GarakRunner.run_scan() is a generator; consume it all
            run_gen = self._garak.run_scan(probes=probes)
            # Depending on GarakRunner version, result may be a list or generator
            if hasattr(run_gen, "__iter__"):
                raw_findings = list(run_gen)
            else:
                raw_findings = run_gen or []
        except Exception as exc:
            logger.error("Garak scan failed: %s", exc)
            return []

        return [self._bridge_to_schema(f) for f in raw_findings]

    def _run_pyrit(
        self,
        probes: list[dict[str, str]] | None,
        max_turns: int,
    ) -> list[Finding]:
        """Run PyRITRunner and convert raw dicts to Finding objects."""
        try:
            raw_results = self._pyrit.run_scan(
                probes=probes, max_turns=max_turns
            )
        except Exception as exc:
            logger.error("PyRIT scan failed: %s", exc)
            return []

        return [self._pyrit_dict_to_finding(r) for r in raw_results]

    @staticmethod
    def _bridge_to_schema(bridge_finding: Any) -> Finding:
        """Convert an integration_bridge Finding to a schemas Finding."""
        return Finding(
            probe_name=bridge_finding.probe_name,
            detector_name=bridge_finding.detector_name,
            attack_prompt=bridge_finding.attack_prompt,
            model_response=bridge_finding.model_response,
            is_successful_attack=bridge_finding.is_successful_attack,
            owasp_llm_category=bridge_finding.owasp_llm_category,
            owasp_agentic_categories=list(bridge_finding.owasp_agentic_categories),
            severity=bridge_finding.severity,
            source="garak",
            raw_data=dict(bridge_finding.raw_data),
        )

    @staticmethod
    def _pyrit_dict_to_finding(raw: dict[str, Any]) -> Finding:
        """Convert a PyRITRunner result dict to a schemas Finding.

        Agentic codes come from two sources (merged, deduped):
        1. ``raw["agentic"]`` — codes declared in the probe definition itself
           (for ASI categories that don't cross-map from any LLM code).
        2. ``OwaspMapper.map_llm_to_agentic(llm_code)`` — standard LLM→ASI
           cross-map for codes that do have an established mapping.
        """
        try:
            from integration_bridge.owasp_mapper import OwaspMapper
        except ImportError:
            OwaspMapper = None  # type: ignore[assignment,misc]

        llm_code = raw.get("owasp", "LLM01")
        direct_agentic: list[str] = raw.get("agentic", [])

        if OwaspMapper is not None:
            cross_mapped = OwaspMapper.map_llm_to_agentic(llm_code)
        else:
            cross_mapped = []

        merged: list[str] = []
        for code in (*direct_agentic, *cross_mapped):
            if code not in merged:
                merged.append(code)

        return Finding(
            probe_name=raw["probe_name"],
            detector_name="pyrit.HeuristicDetector",
            attack_prompt=raw["attack_prompt"],
            model_response=raw["model_response"],
            is_successful_attack=raw.get("is_successful_attack", False),
            owasp_llm_category=llm_code,
            owasp_agentic_categories=merged,
            severity="MEDIUM",
            source="pyrit",
            raw_data=raw,
        )

    @staticmethod
    def _deduplicate(findings: list[Finding]) -> list[Finding]:
        """Remove duplicate findings by (probe_name, attack_prompt)."""
        seen: set[tuple[str, str]] = set()
        unique: list[Finding] = []
        for f in findings:
            key = (f.probe_name, f.attack_prompt)
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
