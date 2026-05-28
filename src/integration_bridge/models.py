"""Data models for findings parsed from garak hitlogs.

Defines the canonical ``Finding`` contract shared by all downstream pipeline
stages (``remediation_engine``, ``verifier``, ``output``) and the
``OWASPCategory`` record used by the taxonomy module.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


class Severity(StrEnum):
    """Severity bucket assigned to a Finding based on attack success rate."""

    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass(frozen=True, slots=True)
class OWASPCategory:
    """A single OWASP category entry from either the LLM or Agentic Top 10.

    Attributes:
        code: Short identifier such as ``"LLM01"`` or ``"ASI03"``.
        name: Human-readable category name, e.g. ``"Prompt Injection"``.
        description: Free-form description of the category.
        framework: Either ``"LLM"`` (OWASP LLM Top 10) or ``"AGENTIC"``
            (OWASP Agentic ASI Top 10).
    """

    code: str
    name: str
    description: str
    framework: str


@dataclass(frozen=True, slots=True)
class Finding:
    """Normalized representation of a single garak hitlog record.

    Each Finding ties one successful garak attack to its OWASP context so
    downstream remediation can reason about the failure independently of
    garak's wire format.

    Attributes:
        probe_name: Garak probe identifier (e.g. ``"dan.DAN_Jailbreak"``).
        detector_name: Garak detector identifier that flagged the hit.
        attack_prompt: The prompt sent to the model under test.
        model_response: The model's response that was judged a hit.
        is_successful_attack: True when the row represents a successful
            attack. Hitlog rows are hits by definition; the field exists
            so downstream stages can filter uniformly.
        owasp_llm_category: OWASP LLM Top 10 code (e.g. ``"LLM01"``).
        owasp_agentic_categories: Zero or more OWASP Agentic codes
            (e.g. ``["ASI01", "ASI03"]``) cross-mapped from the LLM code.
        severity: One of ``"LOW"``, ``"MEDIUM"``, ``"HIGH"``, ``"CRITICAL"``,
            derived from the attack success rate for the probe.
        raw_data: The original JSONL row, preserved for forensic inspection.
    """

    probe_name: str
    detector_name: str
    attack_prompt: str
    model_response: str
    is_successful_attack: bool
    owasp_llm_category: str
    owasp_agentic_categories: list[str]
    severity: str
    raw_data: dict[str, Any]
