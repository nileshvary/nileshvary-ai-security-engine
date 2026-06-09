"""Unified Finding dataclass for the RemediAX v2.0 agent pipeline.

Every scanner agent (Garak, PyRIT) normalizes its results into this
schema before passing findings downstream to the Remediator, Reporter,
and Verifier agents.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Finding:
    """A single normalized vulnerability finding from any scanner.

    Attributes:
        probe_name: Scanner probe or attack identifier.
        detector_name: Detector or classifier that flagged the response.
        attack_prompt: The prompt sent to the target model.
        model_response: The model's response to the attack.
        is_successful_attack: True when the attack succeeded.
        owasp_llm_category: OWASP LLM Top 10 code (e.g. ``"LLM07"``).
        owasp_agentic_categories: ASI Agentic Top 10 codes (e.g. ``["ASI01"]``).
        severity: One of ``LOW``, ``MEDIUM``, ``HIGH``, ``CRITICAL``.
        source: Scanner that produced this finding (``"garak"`` or ``"pyrit"``).
        raw_data: Original scanner output preserved for forensics.
    """

    probe_name: str
    detector_name: str
    attack_prompt: str
    model_response: str
    is_successful_attack: bool
    owasp_llm_category: str
    owasp_agentic_categories: list[str] = field(default_factory=list)
    severity: str = "MEDIUM"
    source: str = "garak"
    raw_data: dict[str, Any] = field(default_factory=dict)

    # Severity constants
    LOW: str = field(default="LOW", init=False, repr=False, compare=False)
    MEDIUM: str = field(default="MEDIUM", init=False, repr=False, compare=False)
    HIGH: str = field(default="HIGH", init=False, repr=False, compare=False)
    CRITICAL: str = field(default="CRITICAL", init=False, repr=False, compare=False)

    VALID_SEVERITIES: tuple[str, ...] = field(
        default=("LOW", "MEDIUM", "HIGH", "CRITICAL"),
        init=False,
        repr=False,
        compare=False,
    )
    VALID_SOURCES: tuple[str, ...] = field(
        default=("garak", "pyrit", "manual"),
        init=False,
        repr=False,
        compare=False,
    )

    def __post_init__(self) -> None:
        """Validate severity and source values."""
        if self.severity not in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
            raise ValueError(
                f"severity must be one of LOW/MEDIUM/HIGH/CRITICAL, got {self.severity!r}"
            )
        if self.owasp_llm_category and not self.owasp_llm_category.startswith("LLM"):
            raise ValueError(
                f"owasp_llm_category must start with 'LLM', got {self.owasp_llm_category!r}"
            )

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a plain dict (JSON-safe).

        Returns:
            Dict with all public fields serialized.
        """
        return {
            "probe_name": self.probe_name,
            "detector_name": self.detector_name,
            "attack_prompt": self.attack_prompt,
            "model_response": self.model_response,
            "is_successful_attack": self.is_successful_attack,
            "owasp_llm_category": self.owasp_llm_category,
            "owasp_agentic_categories": self.owasp_agentic_categories,
            "severity": self.severity,
            "source": self.source,
            "raw_data": self.raw_data,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Finding:
        """Deserialize from a plain dict.

        Args:
            data: Dict previously produced by ``to_dict()``.

        Returns:
            A new ``Finding`` instance.
        """
        return cls(
            probe_name=data["probe_name"],
            detector_name=data["detector_name"],
            attack_prompt=data["attack_prompt"],
            model_response=data["model_response"],
            is_successful_attack=data["is_successful_attack"],
            owasp_llm_category=data["owasp_llm_category"],
            owasp_agentic_categories=data.get("owasp_agentic_categories", []),
            severity=data.get("severity", "MEDIUM"),
            source=data.get("source", "garak"),
            raw_data=data.get("raw_data", {}),
        )
