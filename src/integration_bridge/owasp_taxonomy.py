"""OWASP LLM Top 10 (2025) and OWASP Agentic Top 10 (ASI) reference taxonomy.

This module exposes two ``dict[str, OWASPCategory]`` constants — ``LLM_TOP_10``
and ``AGENTIC_TOP_10`` — plus convenience lookup helpers. The taxonomy is the
single source of truth used by ``owasp_mapper`` and consumed by every
downstream pipeline stage.
"""

from __future__ import annotations

from integration_bridge.models import OWASPCategory

_LLM = "LLM"
_AGENTIC = "AGENTIC"


LLM_TOP_10: dict[str, OWASPCategory] = {
    "LLM01": OWASPCategory(
        code="LLM01",
        name="Prompt Injection",
        description="Manipulating LLM behavior through crafted inputs.",
        framework=_LLM,
    ),
    "LLM02": OWASPCategory(
        code="LLM02",
        name="Sensitive Information Disclosure",
        description="Exposure of PII, credentials, or proprietary data.",
        framework=_LLM,
    ),
    "LLM03": OWASPCategory(
        code="LLM03",
        name="Supply Chain",
        description="Compromised models, datasets, or dependencies.",
        framework=_LLM,
    ),
    "LLM04": OWASPCategory(
        code="LLM04",
        name="Data and Model Poisoning",
        description="Malicious training data and backdoor attacks.",
        framework=_LLM,
    ),
    "LLM05": OWASPCategory(
        code="LLM05",
        name="Improper Output Handling",
        description="Insufficient validation of LLM-generated content.",
        framework=_LLM,
    ),
    "LLM06": OWASPCategory(
        code="LLM06",
        name="Excessive Agency",
        description="Unchecked autonomous AI agent permissions.",
        framework=_LLM,
    ),
    "LLM07": OWASPCategory(
        code="LLM07",
        name="System Prompt Leakage",
        description="Exposure of sensitive system prompts.",
        framework=_LLM,
    ),
    "LLM08": OWASPCategory(
        code="LLM08",
        name="Vector and Embedding Weaknesses",
        description="RAG-specific vulnerabilities in vector stores and embeddings.",
        framework=_LLM,
    ),
    "LLM09": OWASPCategory(
        code="LLM09",
        name="Misinformation",
        description="Hallucination, bias, and overreliance risks.",
        framework=_LLM,
    ),
    "LLM10": OWASPCategory(
        code="LLM10",
        name="Unbounded Consumption",
        description="Resource exhaustion and economic attacks.",
        framework=_LLM,
    ),
}


AGENTIC_TOP_10: dict[str, OWASPCategory] = {
    "ASI01": OWASPCategory(
        code="ASI01",
        name="Agent Goal Hijack",
        description="[CRITICAL] Redirecting agent objectives via prompt injection.",
        framework=_AGENTIC,
    ),
    "ASI02": OWASPCategory(
        code="ASI02",
        name="Tool Misuse & Exploitation",
        description="[CRITICAL] Agents misusing legitimate tools.",
        framework=_AGENTIC,
    ),
    "ASI03": OWASPCategory(
        code="ASI03",
        name="Identity & Privilege Abuse",
        description="[CRITICAL] Exploiting credentials or permissions.",
        framework=_AGENTIC,
    ),
    "ASI04": OWASPCategory(
        code="ASI04",
        name="Agentic Supply Chain",
        description="[HIGH] Malicious or tampered tools, descriptors, or models.",
        framework=_AGENTIC,
    ),
    "ASI05": OWASPCategory(
        code="ASI05",
        name="Unexpected Code Execution",
        description="[HIGH] Agents executing attacker-controlled code.",
        framework=_AGENTIC,
    ),
    "ASI06": OWASPCategory(
        code="ASI06",
        name="Memory & Context Poisoning",
        description="[HIGH] Persistent corruption of agent memory or RAG context.",
        framework=_AGENTIC,
    ),
    "ASI07": OWASPCategory(
        code="ASI07",
        name="Insecure Inter-Agent Communication",
        description="[HIGH] Spoofed inter-agent messages.",
        framework=_AGENTIC,
    ),
    "ASI08": OWASPCategory(
        code="ASI08",
        name="Cascading Failures",
        description="[MEDIUM] False signals cascading through pipelines.",
        framework=_AGENTIC,
    ),
    "ASI09": OWASPCategory(
        code="ASI09",
        name="Human-Agent Trust Exploitation",
        description="[MEDIUM] Polished outputs misleading operators.",
        framework=_AGENTIC,
    ),
    "ASI10": OWASPCategory(
        code="ASI10",
        name="Rogue Agents",
        description="[CRITICAL] Compromised or misaligned agents.",
        framework=_AGENTIC,
    ),
}


def get_llm_category(code: str) -> OWASPCategory:
    """Return the ``OWASPCategory`` for the given LLM code.

    Args:
        code: An OWASP LLM Top 10 code such as ``"LLM01"``.

    Returns:
        The matching ``OWASPCategory``.

    Raises:
        KeyError: If ``code`` is not a known LLM Top 10 entry.
    """
    return LLM_TOP_10[code]


def get_agentic_category(code: str) -> OWASPCategory:
    """Return the ``OWASPCategory`` for the given Agentic ASI code.

    Args:
        code: An OWASP Agentic Top 10 code such as ``"ASI03"``.

    Returns:
        The matching ``OWASPCategory``.

    Raises:
        KeyError: If ``code`` is not a known Agentic Top 10 entry.
    """
    return AGENTIC_TOP_10[code]


def all_llm_categories() -> list[OWASPCategory]:
    """Return all ten OWASP LLM Top 10 entries in code order."""
    return list(LLM_TOP_10.values())


def all_agentic_categories() -> list[OWASPCategory]:
    """Return all ten OWASP Agentic Top 10 entries in code order."""
    return list(AGENTIC_TOP_10.values())
