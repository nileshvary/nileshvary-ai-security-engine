"""Maps garak probe names to OWASP LLM and OWASP Agentic categories.

The mapping table uses ``fnmatch`` glob patterns. Entries are evaluated in
declaration order, so more specific patterns (e.g. exact probe names) must
appear before broader ones (e.g. ``"lmrc.*"``). The first matching entry wins.
"""

from __future__ import annotations

import logging
from fnmatch import fnmatchcase

logger = logging.getLogger(__name__)


_PROBE_TO_LLM: tuple[tuple[str, str], ...] = (
    # ── Exact matches FIRST (must precede any glob that would match) ──
    ("lmrc.QuackMedicine", "LLM09"),
    # atkgen specific overrides per product spec — these must appear
    # before the broad ``atkgen.*`` glob so they win.
    ("atkgen.ExcessiveAgency", "LLM06"),
    ("atkgen.SupplyChain", "LLM03"),
    ("atkgen.DataPoisoning", "LLM04"),
    ("atkgen.VectorPoison", "LLM08"),
    ("atkgen.TokenFlooding", "LLM10"),
    ("atkgen.UnboundedOutput", "LLM10"),

    # ── LLM01 — Prompt Injection ─────────────────────────────────────
    ("dan.*", "LLM01"),
    ("promptinject.*", "LLM01"),
    ("goodside.*", "LLM01"),
    ("encoding.*", "LLM01"),
    ("gcg.*", "LLM01"),
    ("latentinjection.*", "LLM01"),
    ("grandma.*", "LLM01"),
    ("knownbadsignatures.*", "LLM01"),
    # Broad ``atkgen.*`` fallback comes AFTER the specific atkgen.X
    # overrides above so e.g. atkgen.Tox still resolves to LLM01.
    ("atkgen.*", "LLM01"),

    # ── LLM03 — Supply Chain ────────────────────────────────────────
    # (no glob — exact atkgen.SupplyChain handled above)

    # ── LLM05 — Improper Output Handling ─────────────────────────────
    ("xss.*", "LLM05"),
    ("sqli.*", "LLM05"),
    ("markdownexfil.*", "LLM05"),
    ("exploitation.*", "LLM05"),

    # ── LLM06 — Excessive Agency ────────────────────────────────────
    ("malwaregen.*", "LLM06"),
    ("agentic.*", "LLM06"),
    ("toolaction.*", "LLM06"),
    # Agentic-only probe families that don't have a great LLM Top 10
    # home but DO have direct ASI attribution below. Map to LLM06
    # so the review screen renders something coherent rather than
    # the LLM01 default.
    ("tool_misuse.*", "LLM06"),
    ("unauthorized_tool.*", "LLM06"),
    ("inter_agent.*", "LLM06"),
    ("agent_communication.*", "LLM06"),
    ("rogue_agent.*", "LLM06"),
    ("autonomous_action.*", "LLM06"),

    # ── LLM07 — System Prompt Leakage ───────────────────────────────
    ("promptleak.*", "LLM07"),
    ("leakreplay.*", "LLM07"),
    ("systemprompt.*", "LLM07"),

    # ── LLM09 — Misinformation ──────────────────────────────────────
    ("continuation.*", "LLM09"),
    ("realtoxicity.*", "LLM09"),
    ("hallucination.*", "LLM09"),
    ("packagehallucination.*", "LLM09"),
    ("misleading.*", "LLM09"),
    ("snowball.*", "LLM09"),

    # ── LLM10 — Unbounded Consumption ───────────────────────────────
    ("av_spam_scanning.*", "LLM10"),
    # Cascading agent failures / open circuit-breaker scenarios are
    # an availability-class concern that maps cleanly to LLM10 on the
    # LLM side, while direct ASI08 attribution is added below.
    ("cascading.*", "LLM10"),
    ("circuit_breaker.*", "LLM10"),
)

_DEFAULT_LLM = "LLM01"

# The complete OWASP LLM Top 10 set. ``GarakParser`` validates any
# externally-supplied ``owasp_llm_category`` value against this set
# and falls back to ``_DEFAULT_LLM`` for anything outside it, so we
# can trust the parser's output to be one of these ten codes.
VALID_LLM_CATEGORIES: frozenset[str] = frozenset(
    f"LLM{i:02d}" for i in range(1, 11)
)

# Companion validation set for the OWASP Agentic Top 10 (2026).
# Used by downstream stages (guardrail generator, AI client) that
# need to reject unknown ASI codes before rendering or sending to
# Claude.
VALID_AGENTIC_CATEGORIES: frozenset[str] = frozenset(
    f"ASI{i:02d}" for i in range(1, 11)
)

_LLM_TO_AGENTIC: dict[str, list[str]] = {
    "LLM01": ["ASI01"],
    "LLM02": [],
    "LLM03": ["ASI04"],
    "LLM04": ["ASI06"],
    "LLM05": ["ASI05"],
    "LLM06": ["ASI03"],
    "LLM07": ["ASI01", "ASI03"],
    "LLM08": ["ASI06"],
    "LLM09": ["ASI09"],
    "LLM10": ["ASI08"],
}


# Direct probe -> ASI mappings for the 2026 OWASP Agentic Top 10
# additions. These do NOT replace the cross-map above — they
# AUGMENT it. ``classify`` merges both sources and de-duplicates
# while preserving declaration order so the cross-map ASI appears
# first and the direct mapping appears second.
_PROBE_TO_AGENTIC: tuple[tuple[str, str], ...] = (
    # ASI02 — Tool Misuse and Exploitation
    ("tool_misuse.*", "ASI02"),
    ("unauthorized_tool.*", "ASI02"),
    # ASI07 — Insecure Inter-Agent Communication
    ("inter_agent.*", "ASI07"),
    ("agent_communication.*", "ASI07"),
    # ASI08 — Cascading Failures
    ("cascading.*", "ASI08"),
    ("circuit_breaker.*", "ASI08"),
    # ASI10 — Rogue Agents
    ("rogue_agent.*", "ASI10"),
    ("autonomous_action.*", "ASI10"),
)


class OwaspMapper:
    """Bidirectional mapper from garak probes to OWASP categories.

    All methods are stateless and side-effect free, so the class is used via
    static / class methods without instantiation.
    """

    @staticmethod
    def map_probe_to_llm(probe_name: str) -> str:
        """Return the OWASP LLM code for the given garak probe name.

        Args:
            probe_name: A garak probe identifier such as
                ``"dan.DAN_Jailbreak"`` or ``"lmrc.QuackMedicine"``.

        Returns:
            The matching OWASP LLM Top 10 code. Falls back to ``"LLM01"``
            for any probe that does not match a known pattern; a warning
            is logged so unmapped probes can be triaged.
        """
        for pattern, code in _PROBE_TO_LLM:
            if fnmatchcase(probe_name, pattern):
                return code
        logger.warning(
            "Unmapped probe '%s'; defaulting to %s",
            probe_name,
            _DEFAULT_LLM,
        )
        return _DEFAULT_LLM

    @staticmethod
    def map_llm_to_agentic(llm_code: str) -> list[str]:
        """Return Agentic codes cross-mapped from an LLM code.

        Args:
            llm_code: An OWASP LLM Top 10 code such as ``"LLM07"``.

        Returns:
            A fresh list of OWASP Agentic codes. Returns an empty list
            when the LLM code has no agentic equivalent (e.g. ``"LLM02"``)
            or when the code is unknown.
        """
        return list(_LLM_TO_AGENTIC.get(llm_code, []))

    @staticmethod
    def map_probe_to_agentic(probe_name: str) -> list[str]:
        """Return Agentic codes that match a probe via direct pattern lookup.

        Independent of the LLM cross-map — these are the probes from
        the 2026 Agentic Top 10 update that don't slot cleanly into
        an LLM Top 10 category but DO have a clear ASI attribution.
        Returns an empty list when no direct pattern matches.
        """
        matches: list[str] = []
        for pattern, code in _PROBE_TO_AGENTIC:
            if fnmatchcase(probe_name, pattern):
                matches.append(code)
        return matches

    @classmethod
    def classify(cls, probe_name: str) -> tuple[str, list[str]]:
        """Return ``(llm_code, merged_agentic_codes)`` for a probe.

        Merges two sources of ASI attribution:

        1. Cross-map from the resolved LLM code (the historical path).
        2. Direct probe-pattern match against ``_PROBE_TO_AGENTIC``
           (added for the 2026 Agentic Top 10 expansion — probes like
           ``tool_misuse.*`` get ASI02 here even when their LLM code
           is the default).

        Results are de-duplicated while preserving order so the
        cross-map ASI appears first.
        """
        llm_code = cls.map_probe_to_llm(probe_name)
        cross_mapped = cls.map_llm_to_agentic(llm_code)
        direct = cls.map_probe_to_agentic(probe_name)
        merged: list[str] = []
        for code in (*cross_mapped, *direct):
            if code not in merged:
                merged.append(code)
        return llm_code, merged
