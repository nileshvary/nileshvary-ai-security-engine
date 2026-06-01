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
    # Exact matches first so the broader globs below cannot shadow them.
    ("lmrc.QuackMedicine", "LLM09"),
    # LLM01 — Prompt Injection family.
    ("dan.*", "LLM01"),
    ("promptinject.*", "LLM01"),
    ("goodside.*", "LLM01"),
    ("encoding.*", "LLM01"),
    ("latentinjection.*", "LLM01"),
    ("grandma.*", "LLM01"),
    ("atkgen.*", "LLM01"),
    # LLM02 — Sensitive Information Disclosure family.
    ("leakreplay.*", "LLM02"),
    ("knownbadsignatures.*", "LLM02"),
    # LLM05 — Improper Output Handling family.
    ("malwaregen.*", "LLM05"),
    ("xss.*", "LLM05"),
    ("exploitation.*", "LLM05"),
    # LLM06 — Excessive Agency family.
    ("agentic.*", "LLM06"),
    ("toolaction.*", "LLM06"),
    # LLM09 — Misinformation family.
    ("misleading.*", "LLM09"),
    ("snowball.*", "LLM09"),
    # LLM10 — Unbounded Consumption family.
    ("av_spam_scanning.*", "LLM10"),
)

_DEFAULT_LLM = "LLM01"

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

    @classmethod
    def classify(cls, probe_name: str) -> tuple[str, list[str]]:
        """Return ``(llm_code, agentic_codes)`` for a probe in one call.

        Args:
            probe_name: A garak probe identifier.

        Returns:
            A two-tuple of the OWASP LLM code and the list of cross-mapped
            OWASP Agentic codes.
        """
        llm_code = cls.map_probe_to_llm(probe_name)
        return llm_code, cls.map_llm_to_agentic(llm_code)
