"""Centralized configuration for all RemediAX v2.0 agents.

All API keys are read from environment variables — never hardcoded.
Import this module in any agent to get a consistent configuration object.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class Config:
    """All agent configuration in one place.

    Attributes:
        anthropic_api_key: Claude API key from ``ANTHROPIC_API_KEY`` env var.
        claude_model: Claude model used for all AI calls.
        garak_probes: Garak probe families to run (empty = all).
        pyrit_max_turns: Max conversation turns per PyRIT multi-turn attack.
        llmguard_enabled: Whether LLM Guard scanners are active.
        nemo_enabled: Whether NeMo Guardrails colang output is generated.
        promptfoo_config_path: Path to the Promptfoo regression config file.
        output_dir: Default directory for all output artifacts.
        log_level: Python logging level (e.g. ``"INFO"``).
    """

    anthropic_api_key: str = field(default_factory=lambda: os.environ.get("ANTHROPIC_API_KEY", ""))
    claude_model: str = "claude-haiku-4-5-20251001"

    # Scanner — Agent 1
    garak_probes: list[str] = field(default_factory=list)
    pyrit_max_turns: int = 5

    # Remediator — Agent 2
    llmguard_enabled: bool = True
    nemo_enabled: bool = True

    # Verifier — Agent 4
    promptfoo_config_path: str = "promptfoo.config.yaml"

    # Output
    output_dir: str = "artifacts"
    log_level: str = "INFO"

    @property
    def has_api_key(self) -> bool:
        """Return True if an Anthropic API key is configured."""
        return bool(self.anthropic_api_key)

    @classmethod
    def from_env(cls) -> Config:
        """Build a Config from environment variables.

        Returns:
            Config populated from the current environment.
        """
        return cls(
            anthropic_api_key=os.environ.get("ANTHROPIC_API_KEY", ""),
            claude_model=os.environ.get("REMEDIAX_MODEL", "claude-haiku-4-5-20251001"),
            pyrit_max_turns=int(os.environ.get("PYRIT_MAX_TURNS", "5")),
            llmguard_enabled=os.environ.get("LLMGUARD_ENABLED", "true").lower() == "true",
            nemo_enabled=os.environ.get("NEMO_ENABLED", "true").lower() == "true",
            output_dir=os.environ.get("REMEDIAX_OUTPUT_DIR", "artifacts"),
            log_level=os.environ.get("REMEDIAX_LOG_LEVEL", "INFO"),
        )
