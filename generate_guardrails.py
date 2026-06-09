"""Command-line generator for a populated ``guardrails.yaml``.

Fills the gap described in ``REMEDIAX_MASTER_CONTEXT.md`` (§4, "Fix 1"): the
guardrail file was empty because no Claude (autonomous) pass ever ran. The
autonomous merge path lives in
``remediation_engine.guardrail_generator.GuardrailGenerator`` but, until now,
was only wired into the Streamlit app. This script is the missing command-line
entry point.

It loads the ten synthetic findings (one per OWASP LLM category) from
``demo_data.load_demo_findings``, hands them to the generator together with a
``RemediAXAI`` client built from the ``ANTHROPIC_API_KEY`` environment variable,
and writes the resulting universal LLM01-LLM10 guardrail config to
``guardrails.yaml``.

Usage (PowerShell)::

    $env:ANTHROPIC_API_KEY = "sk-ant-..."
    python generate_guardrails.py                 # -> guardrails.yaml (AI mode)
    python generate_guardrails.py --deterministic # no key; LLM01/02/05/10 only

The API key is read from the environment and never hardcoded or logged.
"""

from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path
from typing import Any

# The repo mixes ``src/`` packages with root-level modules. Running this script
# from the repo root puts the root on ``sys.path`` (covering ``components`` and
# ``demo_data``); prepend ``src`` so the pipeline packages import too — mirrors
# the bootstrap in ``app.py``.
_SRC_DIR = Path(__file__).resolve().parent / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

from components.ai_client import RemediAXAI  # noqa: E402
from demo_data import load_demo_findings  # noqa: E402
from integration_bridge.models import Finding  # noqa: E402
from output.writers import YamlWriter  # noqa: E402
from remediation_engine import GuardrailGenerator  # noqa: E402
from remediation_engine.models import GuardrailConfig  # noqa: E402

logger = logging.getLogger("generate_guardrails")

_DEFAULT_OUTPUT = "guardrails.yaml"
_CANONICAL_NAME = "guardrails.yaml"


def build_guardrails(
    findings: list[Finding],
    ai_client: Any | None,
    output_format: str = "portkey",
) -> GuardrailConfig:
    """Generate a guardrail config from ``findings``.

    Thin, network-free wrapper around ``GuardrailGenerator.generate`` so the
    orchestration can be unit-tested with a fake ``ai_client`` injected.

    Args:
        findings: Findings whose distinct ``owasp_llm_category`` values drive
            the rule set.
        ai_client: A ``RemediAXAI`` (or test double exposing
            ``generate_complete_analysis``). When ``None`` the generator falls
            back to its deterministic rules (LLM01/02/05/10 + ASI policies).
        output_format: One of ``"portkey"``, ``"litellm"``, ``"generic"``.

    Returns:
        The generated ``GuardrailConfig`` (parsed rule lists plus serialized
        YAML in ``yaml_export``).
    """
    return GuardrailGenerator().generate(
        findings, output_format, ai_client=ai_client
    )


def write_guardrails(config: GuardrailConfig, output_path: Path) -> Path:
    """Write ``config`` to ``output_path`` and return the path written.

    When the target is the canonical ``guardrails.yaml`` the write is delegated
    to ``output.writers.YamlWriter`` so it stays identical to the pipeline's own
    artifact. Any other filename is written directly.

    Args:
        config: The guardrail config to serialize.
        output_path: Destination file path.

    Returns:
        The path that was written.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    if output_path.name == _CANONICAL_NAME:
        artifact = YamlWriter().write(config, output_path.parent)
        return Path(artifact.filepath)
    output_path.write_text(config.yaml_export, encoding="utf-8")
    return output_path


def main(argv: list[str] | None = None) -> int:
    """Generate ``guardrails.yaml`` from the demo findings.

    Args:
        argv: Optional argument vector (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code: ``0`` on success, ``1`` when the API key is missing
        in AI mode.
    """
    parser = argparse.ArgumentParser(
        description="Generate a universal LLM01-LLM10 guardrails.yaml.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path(_DEFAULT_OUTPUT),
        help="Destination file (default: guardrails.yaml).",
    )
    parser.add_argument(
        "--deterministic",
        action="store_true",
        help=(
            "Skip the Claude pass; emit only the hardcoded rules "
            "(LLM01/02/05/10 + ASI policies). No API key required."
        ),
    )
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.INFO, format="%(levelname)s %(name)s: %(message)s"
    )

    findings = load_demo_findings()

    ai_client: RemediAXAI | None = None
    if args.deterministic:
        logger.info(
            "Deterministic mode: generating hardcoded rules without Claude."
        )
    else:
        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            logger.error(
                "ANTHROPIC_API_KEY is not set. Set it and re-run, e.g.:\n"
                '    $env:ANTHROPIC_API_KEY = "sk-ant-..."\n'
                "    python generate_guardrails.py\n"
                "Or pass --deterministic for hardcoded rules without a key."
            )
            return 1
        ai_client = RemediAXAI(api_key)
        logger.info(
            "AI mode: querying Claude once per finding (%d findings).",
            len(findings),
        )

    config = build_guardrails(findings, ai_client)
    written = write_guardrails(config, args.output)

    covered = sorted({f.owasp_llm_category for f in findings})
    logger.info(
        "Wrote %s: %d input rule(s), %d output rule(s), covering %s.",
        written,
        len(config.input_filters),
        len(config.output_filters),
        ", ".join(covered),
    )
    if ai_client is not None:
        logger.info("Claude API calls made: %d.", ai_client.call_count)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
