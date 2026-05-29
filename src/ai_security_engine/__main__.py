"""CLI entry point for the ai-security-engine pipeline.

Subcommands:
- ``remediate`` — parse a garak hitlog, run the full Phase 2-5 pipeline,
  and write artifacts to disk.
- ``version`` — print the installed package version and exit.
- ``help`` (or no args) — print usage examples and exit.
"""

from __future__ import annotations

import argparse
import logging
import sys
from importlib.metadata import PackageNotFoundError, version as pkg_version
from pathlib import Path

from integration_bridge import GarakParser
from output import OutputOrchestrator
from remediation_engine import GuardrailGenerator, RemediationOrchestrator
from verifier import VerificationOrchestrator

logger = logging.getLogger(__name__)


_PACKAGE_NAME = "ai-security-engine"
_FALLBACK_VERSION = "0.0.0+unknown"
_VALID_FORMATS = ("portkey", "litellm", "generic")


def _tool_version() -> str:
    try:
        return pkg_version(_PACKAGE_NAME)
    except PackageNotFoundError:
        return _FALLBACK_VERSION


_HELP_TEXT = f"""\
{_PACKAGE_NAME} — convert garak findings into actionable security artifacts.

Usage:
  {_PACKAGE_NAME} remediate --input HITLOG --output DIR [options]
  {_PACKAGE_NAME} version
  {_PACKAGE_NAME} help

Examples:
  # Run the full pipeline against a garak hitlog, write a Portkey-format
  # bundle to ./out:
  {_PACKAGE_NAME} remediate \\
      --input runs/hitlog.jsonl \\
      --output out/ \\
      --format portkey \\
      --prompt prompts/system.txt

  # Same run, LiteLLM format, with debug logging:
  {_PACKAGE_NAME} remediate \\
      --input runs/hitlog.jsonl \\
      --output out/ \\
      --format litellm \\
      --verbose

Subcommands:
  remediate   Run the full Phase 2-5 pipeline (parse, remediate, verify, write).
  version     Print {_PACKAGE_NAME} version.
  help        Print this help block.
"""


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=_PACKAGE_NAME,
        description="Convert garak findings into actionable security artifacts.",
        add_help=False,
    )
    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    remediate = subparsers.add_parser(
        "remediate",
        help="Run the full pipeline against a garak hitlog.",
    )
    remediate.add_argument(
        "--input",
        type=Path,
        required=True,
        help="Path to a garak hitlog.jsonl file.",
    )
    remediate.add_argument(
        "--output",
        type=Path,
        required=True,
        help="Output directory (created if missing).",
    )
    remediate.add_argument(
        "--format",
        choices=_VALID_FORMATS,
        default="portkey",
        help="Guardrail config format (default: portkey).",
    )
    remediate.add_argument(
        "--prompt",
        type=Path,
        default=None,
        help="Path to original system prompt file for LLM01/LLM07 patching.",
    )
    remediate.add_argument(
        "--verbose",
        action="store_true",
        help="Enable DEBUG-level logging.",
    )

    subparsers.add_parser("version", help="Print version and exit.")
    subparsers.add_parser("help", help="Print usage examples and exit.")

    return parser


def _configure_logging(verbose: bool) -> None:
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        force=True,
    )


def _print_summary(output_dir: Path, final_report) -> None:  # type: ignore[no-untyped-def]
    """Print a concise human summary of the run to stdout."""
    report = final_report.verification_report
    print()
    print(f"=== {_PACKAGE_NAME} run complete ===")
    print(f"Output directory: {output_dir}")
    print(f"Total findings:   {report.total_findings}")
    print(
        f"Status:           verified={report.verified_count} "
        f"partial={report.partial_count} "
        f"failed={report.failed_count} "
        f"unverifiable={report.unverifiable_count}"
    )
    print(
        f"Overall improvement: {report.overall_improvement_percent:.1f}%"
    )
    print("Artifacts:")
    for artifact in final_report.artifacts:
        print(f"  - {artifact.filename}  ({artifact.size_bytes:,} bytes)")


def _run_remediate(args: argparse.Namespace) -> int:
    if not args.input.is_file():
        print(f"error: input file not found: {args.input}", file=sys.stderr)
        return 2

    _configure_logging(args.verbose)
    logger.info("Starting pipeline against %s", args.input)

    findings = GarakParser(args.input).parse()

    original_prompt: str | None = None
    if args.prompt is not None:
        if not args.prompt.is_file():
            print(
                f"error: prompt file not found: {args.prompt}", file=sys.stderr
            )
            return 2
        original_prompt = args.prompt.read_text(encoding="utf-8")

    remediation_orchestrator = RemediationOrchestrator(guardrail_format=args.format)
    remediation_results = remediation_orchestrator.remediate_findings(
        findings, original_prompt=original_prompt
    )

    verifier = VerificationOrchestrator()
    verification_report = verifier.verify_all(remediation_results, mode="quick")

    if remediation_results:
        guardrail_config = remediation_results[0].guardrail_config
        if guardrail_config is None:
            guardrail_config = GuardrailGenerator().generate(findings, args.format)
    else:
        guardrail_config = GuardrailGenerator().generate(findings, args.format)

    output_orchestrator = OutputOrchestrator()
    final_report = output_orchestrator.write_all(
        findings=findings,
        remediation_results=remediation_results,
        verification_report=verification_report,
        guardrail_config=guardrail_config,
        output_dir=args.output,
    )

    _print_summary(args.output, final_report)
    return 0


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    Args:
        argv: Optional argument list (defaults to ``sys.argv[1:]``).
            Tests pass an explicit list.

    Returns:
        Process exit code (``0`` on success, ``2`` for usage / missing-file
        errors, ``1`` for unexpected runtime errors).
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command is None or args.command == "help":
        print(_HELP_TEXT)
        return 0

    if args.command == "version":
        print(f"{_PACKAGE_NAME} {_tool_version()}")
        return 0

    if args.command == "remediate":
        try:
            return _run_remediate(args)
        except Exception as exc:  # pragma: no cover - defensive boundary
            logger.exception("Pipeline failed")
            print(f"error: {exc}", file=sys.stderr)
            return 1

    parser.print_help()
    return 2


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
