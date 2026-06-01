"""Standalone CLI for minting RemediAX access tokens.

Run locally; the raw token is printed once and then only its hash is
persisted to ``tokens.json``. Do not check ``tokens.json`` in — it is
gitignored.

Usage:
    python generate_token.py --duration 48h --for "Alice"
    python generate_token.py --duration permanent --for "Admin"
"""

from __future__ import annotations

import argparse
import sys

from auth.token_manager import TokenManager

# Some Windows terminals default to cp1252 and choke on the Unicode box
# characters below. Reconfigure stdout to UTF-8 when possible; fall back
# silently if not.
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
except (AttributeError, ValueError):  # pragma: no cover - non-text stdout
    pass


_DURATION_HOURS: dict[str, int] = {
    "2h": 2,
    "24h": 24,
    "48h": 48,
    "7d": 168,
}


def main() -> int:
    """Parse args, mint a token, print it in an ASCII box. Returns ``0``."""
    parser = argparse.ArgumentParser(description="Generate RemediAX access token")
    parser.add_argument(
        "--duration",
        default="48h",
        choices=["2h", "24h", "48h", "7d", "permanent"],
        help="Token validity duration (default: 48h)",
    )
    parser.add_argument(
        "--for",
        dest="for_person",
        default="",
        help="Free-form note about who the token is for",
    )
    args = parser.parse_args()

    permanent = args.duration == "permanent"
    duration = _DURATION_HOURS.get(args.duration, 48)

    token = TokenManager().generate_token(
        duration_hours=duration,
        for_person=args.for_person,
        permanent=permanent,
    )

    print(
        "\n"
        "  ╔════════════════════════════════════════╗\n"
        "  ║   RemediAX Token Generated             ║\n"
        "  ╠════════════════════════════════════════╣\n"
        f"  ║  Token : {token}\n"
        f"  ║  For   : {args.for_person or '(unspecified)'}\n"
        f"  ║  Valid : {args.duration}\n"
        "  ║                                        ║\n"
        "  ║  ⚠️  Share once. Not stored anywhere.  ║\n"
        "  ╚════════════════════════════════════════╝\n"
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
