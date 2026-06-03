"""Penalty-based security score + status bands shared by analytics + history.

Kept in its own module (not in ``app.py``) so the pure logic can be
unit-tested without spinning up the Streamlit runtime. ``app.py``
imports these and uses them everywhere a score is computed or
displayed, so the formula stays consistent end-to-end.
"""

from __future__ import annotations

from typing import Iterable, Protocol


class _HasSeverity(Protocol):
    severity: str


# Penalty per finding by severity. The numbers come from the product
# spec — if they change, change them HERE so every callsite picks it
# up.
_PENALTY = {
    "CRITICAL": 20,
    "HIGH": 10,
    "MEDIUM": 5,
    "LOW": 2,
}


def calculate_security_score(findings: Iterable[_HasSeverity]) -> float:
    """Return a penalty-based security score in ``[0, 100]``.

        score = 100 - CRITICAL*20 - HIGH*10 - MEDIUM*5 - LOW*2

    The result is clamped to ``[0.0, 100.0]``. Unknown severities are
    ignored (they contribute zero penalty).
    """
    raw = 100.0
    for f in findings:
        raw -= _PENALTY.get(getattr(f, "severity", ""), 0)
    return max(0.0, min(100.0, raw))


# Status bands map a score to a (label, hex_color) tuple. Used by the
# UI to render a colored SECURE / MODERATE / AT RISK / CRITICAL chip
# alongside the numeric metric.
_BANDS: tuple[tuple[float, str, str], ...] = (
    (90.0, "SECURE", "#00ff88"),
    (70.0, "MODERATE", "#ffd166"),
    (50.0, "AT RISK", "#ff8c42"),
    (0.0, "CRITICAL", "#ff4444"),
)


def score_status(score: float) -> tuple[str, str]:
    """Return ``(label, hex_color)`` for a security score.

    Bands (lower inclusive, upper exclusive except the top):
        90-100 -> SECURE (green)
        70-89  -> MODERATE (yellow)
        50-69  -> AT RISK (orange)
        0-49   -> CRITICAL (red)
    """
    for threshold, label, color in _BANDS:
        if score >= threshold:
            return (label, color)
    # Defensive: scores below 0 are clamped by calculate_security_score,
    # but if a caller passes a negative number directly we still want
    # a sensible answer rather than an exception.
    return ("CRITICAL", "#ff4444")
