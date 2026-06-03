"""Tests for the penalty-based security score + status-band helpers."""

from __future__ import annotations

from dataclasses import dataclass

import pytest

from components.security_score import calculate_security_score, score_status


@dataclass
class _Stub:
    """Minimal stand-in for ``integration_bridge.Finding`` for these tests."""

    severity: str


# ---------------------------------------------------------------------------
# calculate_security_score
# ---------------------------------------------------------------------------


def test_calculate_empty_returns_100() -> None:
    assert calculate_security_score([]) == 100.0


def test_calculate_single_critical_deducts_20() -> None:
    assert calculate_security_score([_Stub("CRITICAL")]) == 80.0


def test_calculate_single_high_deducts_10() -> None:
    assert calculate_security_score([_Stub("HIGH")]) == 90.0


def test_calculate_single_medium_deducts_5() -> None:
    assert calculate_security_score([_Stub("MEDIUM")]) == 95.0


def test_calculate_single_low_deducts_2() -> None:
    assert calculate_security_score([_Stub("LOW")]) == 98.0


def test_calculate_mixed_findings_sums_penalties() -> None:
    findings = [
        _Stub("CRITICAL"),  # -20
        _Stub("HIGH"),  # -10
        _Stub("HIGH"),  # -10
        _Stub("MEDIUM"),  # -5
        _Stub("LOW"),  # -2
        _Stub("LOW"),  # -2
    ]
    # 100 - 20 - 10 - 10 - 5 - 2 - 2 = 51
    assert calculate_security_score(findings) == 51.0


def test_calculate_clamps_to_zero_when_penalty_exceeds_100() -> None:
    # Six criticals = -120 → clamped at 0
    assert calculate_security_score([_Stub("CRITICAL")] * 6) == 0.0


def test_calculate_clamps_to_zero_for_very_many_findings() -> None:
    assert calculate_security_score([_Stub("LOW")] * 1000) == 0.0


def test_calculate_unknown_severity_ignored() -> None:
    # Garbage severities contribute zero penalty.
    assert calculate_security_score([_Stub("WEIRD"), _Stub("INFO"), _Stub("")]) == 100.0


# ---------------------------------------------------------------------------
# score_status — boundary checks per spec (90 / 70 / 50 thresholds)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("score", "label"),
    [
        (100.0, "SECURE"),
        (95.0, "SECURE"),
        (90.0, "SECURE"),
        (89.9, "MODERATE"),
        (80.0, "MODERATE"),
        (70.0, "MODERATE"),
        (69.9, "AT RISK"),
        (60.0, "AT RISK"),
        (50.0, "AT RISK"),
        (49.9, "CRITICAL"),
        (25.0, "CRITICAL"),
        (0.0, "CRITICAL"),
    ],
)
def test_score_status_band_boundaries(score: float, label: str) -> None:
    assert score_status(score)[0] == label


def test_score_status_returns_hex_color() -> None:
    for score in (95.0, 80.0, 60.0, 10.0):
        _, color = score_status(score)
        assert color.startswith("#") and len(color) == 7


def test_score_status_negative_falls_back_to_critical() -> None:
    # calculate_security_score clamps, but score_status is defensive
    # against a negative passed directly.
    assert score_status(-5.0) == ("CRITICAL", "#ff4444")
