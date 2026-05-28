"""Tests for ``GarakParser``."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from integration_bridge.parser import GarakParser


def _attempts_for_fixture() -> dict[str, int]:
    """Total attempts per probe sized to land each severity in a known bucket."""
    return {
        "dan.DAN_Jailbreak": 2,                # 2/2 = 1.00 -> CRITICAL
        "leakreplay.LiteratureCloze": 20,      # 1/20 = 0.05 -> LOW
        "promptinject.HijackHateHumansMini": 4,  # 1/4 = 0.25 -> MEDIUM
        "malwaregen.Evasion": 2,               # 1/2 = 0.50 -> HIGH
        "lmrc.QuackMedicine": 4,               # 1/4 = 0.25 -> MEDIUM (not asserted)
        "somethingweird.unknown": 10,          # 1/10 = 0.10 -> MEDIUM (not asserted)
    }


def test_parse_happy_path_field_population(sample_hitlog_path: Path) -> None:
    parser = GarakParser(sample_hitlog_path, attempts_per_probe=_attempts_for_fixture())
    findings = parser.parse()

    assert len(findings) == 7

    first = findings[0]
    assert first.probe_name == "dan.DAN_Jailbreak"
    assert first.detector_name == "mitigation.MitigationBypass"
    assert "Ignore previous instructions" in first.attack_prompt
    assert "DAN" in first.model_response
    assert first.is_successful_attack is True
    assert isinstance(first.raw_data, dict)
    assert first.raw_data["score"] == 1.0


def test_parse_severity_buckets(sample_hitlog_path: Path) -> None:
    parser = GarakParser(sample_hitlog_path, attempts_per_probe=_attempts_for_fixture())
    findings = parser.parse()
    sev_by_probe = {f.probe_name: f.severity for f in findings}
    assert sev_by_probe["dan.DAN_Jailbreak"] == "CRITICAL"
    assert sev_by_probe["leakreplay.LiteratureCloze"] == "LOW"
    assert sev_by_probe["promptinject.HijackHateHumansMini"] == "MEDIUM"
    assert sev_by_probe["malwaregen.Evasion"] == "HIGH"


def test_owasp_mappings_wired_end_to_end(sample_hitlog_path: Path) -> None:
    parser = GarakParser(
        sample_hitlog_path,
        attempts_per_probe={"dan.DAN_Jailbreak": 2},
    )
    findings = parser.parse()
    dan = next(f for f in findings if f.probe_name == "dan.DAN_Jailbreak")
    assert dan.owasp_llm_category == "LLM01"
    assert dan.owasp_agentic_categories == ["ASI01"]

    leak = next(f for f in findings if f.probe_name == "leakreplay.LiteratureCloze")
    assert leak.owasp_llm_category == "LLM02"
    assert leak.owasp_agentic_categories == []

    quack = next(f for f in findings if f.probe_name == "lmrc.QuackMedicine")
    assert quack.owasp_llm_category == "LLM09"
    assert quack.owasp_agentic_categories == ["ASI09"]


def test_unmapped_probe_falls_back_to_llm01(sample_hitlog_path: Path) -> None:
    parser = GarakParser(sample_hitlog_path, attempts_per_probe=_attempts_for_fixture())
    findings = parser.parse()
    weird = next(f for f in findings if f.probe_name == "somethingweird.unknown")
    assert weird.owasp_llm_category == "LLM01"
    assert weird.owasp_agentic_categories == ["ASI01"]


def test_per_row_total_attempts_metadata(tmp_path: Path) -> None:
    rows = [
        {
            "probe": "dan.DAN",
            "detector": "d",
            "prompt": f"p{i}",
            "output": "o",
            "total_attempts": 10,
        }
        for i in range(8)
    ]
    path = tmp_path / "h.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")

    findings = GarakParser(path).parse()

    assert len(findings) == 8
    # 8 hits out of total_attempts=10 -> rate=0.80 -> CRITICAL
    assert all(f.severity == "CRITICAL" for f in findings)


def test_generations_per_prompt_metadata(tmp_path: Path) -> None:
    # 4 distinct prompts * generations_per_prompt=5 = 20 total attempts;
    # 1 hit / 20 = 0.05 -> LOW.
    row = {
        "probe": "leakreplay.X",
        "detector": "d",
        "prompt": "p-unique",
        "output": "o",
        "generations_per_prompt": 5,
    }
    path = tmp_path / "h.jsonl"
    lines = [
        json.dumps({**row, "prompt": f"p{i}"}) if i == 0 else json.dumps({**row, "prompt": f"p{i}", "score": 0.1})
        for i in range(4)
    ]
    # Only the first row is a "hit" semantically; for the parser, every row is a hit.
    # We just need 4 distinct prompts under the same probe.
    path.write_text("\n".join(lines), encoding="utf-8")

    findings = GarakParser(path).parse()
    # 4 hits / (5 gens * 4 prompts = 20) = 0.20 -> MEDIUM
    assert all(f.severity == "MEDIUM" for f in findings)


def test_fallback_defaults_to_medium_when_no_metadata(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    rows = [{"probe": "dan.DAN", "detector": "d", "prompt": "p", "output": "o"}]
    path = tmp_path / "h.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")

    with caplog.at_level(logging.WARNING, logger="integration_bridge.parser"):
        parser = GarakParser(path)
        findings = parser.parse()

    assert findings[0].severity == "MEDIUM"
    assert any("No attempts metadata" in rec.message for rec in caplog.records)
    assert "dan.DAN" in parser.unknown_attempts


def test_malformed_rows_are_skipped(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
) -> None:
    path = tmp_path / "h.jsonl"
    lines = [
        json.dumps({"probe": "dan.DAN", "detector": "d", "prompt": "p", "output": "o"}),
        json.dumps({"detector": "d", "prompt": "p"}),  # missing probe
        "this is not valid json",
        "",
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    with caplog.at_level(logging.WARNING, logger="integration_bridge.parser"):
        findings = GarakParser(
            path, attempts_per_probe={"dan.DAN": 1}
        ).parse()

    assert len(findings) == 1
    assert any("no probe name" in rec.message for rec in caplog.records)
    assert any("malformed JSON" in rec.message for rec in caplog.records)


def test_score_below_threshold_marks_unsuccessful(tmp_path: Path) -> None:
    rows = [
        {"probe": "dan.DAN", "detector": "d", "prompt": "p1", "output": "o", "score": 0.9},
        {"probe": "dan.DAN", "detector": "d", "prompt": "p2", "output": "o", "score": 0.2},
    ]
    path = tmp_path / "h.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")

    findings = GarakParser(path, attempts_per_probe={"dan.DAN": 2}).parse()

    assert findings[0].is_successful_attack is True
    assert findings[1].is_successful_attack is False


def test_alternate_field_names_are_accepted(tmp_path: Path) -> None:
    rows = [
        {
            "probe_name": "dan.DAN",
            "detector_name": "d",
            "attack_prompt": "p",
            "model_response": "o",
        }
    ]
    path = tmp_path / "h.jsonl"
    path.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")

    findings = GarakParser(path, attempts_per_probe={"dan.DAN": 1}).parse()

    assert len(findings) == 1
    assert findings[0].probe_name == "dan.DAN"
    assert findings[0].detector_name == "d"
    assert findings[0].attack_prompt == "p"
    assert findings[0].model_response == "o"
