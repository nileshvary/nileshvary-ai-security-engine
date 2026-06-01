"""Tests for probe -> LLM and LLM -> Agentic mapping."""

from __future__ import annotations

import logging

import pytest

from integration_bridge.owasp_mapper import OwaspMapper


@pytest.mark.parametrize(
    ("probe_name", "expected_llm"),
    [
        ("dan.DAN_Jailbreak", "LLM01"),
        ("promptinject.HijackHateHumansMini", "LLM01"),
        ("goodside.WhoIsRiley", "LLM01"),
        ("encoding.InjectBase64", "LLM01"),
        ("latentinjection.LatentJailbreak", "LLM01"),
        ("grandma.Slurs", "LLM01"),
        ("atkgen.Tox", "LLM01"),
        ("leakreplay.LiteratureCloze", "LLM02"),
        ("knownbadsignatures.GTUBE", "LLM02"),
        ("malwaregen.Evasion", "LLM05"),
        ("xss.MarkdownImageExfil", "LLM05"),
        ("exploitation.SQLInjection", "LLM05"),
        ("agentic.AutonomousAction", "LLM06"),
        ("toolaction.ShellExec", "LLM06"),
        ("misleading.FalseAssertion", "LLM09"),
        ("snowball.GraphConnectivity", "LLM09"),
        ("av_spam_scanning.EICAR", "LLM10"),
    ],
)
def test_map_probe_to_llm_known_patterns(probe_name: str, expected_llm: str) -> None:
    assert OwaspMapper.map_probe_to_llm(probe_name) == expected_llm


def test_exact_match_wins_over_glob() -> None:
    # lmrc.QuackMedicine is exact-mapped to LLM09; without the exact entry
    # the default would apply since no `lmrc.*` glob exists.
    assert OwaspMapper.map_probe_to_llm("lmrc.QuackMedicine") == "LLM09"


def test_unknown_probe_defaults_and_warns(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.WARNING, logger="integration_bridge.owasp_mapper"):
        result = OwaspMapper.map_probe_to_llm("totally.unknown.probe")
    assert result == "LLM01"
    assert any("Unmapped probe" in rec.message for rec in caplog.records)


@pytest.mark.parametrize(
    ("llm_code", "expected"),
    [
        ("LLM01", ["ASI01"]),
        ("LLM02", []),
        ("LLM03", ["ASI04"]),
        ("LLM04", ["ASI06"]),
        ("LLM05", ["ASI05"]),
        ("LLM06", ["ASI03"]),
        ("LLM07", ["ASI01", "ASI03"]),
        ("LLM08", ["ASI06"]),
        ("LLM09", ["ASI09"]),
        ("LLM10", ["ASI08"]),
    ],
)
def test_llm_to_agentic_mapping(llm_code: str, expected: list[str]) -> None:
    assert OwaspMapper.map_llm_to_agentic(llm_code) == expected


def test_llm_to_agentic_unknown_returns_empty_list() -> None:
    assert OwaspMapper.map_llm_to_agentic("LLM99") == []


def test_returned_agentic_list_is_a_fresh_copy() -> None:
    first = OwaspMapper.map_llm_to_agentic("LLM07")
    first.append("ASI99")
    second = OwaspMapper.map_llm_to_agentic("LLM07")
    assert second == ["ASI01", "ASI03"]


def test_classify_returns_both() -> None:
    llm_code, agentic = OwaspMapper.classify("dan.DAN")
    assert llm_code == "LLM01"
    assert agentic == ["ASI01"]


def test_classify_for_llm02_probe_has_empty_agentic() -> None:
    llm_code, agentic = OwaspMapper.classify("leakreplay.LiteratureCloze")
    assert llm_code == "LLM02"
    assert agentic == []
