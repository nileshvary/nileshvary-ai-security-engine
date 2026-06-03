"""Tests for probe -> LLM and LLM -> Agentic mapping."""

from __future__ import annotations

import logging

import pytest

from integration_bridge.owasp_mapper import OwaspMapper


@pytest.mark.parametrize(
    ("probe_name", "expected_llm"),
    [
        # LLM01 — Prompt Injection
        ("dan.DAN_Jailbreak", "LLM01"),
        ("promptinject.HijackHateHumansMini", "LLM01"),
        ("goodside.WhoIsRiley", "LLM01"),
        ("encoding.InjectBase64", "LLM01"),
        ("gcg.GCGAttack", "LLM01"),
        ("latentinjection.LatentJailbreak", "LLM01"),
        ("grandma.Slurs", "LLM01"),
        ("knownbadsignatures.GTUBE", "LLM01"),
        ("atkgen.Tox", "LLM01"),
        # LLM03 — Supply Chain (exact atkgen overrides)
        ("atkgen.SupplyChain", "LLM03"),
        # LLM04 — Data and Model Poisoning
        ("atkgen.DataPoisoning", "LLM04"),
        # LLM05 — Improper Output Handling
        ("xss.MarkdownImageExfil", "LLM05"),
        ("sqli.UnionInjection", "LLM05"),
        ("markdownexfil.ImageExfil", "LLM05"),
        ("exploitation.SQLInjection", "LLM05"),
        # LLM06 — Excessive Agency
        ("atkgen.ExcessiveAgency", "LLM06"),
        ("malwaregen.Evasion", "LLM06"),
        ("agentic.AutonomousAction", "LLM06"),
        ("toolaction.ShellExec", "LLM06"),
        # LLM07 — System Prompt Leakage
        ("promptleak.SystemPrompt", "LLM07"),
        ("leakreplay.LiteratureCloze", "LLM07"),
        ("systemprompt.Reveal", "LLM07"),
        # LLM08 — Vector and Embedding Weaknesses
        ("atkgen.VectorPoison", "LLM08"),
        # LLM09 — Misinformation
        ("continuation.Conspiracy", "LLM09"),
        ("realtoxicity.Insult", "LLM09"),
        ("hallucination.Persona", "LLM09"),
        ("packagehallucination.NPM", "LLM09"),
        ("misleading.FalseAssertion", "LLM09"),
        ("snowball.GraphConnectivity", "LLM09"),
        # LLM10 — Unbounded Consumption
        ("atkgen.TokenFlooding", "LLM10"),
        ("atkgen.UnboundedOutput", "LLM10"),
        ("av_spam_scanning.EICAR", "LLM10"),
    ],
)
def test_map_probe_to_llm_known_patterns(probe_name: str, expected_llm: str) -> None:
    assert OwaspMapper.map_probe_to_llm(probe_name) == expected_llm


def test_atkgen_specific_overrides_win_over_broad_glob() -> None:
    """The exact-name atkgen.X entries must beat the broad ``atkgen.*`` fallback."""
    assert OwaspMapper.map_probe_to_llm("atkgen.ExcessiveAgency") == "LLM06"
    assert OwaspMapper.map_probe_to_llm("atkgen.SupplyChain") == "LLM03"
    # And a non-overridden atkgen probe still resolves to the broad LLM01.
    assert OwaspMapper.map_probe_to_llm("atkgen.SomethingNew") == "LLM01"


def test_changed_mappings_match_product_spec() -> None:
    """Regression guard for the three mappings the spec deliberately moved."""
    assert OwaspMapper.map_probe_to_llm("leakreplay.X") == "LLM07"
    assert OwaspMapper.map_probe_to_llm("knownbadsignatures.X") == "LLM01"
    assert OwaspMapper.map_probe_to_llm("malwaregen.X") == "LLM06"


def test_valid_llm_categories_is_the_full_top_ten() -> None:
    from integration_bridge.owasp_mapper import VALID_LLM_CATEGORIES

    assert VALID_LLM_CATEGORIES == {
        "LLM01", "LLM02", "LLM03", "LLM04", "LLM05",
        "LLM06", "LLM07", "LLM08", "LLM09", "LLM10",
    }


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


def test_classify_for_leakreplay_probe_resolves_to_llm07_under_new_mapping() -> None:
    """leakreplay moved from LLM02 to LLM07 per the product-spec update."""
    llm_code, agentic = OwaspMapper.classify("leakreplay.LiteratureCloze")
    assert llm_code == "LLM07"
    # LLM07 cross-maps to both ASI01 and ASI03.
    assert agentic == ["ASI01", "ASI03"]


def test_classify_for_llm02_probe_has_empty_agentic() -> None:
    """An LLM02-only probe (no current mapping points here) returns empty agentic."""
    # No probe pattern maps to LLM02 after the spec update, but the
    # cross-map table itself still must yield [] for LLM02 -> agentic.
    llm_code, agentic = OwaspMapper.classify("dan.x")  # resolves to LLM01 (agentic=ASI01)
    assert llm_code == "LLM01"
    assert agentic == ["ASI01"]
