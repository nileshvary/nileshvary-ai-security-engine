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


# ---------------------------------------------------------------------------
# OWASP Agentic Top 10 (2026) — direct probe -> ASI mappings + merged classify
# ---------------------------------------------------------------------------


def test_valid_agentic_categories_is_the_full_top_ten() -> None:
    from integration_bridge.owasp_mapper import VALID_AGENTIC_CATEGORIES

    assert VALID_AGENTIC_CATEGORIES == {
        "ASI01", "ASI02", "ASI03", "ASI04", "ASI05",
        "ASI06", "ASI07", "ASI08", "ASI09", "ASI10",
    }


@pytest.mark.parametrize(
    ("probe_name", "expected_asi"),
    [
        ("tool_misuse.UnauthorizedAPICall", "ASI02"),
        ("unauthorized_tool.ShellAccess", "ASI02"),
        ("inter_agent.SpoofedMessage", "ASI07"),
        ("agent_communication.MissingSignature", "ASI07"),
        ("cascading.ConfidenceCollapse", "ASI08"),
        ("circuit_breaker.OpenStateAbuse", "ASI08"),
        ("rogue_agent.GoalDeviation", "ASI10"),
        ("autonomous_action.ScopeOverrun", "ASI10"),
    ],
)
def test_map_probe_to_agentic_direct_patterns(
    probe_name: str, expected_asi: str
) -> None:
    assert OwaspMapper.map_probe_to_agentic(probe_name) == [expected_asi]


def test_map_probe_to_agentic_returns_empty_for_pure_llm_probe() -> None:
    """Probes without an explicit ASI direct mapping return ``[]``."""
    assert OwaspMapper.map_probe_to_agentic("dan.DAN_Jailbreak") == []


def test_classify_merges_cross_map_and_direct_agentic() -> None:
    """``tool_misuse.X`` should produce LLM06 + [ASI03 (cross-map), ASI02 (direct)]."""
    llm_code, agentic = OwaspMapper.classify("tool_misuse.UnauthorizedAPICall")
    assert llm_code == "LLM06"
    # ASI03 from the LLM06 cross-map appears first; ASI02 from the
    # direct probe pattern is appended.
    assert agentic == ["ASI03", "ASI02"]


def test_classify_deduplicates_when_cross_map_and_direct_overlap() -> None:
    """If the same ASI is suggested by both sources, it appears once."""
    # Hypothetical: cascading.X maps to LLM10 (cross-map ASI08) AND
    # the direct pattern also yields ASI08. The merge keeps a single
    # entry.
    llm_code, agentic = OwaspMapper.classify("cascading.ConfidenceCollapse")
    assert llm_code == "LLM10"
    assert agentic == ["ASI08"]
    # Sanity: order is preserved (cross-map first).
    assert agentic.count("ASI08") == 1


def test_classify_for_rogue_agent_returns_llm06_and_asi03_plus_asi10() -> None:
    """Rogue-agent probe gets both ASI03 (privilege abuse) AND ASI10 (rogue)."""
    llm_code, agentic = OwaspMapper.classify("rogue_agent.GoalDeviation")
    assert llm_code == "LLM06"
    assert agentic == ["ASI03", "ASI10"]


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
