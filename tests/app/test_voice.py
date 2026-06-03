"""Tests for the TTS Listen-button speech builder + voice JS rendering."""

from __future__ import annotations

import pytest

from components.owasp_content import OWASP_CONTENT
from components.voice import build_finding_speech, get_voice_js

from tests.remediation_engine.fixtures.sample_findings import make_finding


# ---------------------------------------------------------------------------
# build_finding_speech — exact product-spec script
# ---------------------------------------------------------------------------


def test_speech_format_matches_product_spec() -> None:
    """Four items per spec, one per line, in the documented order."""
    finding = make_finding("LLM01", severity="CRITICAL")
    speech = build_finding_speech(finding, idx=0, total=7)

    lines = speech.split("\n")
    # Item 1 — number on its own line.
    assert lines[0] == "Finding 1 of 7."
    # Item 2 — category + severity together (single line per spec).
    assert lines[1] == "Category: Prompt Injection. Severity: CRITICAL."
    # Item 3 — why dangerous.
    assert lines[2].startswith("Why this is dangerous: ")
    # Item 4 — why fix works.
    assert lines[3].startswith("Why this fix works: ")


def test_speech_uses_one_based_finding_number() -> None:
    """idx is zero-based but the spoken number is human-readable (1-based)."""
    finding = make_finding("LLM01")
    speech = build_finding_speech(finding, idx=4, total=10)
    assert speech.startswith("Finding 5 of 10.\n")


def test_speech_pulls_danger_and_fix_text_verbatim() -> None:
    """No paraphrasing — exact OWASP_CONTENT strings get spoken."""
    finding = make_finding("LLM01")
    speech = build_finding_speech(finding, idx=0, total=1)

    expected_danger = OWASP_CONTENT["LLM01"]["danger_explanation"].strip()
    expected_fix = OWASP_CONTENT["LLM01"]["fix_explanation"].strip()

    assert expected_danger in speech
    assert expected_fix in speech


@pytest.mark.parametrize("code", sorted(OWASP_CONTENT.keys()))
def test_speech_covers_every_owasp_llm_category(code: str) -> None:
    """No category is missing danger / fix text or its human-readable name."""
    finding = make_finding(code)
    speech = build_finding_speech(finding, idx=0, total=1)
    entry = OWASP_CONTENT[code]
    assert f"Category: {entry['name']}." in speech
    assert entry["danger_explanation"].strip() in speech
    assert entry["fix_explanation"].strip() in speech


def test_speech_falls_back_for_unknown_category() -> None:
    """A finding with a category outside OWASP_CONTENT still produces a script.

    Defensive — the parser validates categories before construction,
    but the speech builder should never crash if upstream changes
    introduce a new code before OWASP_CONTENT is updated.
    """
    finding = make_finding(
        "LLM01",
        owasp_llm_category="LLM99",  # not in the taxonomy
    )
    speech = build_finding_speech(finding, idx=0, total=1)
    assert "Finding 1 of 1." in speech
    # Falls back to the bare code as the category label.
    assert "Category: LLM99." in speech
    # Sections are still present with empty values, not missing.
    assert "Why this is dangerous:" in speech
    assert "Why this fix works:" in speech


def test_speech_uses_finding_severity_verbatim() -> None:
    for sev in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        finding = make_finding("LLM01", severity=sev)
        speech = build_finding_speech(finding, idx=0, total=1)
        assert f"Severity: {sev}." in speech


# ---------------------------------------------------------------------------
# get_voice_js — Listen button mode
# ---------------------------------------------------------------------------


def test_manual_listen_button_renders_listen_button_and_suppresses_autoplay() -> None:
    js = get_voice_js("hello world", manual_listen_button=True)
    # The constants used by the JS branches:
    assert "const AUTO_SPEAK = false;" in js
    assert "const SHOW_LISTEN_BTN = true;" in js
    # And the button HTML actually shows up.
    assert "🔊 Listen" in js
    assert 'id="rx-listen-btn"' in js
    # Click handler is wired up — the on-click triggers speak(SPEAK_TEXT).
    assert "listenBtn.addEventListener" in js


def test_default_mode_auto_speaks_no_listen_button() -> None:
    js = get_voice_js("hello")
    assert "const AUTO_SPEAK = true;" in js
    assert "const SHOW_LISTEN_BTN = false;" in js


def test_no_text_means_no_autoplay_no_listen_button() -> None:
    js = get_voice_js("")
    assert "const AUTO_SPEAK = false;" in js
    assert "const SHOW_LISTEN_BTN = false;" in js


def test_speak_text_is_json_encoded_into_the_js() -> None:
    """Hostile input must be JSON-escaped, not interpolated raw."""
    js = get_voice_js(
        "hello \"</script><script>alert('xss')</script>",
        manual_listen_button=True,
    )
    # The bare </script> tag must not appear unescaped — JSON encoding
    # turns it into "<\/script>" or "</script>".
    assert "</script><script>" not in js


def test_listen_mode_for_voice_commands_unaffected_by_manual_listen_button() -> None:
    """The microphone (voice-commands) listen flag is independent of TTS mode."""
    js = get_voice_js("anything", listen=True, manual_listen_button=True)
    assert "const SHOULD_LISTEN = true;" in js
    assert "const SHOW_LISTEN_BTN = true;" in js
