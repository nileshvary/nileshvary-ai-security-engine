"""Tests for the TTS Listen-button speech builder + voice JS rendering.

# VOICE IS FREE - NO API CALLS EVER

The ``test_voice_module_has_zero_ai_imports`` and
``test_render_listen_widget_uses_only_voice_module`` tests in this
file are regression guards: if anyone ever introduces a Claude /
OpenAI / Anthropic call into the voice path, CI fails immediately.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from components.owasp_content import OWASP_CONTENT
from components.voice import build_finding_speech, get_voice_js

from tests.remediation_engine.fixtures.sample_findings import make_finding


# Modules and symbols a voice file must NEVER reach for. Add to this
# list if new LLM providers join the codebase.
_AI_DENYLIST: tuple[str, ...] = (
    "anthropic",
    "openai",
    "components.ai_client",
    "ai_client",
    "RemediAXAI",
)


# ---------------------------------------------------------------------------
# Zero-AI contract — these tests fail CI if voice ever pulls in Claude
# ---------------------------------------------------------------------------


def _imports_from_source(path: Path) -> list[str]:
    """Return every ``import X`` and ``from X import Y`` target in ``path``."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    out: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                out.append(alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                out.append(f"{module}.{alias.name}".strip("."))
                if module:
                    out.append(module)
    return out


def test_voice_module_has_zero_ai_imports() -> None:
    """``components/voice.py`` MUST NOT import any Claude / OpenAI client."""
    voice_path = Path("components/voice.py")
    imports = _imports_from_source(voice_path)
    leaked = [
        symbol
        for symbol in imports
        for denied in _AI_DENYLIST
        if denied in symbol
    ]
    assert not leaked, (
        f"components/voice.py imported AI-client symbol(s): {leaked}. "
        "VOICE IS FREE — NO API CALLS EVER."
    )


def _identifiers_used_in_function(func_source: str) -> set[str]:
    """Return every Name / Attribute / import target inside ``func_source``.

    Walks the AST so docstrings, comments, and string literals are
    ignored — we only catch actual code references. ``inspect.getsource``
    typically returns a body indented relative to its module; we
    ``textwrap.dedent`` first so ``ast.parse`` doesn't choke.
    """
    import textwrap

    tree = ast.parse(textwrap.dedent(func_source))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name)
                if alias.asname:
                    names.add(alias.asname)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module)
            for alias in node.names:
                names.add(alias.name)
                if alias.asname:
                    names.add(alias.asname)
    return names


def test_render_listen_widget_uses_only_voice_module() -> None:
    """The Listen-button renderer must not reach for Claude.

    Walks the AST of ``finding_card.py:render_listen_widget`` and
    asserts no actual code reference touches an AI module / class.
    Docstrings and comments are ignored — only real code identifiers
    are checked.
    """
    from components.finding_card import render_listen_widget

    source = inspect.getsource(render_listen_widget)
    code_identifiers = _identifiers_used_in_function(source)
    leaked = code_identifiers & set(_AI_DENYLIST)
    assert not leaked, (
        f"render_listen_widget code references AI symbol(s): {leaked}. "
        "TTS must remain Claudeless."
    )


def test_build_finding_speech_does_not_call_anthropic_at_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If anthropic.Anthropic were ever constructed, this test would fail."""
    sentinel = {"called": False}

    class _ExplodingAnthropic:
        def __init__(self, *args: object, **kwargs: object) -> None:  # noqa: D401
            sentinel["called"] = True
            raise AssertionError("VOICE IS FREE — anthropic.Anthropic instantiated")

    # Install a fake anthropic module whose Anthropic class explodes
    # the moment it's instantiated. If build_finding_speech ever ends
    # up touching it (directly or through some helper), the call
    # raises and pytest sees the failure immediately.
    import sys
    from types import SimpleNamespace

    fake = SimpleNamespace(Anthropic=_ExplodingAnthropic)
    monkeypatch.setitem(sys.modules, "anthropic", fake)

    finding = make_finding("LLM01")
    build_finding_speech(finding, idx=0, total=1)
    get_voice_js("hello world", manual_listen_button=True)

    assert sentinel["called"] is False



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
