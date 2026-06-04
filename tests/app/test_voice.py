"""Tests for the rewritten browser-side Web Speech (TTS) helpers.

# VOICE IS FREE - NO API CALLS EVER

Three regression guards in this file enforce that voice playback
never reaches for Claude / OpenAI / Anthropic. They will fail CI if
anyone ever wires an LLM call into the voice path:

    * ``test_voice_module_has_zero_ai_imports``
    * ``test_voice_helpers_have_no_ai_identifiers``
    * ``test_build_finding_speech_does_not_call_anthropic_at_runtime``
"""

from __future__ import annotations

import ast
import inspect
import textwrap
from pathlib import Path

import pytest

from components.owasp_content import OWASP_CONTENT
from components.voice import (
    _safe_json,
    _speak_script,
    _TEST_SPEECH_SCRIPT,
    build_finding_speech,
    consume_voice_command,
    render_listen_button,
    render_voice_command_mic,
    render_voice_test,
)

from tests.remediation_engine.fixtures.sample_findings import make_finding


# Modules / classes the voice path must never touch.
_AI_DENYLIST: tuple[str, ...] = (
    "anthropic",
    "openai",
    "components.ai_client",
    "ai_client",
    "RemediAXAI",
)


# ---------------------------------------------------------------------------
# build_finding_speech — spec script format
# ---------------------------------------------------------------------------


def test_speech_format_matches_product_spec() -> None:
    """Five items per spec, each on its own line, in documented order."""
    finding = make_finding("LLM01", severity="CRITICAL")
    speech = build_finding_speech(finding, idx=0, total=7)
    lines = speech.split("\n")

    assert lines[0] == "Finding 1 of 7."
    assert lines[1] == "Category: Prompt Injection."
    assert lines[2] == "Severity: CRITICAL."
    assert lines[3].startswith("Why this is dangerous: ")
    assert lines[4].startswith("Why this fix works: ")


def test_speech_uses_one_based_finding_number() -> None:
    """idx is zero-based; the spoken number is human-readable (1-based)."""
    finding = make_finding("LLM01")
    speech = build_finding_speech(finding, idx=4, total=10)
    assert speech.startswith("Finding 5 of 10.\n")


def test_speech_pulls_danger_and_fix_text_verbatim() -> None:
    finding = make_finding("LLM01")
    speech = build_finding_speech(finding, idx=0, total=1)
    assert OWASP_CONTENT["LLM01"]["danger_explanation"].strip() in speech
    assert OWASP_CONTENT["LLM01"]["fix_explanation"].strip() in speech


@pytest.mark.parametrize("code", sorted(OWASP_CONTENT.keys()))
def test_speech_covers_every_owasp_llm_category(code: str) -> None:
    finding = make_finding(code)
    speech = build_finding_speech(finding, idx=0, total=1)
    entry = OWASP_CONTENT[code]
    assert f"Category: {entry['name']}." in speech
    assert entry["danger_explanation"].strip() in speech
    assert entry["fix_explanation"].strip() in speech


def test_speech_falls_back_for_unknown_category() -> None:
    finding = make_finding("LLM01", owasp_llm_category="LLM99")
    speech = build_finding_speech(finding, idx=0, total=1)
    assert "Finding 1 of 1." in speech
    assert "Category: LLM99." in speech
    assert "Why this is dangerous:" in speech
    assert "Why this fix works:" in speech


@pytest.mark.parametrize("sev", ["LOW", "MEDIUM", "HIGH", "CRITICAL"])
def test_speech_uses_finding_severity_verbatim(sev: str) -> None:
    finding = make_finding("LLM01", severity=sev)
    speech = build_finding_speech(finding, idx=0, total=1)
    assert f"Severity: {sev}." in speech


# ---------------------------------------------------------------------------
# _speak_script — JS payload shape + XSS escape
# ---------------------------------------------------------------------------


def test_speak_script_contains_required_js_calls() -> None:
    js = _speak_script("hello world")
    assert "window.speechSynthesis.cancel()" in js
    assert "new SpeechSynthesisUtterance" in js
    assert "msg.rate = 0.9" in js
    assert "msg.lang = 'en-US'" in js
    assert "window.speechSynthesis.speak(msg)" in js
    assert js.startswith("<script>") and js.endswith("</script>")


def test_speak_script_json_encodes_special_characters() -> None:
    js = _speak_script('he said "hi" and \'bye\'')
    # The literal raw " survives only inside the JSON-encoded utterance,
    # never bleeds into the surrounding JS.
    assert "hi" in js
    assert "bye" in js


def test_speak_script_escapes_inline_script_close_tag() -> None:
    """``</script>`` inside user text must not break out of the inline script."""
    hostile = "innocent </script><script>alert(1)</script> tail"
    js = _speak_script(hostile)
    # The hostile closing tag must NOT appear unescaped anywhere.
    assert "</script><script>alert(1)" not in js
    # The escaped form (``<\\/script>``) DOES appear inside the JSON literal.
    assert "<\\/script>" in js


def test_safe_json_helper_escapes_close_slash() -> None:
    encoded = _safe_json("</script>")
    assert "</script>" not in encoded
    assert "<\\/script>" in encoded


# ---------------------------------------------------------------------------
# Sidebar Test JS — spec-mandated content
# ---------------------------------------------------------------------------


def test_test_speech_script_uses_spec_canned_message() -> None:
    assert (
        "RemediAX voice test successful. "
        "Voice features are working correctly." in _TEST_SPEECH_SCRIPT
    )
    assert "msg.rate = 0.9" in _TEST_SPEECH_SCRIPT
    assert "msg.lang = 'en-US'" in _TEST_SPEECH_SCRIPT
    assert "window.speechSynthesis.cancel()" in _TEST_SPEECH_SCRIPT
    assert "window.speechSynthesis.speak(msg)" in _TEST_SPEECH_SCRIPT


def test_render_voice_test_mounts_zero_height_iframe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The sidebar Test button must inject JS via a height=0 iframe per spec."""
    captured: dict[str, object] = {}

    def fake_html(payload: str, *, height: int = 200, **kw: object) -> None:  # noqa: ANN001
        captured["payload"] = payload
        captured["height"] = height

    import streamlit as st

    monkeypatch.setattr(st.components.v1, "html", fake_html)
    render_voice_test()
    assert captured["height"] == 0
    assert "voice test successful" in str(captured["payload"]).lower()


def test_inject_speech_mounts_zero_height_iframe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per-finding TTS injection must also use height=0 per spec."""
    from components.voice import inject_speech

    captured: dict[str, object] = {}

    def fake_html(payload: str, *, height: int = 200, **kw: object) -> None:  # noqa: ANN001
        captured["payload"] = payload
        captured["height"] = height

    import streamlit as st

    monkeypatch.setattr(st.components.v1, "html", fake_html)
    inject_speech("hello")
    assert captured["height"] == 0
    assert "hello" in str(captured["payload"])


def test_inject_speech_is_noop_for_empty_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from components.voice import inject_speech

    called = {"yes": False}

    def fake_html(*args: object, **kw: object) -> None:
        called["yes"] = True

    import streamlit as st

    monkeypatch.setattr(st.components.v1, "html", fake_html)
    inject_speech("")
    assert called["yes"] is False


# ---------------------------------------------------------------------------
# auto_read_on_navigation — fires on idx change, no-op when disabled
# ---------------------------------------------------------------------------


def _fake_session_state() -> dict:
    """A dict that doubles as a stand-in for st.session_state in tests."""
    return {}


def test_auto_read_skips_when_disabled(monkeypatch: pytest.MonkeyPatch) -> None:
    from components.voice import auto_read_on_navigation

    fake_state = _fake_session_state()
    fake_state["voice_last_idx"] = 3  # any previous tracker
    called = {"yes": False}

    def fake_html(*args: object, **kw: object) -> None:
        called["yes"] = True

    import streamlit as st

    monkeypatch.setattr(st, "session_state", fake_state)
    monkeypatch.setattr(st.components.v1, "html", fake_html)

    auto_read_on_navigation(make_finding("LLM01"), idx=0, total=3, enabled=False)
    assert called["yes"] is False
    # The tracker is cleared so re-enabling triggers a fresh read.
    assert "voice_last_idx" not in fake_state


def test_auto_read_fires_when_idx_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from components.voice import auto_read_on_navigation

    fake_state = _fake_session_state()
    payloads: list[str] = []

    def fake_html(payload: str, *, height: int = 200, **kw: object) -> None:  # noqa: ANN001
        payloads.append(payload)

    import streamlit as st

    monkeypatch.setattr(st, "session_state", fake_state)
    monkeypatch.setattr(st.components.v1, "html", fake_html)

    finding = make_finding("LLM07", severity="HIGH")
    auto_read_on_navigation(finding, idx=2, total=5, enabled=True)
    # One iframe mounted on first call.
    assert len(payloads) == 1
    assert fake_state["voice_last_idx"] == 2
    # Same idx → no re-emit on next rerun.
    auto_read_on_navigation(finding, idx=2, total=5, enabled=True)
    assert len(payloads) == 1
    # Navigating to a new finding triggers a fresh read.
    auto_read_on_navigation(finding, idx=3, total=5, enabled=True)
    assert len(payloads) == 2


# ---------------------------------------------------------------------------
# render_listen_button — manual playback works regardless of TTS toggle
# ---------------------------------------------------------------------------


def test_render_listen_button_invokes_streamlit_button(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Just verifies the button widget is registered with a deterministic key."""
    captured: dict[str, object] = {}

    def fake_button(label: str, *, key: str | None = None, **kw: object) -> bool:  # noqa: ANN001
        captured["label"] = label
        captured["key"] = key
        return False  # not clicked

    import streamlit as st

    monkeypatch.setattr(st, "button", fake_button)
    render_listen_button(make_finding("LLM01"), idx=2, total=4)
    assert captured["label"] == "🔊 Listen"
    assert captured["key"] == "voice-listen-btn-2"


def test_render_listen_button_speaks_on_click(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When the Streamlit button reports a click, inject_speech runs."""
    monkeypatch.setattr("streamlit.button", lambda *a, **kw: True)
    payloads: list[str] = []

    def fake_html(payload: str, *, height: int = 200, **kw: object) -> None:  # noqa: ANN001
        payloads.append(payload)

    import streamlit as st

    monkeypatch.setattr(st.components.v1, "html", fake_html)
    render_listen_button(make_finding("LLM01"), idx=0, total=1)
    assert len(payloads) == 1
    assert "Finding 1 of 1." in payloads[0]


def test_render_voice_command_mic_emits_caption(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The voice-commands toggle stub surfaces a visible indicator."""
    captions: list[str] = []
    monkeypatch.setattr("streamlit.caption", lambda text: captions.append(text))
    render_voice_command_mic()
    assert any("🎤" in c for c in captions)


def test_consume_voice_command_returns_none() -> None:
    """v1 stub: STT is not wired yet."""
    assert consume_voice_command() is None


# ---------------------------------------------------------------------------
# Tier-agnostic — voice helpers reference no tier/role state
# ---------------------------------------------------------------------------


_TIER_TERMS: tuple[str, ...] = (
    "is_admin",
    "_has_premium",
    "_is_unlimited_tier",
    "user_tier",
    "premium",
    "analyst",
    "tier",
)


def test_voice_module_does_not_reference_tier_state() -> None:
    """No symbol in voice.py touches the user's tier — works for everyone."""
    voice_src = Path("components/voice.py").read_text(encoding="utf-8")
    tree = ast.parse(voice_src)
    identifiers: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            identifiers.add(node.id)
        elif isinstance(node, ast.Attribute):
            identifiers.add(node.attr)
    leaked = identifiers & set(_TIER_TERMS)
    assert not leaked, (
        f"voice.py references tier symbol(s) {leaked}; voice must work "
        "for Basic / Premium / Admin equally."
    )


# ---------------------------------------------------------------------------
# Zero-AI contract — three regression guards
# ---------------------------------------------------------------------------


def _imports_from_source(path: Path) -> list[str]:
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


def _identifiers_used_in_function(func_source: str) -> set[str]:
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
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                names.add(node.module)
            for alias in node.names:
                names.add(alias.name)
    return names


def test_voice_module_has_zero_ai_imports() -> None:
    """components/voice.py MUST NOT import any Claude / OpenAI client."""
    imports = _imports_from_source(Path("components/voice.py"))
    leaked = [s for s in imports for d in _AI_DENYLIST if d in s]
    assert not leaked, (
        f"components/voice.py imports AI-client symbol(s): {leaked}. "
        "VOICE IS FREE — NO API CALLS EVER."
    )


@pytest.mark.parametrize(
    "fn",
    [
        build_finding_speech,
        render_listen_button,
        render_voice_test,
        render_voice_command_mic,
    ],
)
def test_voice_helpers_have_no_ai_identifiers(fn) -> None:  # noqa: ANN001
    """Walk each helper's AST — no code identifier may match the AI denylist."""
    source = inspect.getsource(fn)
    identifiers = _identifiers_used_in_function(source)
    leaked = identifiers & set(_AI_DENYLIST)
    assert not leaked, (
        f"{fn.__name__} references AI symbol(s): {leaked}. "
        "TTS must remain Claudeless."
    )


def test_build_finding_speech_does_not_call_anthropic_at_runtime(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """If anthropic.Anthropic were ever constructed, this test fails."""
    sentinel = {"called": False}

    class _ExplodingAnthropic:
        def __init__(self, *a: object, **kw: object) -> None:
            sentinel["called"] = True
            raise AssertionError("VOICE IS FREE — anthropic.Anthropic instantiated")

    import sys
    from types import SimpleNamespace

    monkeypatch.setitem(
        sys.modules, "anthropic", SimpleNamespace(Anthropic=_ExplodingAnthropic)
    )
    build_finding_speech(make_finding("LLM01"), idx=0, total=1)
    _speak_script("hello")
    assert sentinel["called"] is False
