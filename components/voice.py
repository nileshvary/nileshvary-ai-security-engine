"""Browser-side Web Speech API for RemediAX (TTS).

# VOICE IS FREE - NO API CALLS EVER

This module is required to be Claude-free. It must not import or
reference ``components.ai_client``, ``anthropic``, ``openai``, or any
other LLM / transcription network client. All speech synthesis is
performed by the browser via ``window.speechSynthesis``; per-finding
content comes from the pre-written ``OWASP_CONTENT`` dictionary.

The regression tests
``tests/app/test_voice.py::test_voice_module_has_zero_ai_imports`` and
``test_voice_module_only_uses_safe_imports`` enforce this contract
and fail CI if anyone introduces a Claude / OpenAI / Anthropic import
in this module.

Design (per the v1 spec):

* ``inject_speech(text)`` mounts a zero-height iframe whose
  ``<script>`` element calls ``speechSynthesis.speak(...)`` on load.
* ``render_voice_test()`` mounts the same iframe with the canned
  "voice test successful" message — used by the sidebar Test button.
* ``render_listen_button(finding, idx, total)`` mounts a Streamlit
  button per finding; on click it triggers ``inject_speech`` with the
  pre-written script for that finding. Visible regardless of the TTS
  toggle (manual playback always available).
* ``auto_read_on_navigation(finding, idx, total, *, enabled)``
  auto-plays when the TTS toggle is on AND the user navigates to a
  new finding (tracked via session state). No-op otherwise.
* ``consume_voice_command()`` is a stub that always returns ``None``
  — STT is "basic stub for now" per the v1 spec.

Voice features must work identically for Basic / Premium / Admin
users. No tier checks exist in this module; callers should not add
them.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from integration_bridge.models import Finding


# Sidebar Test button JS, verbatim from the spec.
_TEST_SPEECH_SCRIPT = (
    "<script>"
    "window.speechSynthesis.cancel();"
    "var msg = new SpeechSynthesisUtterance("
    "'RemediAX voice test successful. "
    "Voice features are working correctly.'"
    ");"
    "msg.rate = 0.9;"
    "msg.lang = 'en-US';"
    "window.speechSynthesis.speak(msg);"
    "</script>"
)


def _safe_json(value: str) -> str:
    """JSON-encode + escape ``</`` so the result is safe inside a ``<script>`` tag.

    Plain ``json.dumps`` does NOT escape ``</script>``; embedding a
    raw response containing ``</script>`` would break out of the
    inline script and create an XSS vector. The ``</`` -> ``<\\/``
    swap is the canonical mitigation and leaves the value a valid
    JSON-encoded string.
    """
    return json.dumps(value).replace("</", "<\\/")


def _speak_script(text: str) -> str:
    """Return a self-contained ``<script>`` blob that speaks ``text``.

    Cancels any in-flight utterance first so consecutive button
    clicks don't queue up overlapping speech. ``rate=0.9`` and
    ``lang='en-US'`` match the spec's sidebar Test JS for
    consistency.
    """
    return (
        "<script>"
        "window.speechSynthesis.cancel();"
        f"var msg = new SpeechSynthesisUtterance({_safe_json(text)});"
        "msg.rate = 0.9;"
        "msg.lang = 'en-US';"
        "window.speechSynthesis.speak(msg);"
        "</script>"
    )


def build_finding_speech(
    finding: Finding,
    idx: int,
    total: int,
) -> str:
    # VOICE IS FREE - NO API CALLS EVER
    """Return the spec-format TTS script for one finding.

    Spec read-order (one item per line so the screen-reader pauses
    naturally between sections):

        Finding {n} of {total}.
        Category: {owasp_name}.
        Severity: {severity}.
        Why this is dangerous: {danger_text}
        Why this fix works: {fix_text}

    Content comes from ``OWASP_CONTENT`` only — no AI mode, no API
    cost, no network. Identical playback in Basic / Premium / Admin.
    """
    from components.owasp_content import OWASP_CONTENT

    code = finding.owasp_llm_category
    content = OWASP_CONTENT.get(code, {})
    name = content.get("name") or code
    danger = (content.get("danger_explanation") or "").strip()
    fix = (content.get("fix_explanation") or "").strip()
    return (
        f"Finding {idx + 1} of {total}.\n"
        f"Category: {name}.\n"
        f"Severity: {finding.severity}.\n"
        f"Why this is dangerous: {danger}\n"
        f"Why this fix works: {fix}"
    )


def inject_speech(text: str) -> None:
    # VOICE IS FREE - NO API CALLS EVER
    """Mount a zero-height iframe whose script speaks ``text`` on load.

    Side-effecting: must be called from inside a Streamlit run. Empty
    text is a no-op so callers don't need to guard ``inject_speech``.
    """
    if not text:
        return
    import streamlit as st

    st.components.v1.html(_speak_script(text), height=0)


def render_voice_test() -> None:
    # VOICE IS FREE - NO API CALLS EVER
    """Sidebar Test button payload — mounts the spec's canned utterance.

    Called only when the user clicks the Streamlit "🔊 Test" button.
    The iframe runs the JS once on mount; subsequent reruns (when the
    button is NOT clicked) don't re-emit speech.
    """
    import streamlit as st

    st.components.v1.html(_TEST_SPEECH_SCRIPT, height=0)


def render_listen_button(
    finding: Finding,
    idx: int,
    total: int,
) -> None:
    # VOICE IS FREE - NO API CALLS EVER
    """Render the per-finding 🔊 Listen button + click handler.

    Always visible — the TTS toggle controls auto-read elsewhere, but
    the manual Listen button stays available regardless. Works
    identically for Basic, Premium, and Admin users; no tier check
    appears anywhere in this function.
    """
    import streamlit as st

    if st.button(
        "🔊 Listen",
        key=f"voice-listen-btn-{idx}",
        use_container_width=True,
    ):
        inject_speech(build_finding_speech(finding, idx, total))


def auto_read_on_navigation(
    finding: Finding,
    idx: int,
    total: int,
    *,
    enabled: bool,
) -> None:
    # VOICE IS FREE - NO API CALLS EVER
    """Auto-play the finding's TTS when the user navigates to it.

    Only fires when ``enabled`` is True AND the finding index has
    changed since the previous rerun (tracked in
    ``st.session_state["voice_last_idx"]``). Returning early when
    ``enabled`` is False also clears the tracker so re-enabling the
    toggle on the same finding triggers a fresh playback.
    """
    import streamlit as st

    if not enabled:
        st.session_state.pop("voice_last_idx", None)
        return
    if st.session_state.get("voice_last_idx") == idx:
        return
    st.session_state["voice_last_idx"] = idx
    inject_speech(build_finding_speech(finding, idx, total))


def render_voice_command_mic() -> None:
    # VOICE IS FREE - NO API CALLS EVER
    """Render the mic indicator when the voice-commands toggle is on.

    Stub for the v1 voice commands feature — surfaces a visual cue
    so users know the toggle is engaged, but does not yet wire up
    the underlying Speech Recognition handler.
    """
    import streamlit as st

    st.caption("🎤 Voice commands enabled (basic mode)")


def consume_voice_command() -> str | None:
    # VOICE IS FREE - NO API CALLS EVER
    """Stub: voice-command STT is not wired in the v1 rewrite.

    Kept so existing call sites in ``app.py`` don't crash; always
    returns ``None`` so no command is routed. A future revision will
    implement Speech Recognition + ``?cmd=...`` routing.
    """
    return None
