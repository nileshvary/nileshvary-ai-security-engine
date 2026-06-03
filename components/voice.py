"""Browser-side Web Speech API wrappers (TTS + STT).

# VOICE IS FREE - NO API CALLS EVER

This module is required to be Claude-free. It must not import or
reference ``components.ai_client``, ``anthropic``, ``openai``, or any
other LLM/transcription network client. All speech synthesis is
performed by the browser via ``window.speechSynthesis``; all speech
recognition by ``window.SpeechRecognition``. Content for finding
read-aloud comes from the pre-written ``OWASP_CONTENT`` dictionary,
NOT from any AI model.

The regression test ``tests/app/test_voice.py::
test_voice_module_has_zero_ai_imports`` enforces this contract and
will fail CI if anyone introduces a Claude / OpenAI / Anthropic
import in this module.

Returns one HTML/JS blob to embed via ``st.components.v1.html``. The JS
itself feature-detects ``window.speechSynthesis`` and
``window.webkitSpeechRecognition``; on browsers without support, the
controls render as disabled hints and no errors are thrown.

The voice-command → Python bridge uses ``window.location.search``: when
a recognised command fires, the JS rewrites the URL to include
``?cmd=approve`` (or skip, view, repeat, previous, summary). The next
Streamlit run picks the value up via ``st.query_params`` and routes the
action server-side.
"""

from __future__ import annotations

import html
import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from integration_bridge.models import Finding


_VOICE_COMMANDS: dict[str, str] = {
    "approve": "approve",
    "yes": "approve",
    "patch": "approve",
    "confirm": "approve",
    "skip": "skip",
    "no": "skip",
    "dismiss": "skip",
    "next": "skip",
    "view": "view",
    "show": "view",
    "details": "view",
    "repeat": "repeat",
    "again": "repeat",
    "previous": "previous",
    "back": "previous",
    "last": "previous",
    "summary": "summary",
    "overview": "summary",
}


def get_voice_js(
    text_to_speak: str | None = None,
    listen: bool = False,
    *,
    manual_listen_button: bool = False,
) -> str:
    # VOICE IS FREE - NO API CALLS EVER
    """Build a self-contained HTML+JS blob for TTS and (optional) STT.

    Args:
        text_to_speak: The text to feed the Web Speech API. Behavior
            depends on ``manual_listen_button``:

            * ``False`` (default): page speaks immediately on load.
            * ``True``: speech is gated behind a 🔊 Listen button —
              nothing is read until the user clicks.
        listen: When True, the page also wires up a 🎤 microphone
            button that starts Web Speech recognition for voice
            commands (approve / skip / view / repeat / etc.).
        manual_listen_button: When True, suppress auto-speak and
            render a 🔊 Listen button that the user clicks to hear
            ``text_to_speak``. Used by the review screen's per-
            finding listen widget.

    Returns:
        A complete ``<div><script>`` blob ready for
        ``st.components.v1.html(..., height=...)``.
    """
    # json.dumps does NOT escape ``</`` — embedded ``</script>`` in
    # user-supplied text would break out of the inline <script> tag.
    # Replace every ``</`` with ``<\/`` (still valid JSON / JS, but
    # safe inside an HTML <script> block). Apply to every JSON-
    # encoded value we drop into the template.
    def _safe_json(value: object) -> str:
        return json.dumps(value).replace("</", "<\\/")

    speak_text_json = _safe_json(text_to_speak or "")
    commands_json = _safe_json(_VOICE_COMMANDS)
    listen_flag = "true" if listen else "false"
    auto_speak_flag = (
        "true" if (text_to_speak and not manual_listen_button) else "false"
    )
    show_listen_button_flag = (
        "true" if (text_to_speak and manual_listen_button) else "false"
    )

    return f"""
<div id="remediax-voice" style="font-family: monospace; color: #8b949e; padding: 6px 0;">
  <span id="rx-voice-status">🔈 Voice ready</span>
  <button id="rx-listen-btn" type="button"
          style="margin-left: 12px; background:#0d1117; color:#00ff88;
                 border:1px solid #00ff88; border-radius:4px; padding:4px 10px;
                 cursor:pointer; font-weight:600; display:none;">
    🔊 Listen
  </button>
  <button id="rx-mic-btn" type="button"
          style="margin-left: 12px; background:#0d1117; color:#00d4ff;
                 border:1px solid #00d4ff; border-radius:4px; padding:4px 10px;
                 cursor:pointer; display:none;">
    🎤 Listen
  </button>
</div>
<script>
(function() {{
  const SPEAK_TEXT = {speak_text_json};
  const COMMANDS = {commands_json};
  const SHOULD_LISTEN = {listen_flag};
  const AUTO_SPEAK = {auto_speak_flag};
  const SHOW_LISTEN_BTN = {show_listen_button_flag};
  const statusEl = document.getElementById("rx-voice-status");
  const listenBtn = document.getElementById("rx-listen-btn");
  const micBtn = document.getElementById("rx-mic-btn");

  function speak(text) {{
    if (!text || !window.speechSynthesis) return;
    try {{
      window.speechSynthesis.cancel();
      const u = new SpeechSynthesisUtterance(text);
      u.lang = "en-US";
      u.rate = 0.95;
      u.pitch = 1.0;
      u.volume = 1.0;
      const voices = window.speechSynthesis.getVoices();
      const preferred = voices.find(v =>
        v.name.includes("Google") && v.lang === "en-US"
      );
      if (preferred) u.voice = preferred;
      window.speechSynthesis.speak(u);
    }} catch (err) {{
      // Silently no-op — TTS is best-effort.
    }}
  }}

  function setQueryCommand(cmd) {{
    try {{
      const url = new URL(window.parent.location.href);
      url.searchParams.set("cmd", cmd);
      url.searchParams.set("ts", Date.now().toString());
      window.parent.location.replace(url.toString());
    }} catch (err) {{
      // Cross-origin: ignore.
    }}
  }}

  function startListening() {{
    const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
    if (!SR) return;
    const r = new SR();
    r.lang = "en-US";
    r.continuous = false;
    r.interimResults = false;
    r.onresult = (e) => {{
      const transcript = e.results[0][0].transcript.toLowerCase().trim();
      statusEl.textContent = "Heard: " + transcript;
      for (const phrase in COMMANDS) {{
        if (transcript.includes(phrase)) {{
          setQueryCommand(COMMANDS[phrase]);
          return;
        }}
      }}
    }};
    r.onerror = () => {{ statusEl.textContent = "🔈 Voice idle"; }};
    r.onend = () => {{ statusEl.textContent = "🔈 Voice idle"; }};
    statusEl.textContent = "🎤 Listening...";
    try {{ r.start(); }} catch (err) {{
      statusEl.textContent = "🔈 Voice unavailable";
    }}
  }}

  // Auto-speak on load (legacy behavior — used by complete /
  // remediation-complete screens that emit a short status string).
  if (SPEAK_TEXT && AUTO_SPEAK) {{
    if (window.speechSynthesis &&
        window.speechSynthesis.getVoices().length === 0) {{
      window.speechSynthesis.onvoiceschanged = () => speak(SPEAK_TEXT);
    }} else {{
      speak(SPEAK_TEXT);
    }}
  }}

  // Manual 🔊 Listen button — used by per-finding review widgets
  // so the user controls when (and whether) the pre-written content
  // gets read aloud.
  if (SPEAK_TEXT && SHOW_LISTEN_BTN) {{
    listenBtn.style.display = "inline-block";
    listenBtn.addEventListener("click", () => speak(SPEAK_TEXT));
  }}

  const sr = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (SHOULD_LISTEN && sr) {{
    micBtn.style.display = "inline-block";
    micBtn.addEventListener("click", startListening);
  }}
}})();
</script>
"""


def build_finding_speech(
    finding: Finding,
    idx: int,
    total: int,
) -> str:
    # VOICE IS FREE - NO API CALLS EVER
    """Return the pre-written TTS script for one finding.

    Pulled entirely from ``components.owasp_content.OWASP_CONTENT`` so
    the same text is read in Basic mode AND Enhanced mode — no Claude
    call, no API cost. Read order matches the product spec exactly,
    one item per line so a screen-reader pauses naturally between
    sections:

        Finding {n} of {total}.
        Category: {name}. Severity: {sev}.
        Why this is dangerous: {danger_explanation}
        Why this fix works: {fix_explanation}

    Args:
        finding: The ``Finding`` whose category drives the lookup.
        idx: Zero-based index of this finding in the review list.
            Surfaced to the user as ``idx + 1``.
        total: Total finding count in the review.

    Returns:
        A single string ready to hand to ``get_voice_js`` /
        ``escape_for_speech``.
    """
    # Local import to keep this module standalone for tests that
    # don't need the heavyweight owasp_content load path.
    from components.owasp_content import OWASP_CONTENT

    code = finding.owasp_llm_category
    content = OWASP_CONTENT.get(code, {})
    name = content.get("name") or code
    danger = (content.get("danger_explanation") or "").strip()
    fix = (content.get("fix_explanation") or "").strip()

    return (
        f"Finding {idx + 1} of {total}.\n"
        f"Category: {name}. Severity: {finding.severity}.\n"
        f"Why this is dangerous: {danger}\n"
        f"Why this fix works: {fix}"
    )


def consume_voice_command() -> str | None:
    """Return the latest voice command from Streamlit's query params, if any.

    The query param is cleared after reading so subsequent reruns do
    not re-fire the same command.

    Returns:
        One of ``"approve"``, ``"skip"``, ``"view"``, ``"repeat"``,
        ``"previous"``, ``"summary"``, or ``None`` if no command is set.
    """
    import streamlit as st

    params = st.query_params
    cmd = params.get("cmd")
    if cmd is None:
        return None
    if isinstance(cmd, list):
        cmd = cmd[0] if cmd else None
    # Clear ONLY the voice-command keys so the same command does not
    # re-fire on the next rerun. Other query params (notably the
    # remember-me token ``t``) must be preserved or auto-login breaks.
    for key in ("cmd", "ts"):
        try:
            if key in st.query_params:
                del st.query_params[key]
        except Exception:  # pragma: no cover - defensive
            pass
    valid = {"approve", "skip", "view", "repeat", "previous", "summary"}
    return cmd if cmd in valid else None


def escape_for_speech(text: str) -> str:
    """Strip markup so screen-readers / TTS produce clean prose."""
    return html.unescape(text)
