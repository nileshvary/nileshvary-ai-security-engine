"""Browser-side Web Speech API wrappers (TTS + STT).

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


def get_voice_js(text_to_speak: str | None = None, listen: bool = False) -> str:
    """Build a self-contained HTML+JS blob for TTS and (optional) STT.

    Args:
        text_to_speak: When provided and non-empty, the page speaks
            this text immediately on load.
        listen: When True, the page wires up a microphone button that
            starts the Web Speech recognition on click.

    Returns:
        A complete ``<div><style><script>`` blob ready for
        ``st.components.v1.html(..., height=...)``.
    """
    speak_text_json = json.dumps(text_to_speak or "")
    commands_json = json.dumps(_VOICE_COMMANDS)
    listen_flag = "true" if listen else "false"

    return f"""
<div id="remediax-voice" style="font-family: monospace; color: #8b949e; padding: 6px 0;">
  <span id="rx-voice-status">🔈 Voice ready</span>
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
  const statusEl = document.getElementById("rx-voice-status");
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

  if (SPEAK_TEXT) {{
    if (window.speechSynthesis &&
        window.speechSynthesis.getVoices().length === 0) {{
      window.speechSynthesis.onvoiceschanged = () => speak(SPEAK_TEXT);
    }} else {{
      speak(SPEAK_TEXT);
    }}
  }}

  const sr = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (SHOULD_LISTEN && sr) {{
    micBtn.style.display = "inline-block";
    micBtn.addEventListener("click", startListening);
  }}
}})();
</script>
"""


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
