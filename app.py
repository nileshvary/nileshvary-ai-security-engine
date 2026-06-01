"""RemediAX — Streamlit web UI wrapping the AI Security Remediation Engine.

Run with:
    streamlit run app.py

This module only orchestrates UI state and dispatches to per-screen
renderers. The actual security work is delegated to the same engine the
CLI uses (``integration_bridge``, ``remediation_engine``, ``verifier``,
``output``) — nothing in ``src/`` is modified.
"""

from __future__ import annotations

import logging
import shutil
import sys
import tempfile
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any

# Streamlit Community Cloud does not support editable installs ("-e .")
# in requirements.txt, so the engine packages under src/ are NOT on
# sys.path when the app boots there. Prepend it explicitly so imports
# like ``from integration_bridge import ...`` resolve. Harmless locally
# because the dev venv already has the package installed editably.
_SRC_DIR = Path(__file__).parent / "src"
if str(_SRC_DIR) not in sys.path:
    sys.path.insert(0, str(_SRC_DIR))

import streamlit as st

from admin.panel import render_admin_panel
from auth.rate_limiter import RateLimiter
from auth.session_manager import (
    initialize_state,
    is_admin,
    logout,
    reset_to_landing,
)
from auth.token_manager import TokenManager
from components.ai_client import RemediAXAI
from components.finding_card import (
    render_finding,
    render_patch_panel,
    render_tools_panel,
)
from components.owasp_content import (
    ACTIVE_CATEGORIES,
    ESCALATION_CATEGORIES,
    OWASP_CONTENT,
)
from components.voice import (
    consume_voice_command,
    escape_for_speech,
    get_voice_js,
)
from demo_data import load_demo_findings

from integration_bridge import Finding, GarakParser
from output import OutputOrchestrator
from remediation_engine import (
    GuardrailGenerator,
    RemediationOrchestrator,
)
from verifier import VerificationOrchestrator

logger = logging.getLogger(__name__)

_RUNS_ROOT = Path("_remediax_runs")
_GITHUB_URL = "https://github.com/nileshvary/nileshvary-ai-security-engine"
_REMEMBER_PARAM = "t"
_SCREEN_PARAM = "p"
_RESTORABLE_SCREENS: frozenset[str] = frozenset(
    {"landing", "summary", "review", "complete", "results", "admin"}
)


def _read_query_token() -> str | None:
    """Return the remember-me token from ``st.query_params["t"]`` or ``None``."""
    try:
        raw = st.query_params.get(_REMEMBER_PARAM)
    except Exception:  # pragma: no cover - defensive
        return None
    if raw is None:
        return None
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    if not raw:
        return None
    return str(raw).strip()


def _persist_token(raw_token: str) -> None:
    """Persist ``raw_token`` in the URL via a query param for refresh-survival.

    This puts the token in the address bar — see security note at the
    top of this file. We strip whitespace so accidental newlines do not
    propagate into URLs.
    """
    try:
        st.query_params[_REMEMBER_PARAM] = raw_token.strip()
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Failed to write remember-me token to URL: %s", exc)


def _clear_remembered_token() -> None:
    """Remove the remember-me token from the URL (no-op if not present)."""
    try:
        if _REMEMBER_PARAM in st.query_params:
            del st.query_params[_REMEMBER_PARAM]
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Failed to clear remember-me token from URL: %s", exc)


def _read_query_screen() -> str | None:
    """Return ``st.query_params['p']`` if it names a known screen, else ``None``."""
    try:
        raw = st.query_params.get(_SCREEN_PARAM)
    except Exception:  # pragma: no cover - defensive
        return None
    if raw is None:
        return None
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    value = str(raw).strip() if raw else ""
    return value if value in _RESTORABLE_SCREENS else None


def _sync_url_screen() -> None:
    """Mirror ``st.session_state.screen`` to ``st.query_params['p']``.

    Called on every authenticated rerun so that a refresh on any screen
    stays on that screen. Skipped for the access screen — unauthenticated
    URLs do not need a ``p`` marker.
    """
    screen_now = st.session_state.get("screen")
    if not screen_now or screen_now == "access":
        return
    if screen_now not in _RESTORABLE_SCREENS:
        return
    try:
        current = st.query_params.get(_SCREEN_PARAM)
        if isinstance(current, list):
            current = current[0] if current else None
        if current != screen_now:
            st.query_params[_SCREEN_PARAM] = screen_now
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Failed to sync screen to URL: %s", exc)


def _clear_screen_param() -> None:
    """Remove ``?p=`` from the URL — used on logout."""
    try:
        if _SCREEN_PARAM in st.query_params:
            del st.query_params[_SCREEN_PARAM]
    except Exception:  # pragma: no cover - defensive
        pass


def _attempt_auto_login() -> None:
    """If a remember-me token sits in ``?t=``, revalidate and log in.

    Called from ``main`` before screen dispatch. Reads are synchronous
    (no JS round-trip needed) so we can validate the token and decide
    whether to skip the access screen entirely on the very first run.
    Per the chosen design: revalidate against ``TokenManager`` on every
    fresh session so revocation and expiry are honored on refresh.
    """
    if st.session_state.authenticated:
        return
    if st.session_state.get("auto_login_tried"):
        return
    stored = _read_query_token()
    if stored is None:
        return
    # Mark the attempt before validating so repeated reruns on the same
    # bad token do not re-hit the file backend.
    st.session_state.auto_login_tried = True
    ok, _status, record = TokenManager().validate_token(
        stored, ip=_client_id()
    )
    if ok:
        st.session_state.authenticated = True
        st.session_state.token_record = record
        st.session_state.is_admin = bool(record.get("permanent"))
        # Honor a ?p= screen marker so refresh on any page lands the user
        # back on that page. Admin screen requires a permanent token.
        desired = _read_query_screen()
        if desired == "admin" and not record.get("permanent"):
            desired = None
        st.session_state.screen = desired or "landing"
        st.rerun()
    else:
        # Bad / revoked / expired token in URL — strip it so the access
        # screen renders cleanly and refresh does not re-trigger lockout.
        _clear_remembered_token()
        _clear_screen_param()


# ---------------------------------------------------------------------------
# Global theme CSS — injected once at app start
# ---------------------------------------------------------------------------

_GLOBAL_CSS = """
<style>
:root {
  --bg-primary: #0a0e1a;
  --bg-card: #0d1117;
  --bg-hover: #161b22;
  --border: #1e3a5f;
  --accent-cyan: #00d4ff;
  --accent-blue: #0080ff;
  --success: #00ff88;
  --warning: #ffaa00;
  --danger: #ff4444;
  --text-primary: #e6edf3;
  --text-secondary: #8b949e;
}
.stApp { background-color: var(--bg-primary); }
/* Generous top padding so the hero card's cyan box-shadow glow
 * (extends 30px above the box) is not clipped by the browser chrome
 * or by Streamlit's default top toolbar margin. */
.block-container { padding-top: 4rem !important; }
.remediax-hero { margin-top: 24px !important; }
h1, h2, h3, h4, h5 { color: var(--text-primary) !important; }
.remediax-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 20px;
  margin: 10px 0;
}
.ai-card {
  background: var(--bg-card);
  border: 1px solid var(--accent-cyan);
  border-radius: 8px;
  padding: 20px;
  box-shadow: 0 0 15px rgba(0,212,255,0.2);
}
@keyframes pulse {
  0% { box-shadow: 0 0 5px #00d4ff; }
  50% { box-shadow: 0 0 25px #00d4ff; }
  100% { box-shadow: 0 0 5px #00d4ff; }
}
.scanning { animation: pulse 2s infinite; }
.stProgress > div > div {
  background: linear-gradient(90deg, #00d4ff, #0080ff);
}
.remediax-hero {
  background: linear-gradient(135deg, #0a0e1a, #0d1117);
  border: 1px solid #00d4ff;
  border-radius: 12px;
  padding: 32px 40px;
  margin: 12px 0 28px;
  box-shadow: 0 0 30px rgba(0,212,255,0.15);
}
.remediax-hero h1 { color: #00d4ff !important; margin: 0; font-size: 2.6rem; }
.remediax-hero .tagline { color: #8b949e; margin-top: 4px; }
.owasp-strip { display: flex; flex-wrap: wrap; gap: 6px; margin: 12px 0; }
.owasp-strip .owasp-chip {
  font-family: monospace;
  font-size: 0.85rem;
  font-weight: 700;
  padding: 4px 10px;
  border-radius: 999px;
  color: #000;
}
.metric-card {
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 14px 18px;
  text-align: center;
}
.metric-card .value { font-size: 1.7rem; font-weight: 700; }
.metric-card .label { font-size: 0.8rem; color: var(--text-secondary); }
</style>
"""


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _client_id() -> str:
    """Best-effort stable identifier for per-IP brute-force tracking."""
    if "client_id" not in st.session_state:
        st.session_state.client_id = uuid.uuid4().hex
    return st.session_state.client_id


def _ensure_output_dir() -> Path:
    if st.session_state.output_dir is not None:
        path = Path(st.session_state.output_dir)
        path.mkdir(parents=True, exist_ok=True)
        return path
    _RUNS_ROOT.mkdir(parents=True, exist_ok=True)
    session_dir = _RUNS_ROOT / uuid.uuid4().hex[:12]
    session_dir.mkdir(parents=True, exist_ok=True)
    st.session_state.output_dir = str(session_dir)
    return session_dir


def _get_ai_client() -> RemediAXAI | None:
    """Build a RemediAXAI from session state, caching it."""
    if not st.session_state.api_mode or not st.session_state.api_key:
        return None
    cached = st.session_state.get("ai_client")
    if cached is not None:
        return cached
    try:
        client = RemediAXAI(st.session_state.api_key)
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Failed to construct RemediAXAI: %s", exc)
        return None
    st.session_state.ai_client = client
    return client


def _maybe_emit_voice(text: str) -> None:
    if st.session_state.tts_enabled or st.session_state.voice_enabled:
        st.components.v1.html(
            get_voice_js(
                escape_for_speech(text) if st.session_state.tts_enabled else None,
                listen=st.session_state.voice_enabled,
            ),
            height=60,
        )


def _apply_voice_command_to_review() -> None:
    cmd = consume_voice_command()
    if cmd is None:
        return
    if cmd == "approve":
        _approve_current_finding()
    elif cmd == "skip":
        _skip_current_finding()
    elif cmd == "previous":
        st.session_state.current_index = max(0, st.session_state.current_index - 1)
    elif cmd == "summary":
        st.session_state.screen = "summary"


def _ts_label() -> str:
    record = st.session_state.token_record or {}
    if record.get("permanent"):
        return "Token: permanent"
    expires_iso = record.get("expires")
    if not expires_iso:
        return "Token: ?"
    try:
        delta = datetime.fromisoformat(expires_iso) - datetime.utcnow()
        if delta.total_seconds() < 0:
            return "Token: expired"
        hours, remainder = divmod(int(delta.total_seconds()), 3600)
        mins = remainder // 60
        return f"⏱️ {hours}h {mins}m left"
    except ValueError:
        return "Token: unknown"


# ---------------------------------------------------------------------------
# Sidebar — settings panel (shown on every screen after auth)
# ---------------------------------------------------------------------------


def render_sidebar() -> None:
    """The Part 7 settings panel: AI mode, API key, voice, info."""
    with st.sidebar:
        st.markdown("### 🛡️ RemediAX")
        st.caption("AI Security, Human Control")

        if st.button(
            "🏠 Home",
            use_container_width=True,
            key="nav-home",
            help="Return to the landing screen from any page.",
        ):
            st.session_state.screen = "landing"
            st.rerun()

        st.divider()
        st.markdown("**AI mode**")
        mode = st.radio(
            "Mode",
            ("Basic (free)", "Enhanced (Claude)"),
            index=1 if st.session_state.api_mode else 0,
            label_visibility="collapsed",
        )
        st.session_state.api_mode = mode.startswith("Enhanced")

        if st.session_state.api_mode:
            st.markdown("**Claude API key**")
            key_input = st.text_input(
                "API key",
                value=st.session_state.api_key or "",
                type="password",
                label_visibility="collapsed",
            )
            save_col, remove_col = st.columns(2)
            if save_col.button("💾 Save", use_container_width=True):
                st.session_state.api_key = key_input.strip() or None
                st.session_state.ai_client = None  # force rebuild
                st.toast("Key saved." if st.session_state.api_key else "Key cleared.")
            if remove_col.button("🗑️ Remove", use_container_width=True):
                st.session_state.api_key = None
                st.session_state.ai_client = None
                st.toast("Key removed.")
            st.caption(
                "✅ Key saved" if st.session_state.api_key else "❌ No key — basic mode"
            )
            st.caption("Your key — you pay. Never logged or shared.")

        st.divider()
        st.markdown("**Voice features**")
        st.session_state.tts_enabled = st.toggle(
            "🔊 Text-to-Speech", value=st.session_state.tts_enabled
        )
        st.session_state.voice_enabled = st.toggle(
            "🎤 Voice commands", value=st.session_state.voice_enabled
        )
        if st.button("🔊 Test", use_container_width=True):
            st.components.v1.html(
                get_voice_js(
                    "RemediAX voice is working. You can approve or skip findings.",
                    listen=False,
                ),
                height=60,
            )

        st.divider()
        st.markdown("**Access**")
        record = st.session_state.token_record or {}
        token_id = record.get("hash", "?")[:8] if record else "—"
        st.caption(f"Token id: `{token_id}`")
        st.caption(_ts_label())
        usage = RateLimiter().usage_today(record.get("hash", "anon")[:12])
        st.caption(
            f"Scans today: {usage}/3"
            if not st.session_state.api_mode
            else f"Scans today: {usage} (unlimited)"
        )

        st.divider()
        nav_admin, nav_logout = st.columns(2)
        if is_admin():
            if nav_admin.button("👤 Admin", use_container_width=True):
                st.session_state.screen = "admin"
                st.rerun()
        else:
            nav_admin.caption("—")
        if nav_logout.button("🚪 Logout", use_container_width=True):
            _clear_remembered_token()
            _clear_screen_param()
            logout()
            st.rerun()

        st.divider()
        st.caption("RemediAX v1.0.0")
        st.caption(f"[GitHub]({_GITHUB_URL})")


# ---------------------------------------------------------------------------
# Screen 0 — Access
# ---------------------------------------------------------------------------


def render_access() -> None:
    st.markdown(
        '<div class="remediax-hero scanning"><h1>🛡️ REMEDIAX</h1>'
        '<div class="tagline">AI Security, Human Control</div></div>',
        unsafe_allow_html=True,
    )
    left, mid, right = st.columns([1, 2, 1])
    with mid:
        st.markdown("#### Access RemediAX")
        with st.form("access-form"):
            token_input = st.text_input(
                "Access token",
                type="password",
                placeholder="RMX-...",
            )
            remember_me = st.checkbox(
                "Remember me on this device",
                value=False,
                help=(
                    "Stores your token in this browser's localStorage so you "
                    "stay signed in across page refreshes. Anyone with access "
                    "to this browser profile can read it. Uncheck on shared "
                    "machines."
                ),
            )
            submit = st.form_submit_button("🔓 Access RemediAX", use_container_width=True)
        if submit:
            tm = TokenManager()
            ok, status, record = tm.validate_token(token_input, ip=_client_id())
            if ok:
                st.session_state.authenticated = True
                st.session_state.token_record = record
                st.session_state.is_admin = bool(record.get("permanent"))
                st.session_state.screen = "landing"
                if remember_me:
                    _persist_token(token_input.strip())
                else:
                    # If the user explicitly opted out, clear any
                    # previously remembered token so the choice sticks.
                    _clear_remembered_token()
                st.rerun()
            elif status.startswith("locked:"):
                mins = status.split(":", 1)[1]
                st.error(f"🚫 Too many attempts. Wait {mins}m.")
            elif status == "expired":
                st.error("⏰ Token expired. Request a new one.")
            elif status == "revoked":
                st.error("❌ Token revoked.")
            elif status.startswith("invalid:"):
                remaining = status.split(":", 1)[1]
                st.error(f"❌ Invalid token. {remaining} attempts remaining.")
            else:
                st.error(f"❌ {status}")
    st.divider()
    cols = st.columns(3)
    cols[0].caption("⏱️ Tokens are time-limited (48h default)")
    cols[1].caption("🔒 All sessions encrypted via HTTPS")
    cols[2].caption("📧 [Request access](mailto:nileshvary@gmail.com)")


# ---------------------------------------------------------------------------
# Screen 1 — Landing
# ---------------------------------------------------------------------------


def render_landing() -> None:
    st.markdown(
        '<div class="remediax-hero"><h1>🛡️ REMEDIAX</h1>'
        '<div class="tagline">Detect • Remediate • Verify • Protect</div>'
        '<div style="color:#8b949e;margin-top:6px;">'
        "Covering all 10 OWASP LLM vulnerability categories.</div></div>",
        unsafe_allow_html=True,
    )

    left, right = st.columns(2)
    with left:
        st.markdown("### 📁 Upload Scan Results")
        st.caption("Drag and drop a garak `hitlog.jsonl` or `report.jsonl`.")
        uploaded = st.file_uploader(
            "garak hitlog", type=("jsonl", "json"), label_visibility="collapsed"
        )
        if uploaded is not None and st.button("▶ Process upload", use_container_width=True):
            _ingest_uploaded(uploaded)

    with right:
        st.markdown("### ▶ Try Live Demo")
        st.caption("10 findings across all OWASP LLM Top 10 categories.")
        if st.button("▶ Load Full Demo", use_container_width=True):
            st.session_state.findings = load_demo_findings()
            st.session_state.screen = "summary"
            st.rerun()
        st.caption("Real attack patterns • All 10 LLM categories.")

    # Status bar
    cols = st.columns(3)
    cols[0].caption(
        "🔊 Voice: ON" if st.session_state.tts_enabled else "🔊 Voice: OFF"
    )
    cols[1].caption(
        "🤖 AI: Enhanced" if st.session_state.api_mode else "🤖 AI: Basic"
    )
    cols[2].caption(_ts_label())

    # OWASP coverage strip
    chips = "".join(
        f'<span class="owasp-chip" style="background:{OWASP_CONTENT[c]["color"]}">'
        f"{c}</span>"
        for c in [f"LLM{i:02d}" for i in range(1, 11)]
    )
    st.markdown(
        f'<div class="owasp-strip">{chips}</div>'
        '<div style="color:#8b949e;font-size:0.85rem;margin-top:2px;">'
        "Full OWASP LLM Top 10 coverage.</div>",
        unsafe_allow_html=True,
    )

    st.divider()
    st.caption(
        f"Built by Nileshwari Kadgale &middot; [GitHub]({_GITHUB_URL})"
    )


def _ingest_uploaded(uploaded: Any) -> None:
    """Parse the uploaded JSONL via GarakParser and advance to summary."""
    tmp_dir = Path(tempfile.mkdtemp(prefix="remediax-upload-"))
    src_path = tmp_dir / uploaded.name
    src_path.write_bytes(uploaded.getvalue())
    try:
        findings = GarakParser(src_path).parse()
    except Exception as exc:
        st.error(f"Could not parse uploaded file: {exc}")
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return
    if not findings:
        st.warning("No findings detected in this file.")
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return
    st.session_state.findings = findings
    st.session_state.screen = "summary"
    shutil.rmtree(tmp_dir, ignore_errors=True)
    st.rerun()


# ---------------------------------------------------------------------------
# Screen 2 — Scan summary
# ---------------------------------------------------------------------------


def render_summary() -> None:
    findings: list[Finding] = st.session_state.findings
    if not findings:
        st.session_state.screen = "landing"
        st.rerun()

    st.markdown("### 📊 Scan Summary")

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    cat_counts: dict[str, int] = {}
    for finding in findings:
        if finding.severity in severity_counts:
            severity_counts[finding.severity] += 1
        cat_counts[finding.owasp_llm_category] = (
            cat_counts.get(finding.owasp_llm_category, 0) + 1
        )

    cols = st.columns(4)
    metric_html = (
        '<div class="metric-card"><div class="value">{value}</div>'
        '<div class="label">{label}</div></div>'
    )
    cols[0].markdown(metric_html.format(value=len(findings), label="TOTAL"), unsafe_allow_html=True)
    cols[1].markdown(
        metric_html.format(value=severity_counts["CRITICAL"], label="CRITICAL"),
        unsafe_allow_html=True,
    )
    cols[2].markdown(
        metric_html.format(value=severity_counts["HIGH"], label="HIGH"),
        unsafe_allow_html=True,
    )
    cols[3].markdown(
        metric_html.format(
            value=severity_counts["MEDIUM"] + severity_counts["LOW"],
            label="MEDIUM / LOW",
        ),
        unsafe_allow_html=True,
    )

    st.markdown("### OWASP breakdown")
    max_count = max(cat_counts.values()) if cat_counts else 1
    for code in sorted(cat_counts):
        content = OWASP_CONTENT.get(code, {"color": "#8b949e", "name": code})
        count = cat_counts[code]
        bar_pct = int(count / max_count * 100)
        escalation = code in ESCALATION_CATEGORIES
        bar_color = "#8b949e" if escalation else content["color"]
        suffix = (
            "Escalation required"
            if escalation
            else f"{count} finding{'s' if count != 1 else ''}"
        )
        st.markdown(
            f'<div style="display:flex;align-items:center;margin:6px 0;gap:14px;">'
            f'<span class="owasp-chip" style="background:{content["color"]}">{code}</span>'
            f'<span style="color:#e6edf3;flex:0 0 220px;">{content["name"]}</span>'
            f'<div style="background:#1e3a5f;height:8px;flex:1;border-radius:4px;'
            f'overflow:hidden;"><div style="background:{bar_color};height:100%;'
            f'width:{bar_pct}%;"></div></div>'
            f'<span style="color:#8b949e;font-size:0.85rem;min-width:160px;'
            f'text-align:right;">{suffix}</span></div>',
            unsafe_allow_html=True,
        )

    # Build the pipeline lazily so the summary screen reflects real counts
    # without needing the user to click anything yet.
    _ensure_pipeline_results()
    rem_results = st.session_state.remediation_results
    active_count = sum(
        1 for r in rem_results if r.finding.owasp_llm_category in ACTIVE_CATEGORIES
    )
    esc_count = sum(
        1 for r in rem_results if r.finding.owasp_llm_category in ESCALATION_CATEGORIES
    )
    rate_count = sum(
        1
        for r in rem_results
        if r.guardrail_config is not None and r.guardrail_config.rate_limits
    )
    cols = st.columns(3)
    cols[0].markdown(
        metric_html.format(value=active_count, label="ACTIVE PATCHES"),
        unsafe_allow_html=True,
    )
    cols[1].markdown(
        metric_html.format(value=esc_count, label="ESCALATIONS"),
        unsafe_allow_html=True,
    )
    cols[2].markdown(
        metric_html.format(value=1 if rate_count else 0, label="GUARDRAILS"),
        unsafe_allow_html=True,
    )

    # AI assessment card
    ai_client = _get_ai_client()
    summary_text: str | None = None
    if ai_client is not None:
        summary_text = ai_client.summarize_scan(findings)
    if not summary_text:
        crit = severity_counts["CRITICAL"]
        high = severity_counts["HIGH"]
        summary_text = (
            f"Scan surfaced {len(findings)} finding(s) across "
            f"{len(cat_counts)} OWASP category/categories. "
            f"{crit} critical and {high} high-severity issues warrant "
            "immediate attention. Out-of-band categories require external "
            "tooling — see escalation guidance during review."
        )
    st.markdown(
        f'<div class="ai-card"><div style="color:#00d4ff;font-size:0.8rem;'
        f'letter-spacing:0.06em;margin-bottom:6px;">'
        f"{'CLAUDE ASSESSMENT' if ai_client else 'BASIC ASSESSMENT'}"
        f'</div><div>{summary_text}</div></div>',
        unsafe_allow_html=True,
    )

    if st.button("▶ START INTERACTIVE REVIEW", use_container_width=True, type="primary"):
        st.session_state.current_index = 0
        st.session_state.approved = []
        st.session_state.skipped = []
        st.session_state.screen = "review"
        st.rerun()


def _ensure_pipeline_results() -> None:
    """Idempotently build remediation + verification results from session findings."""
    if st.session_state.remediation_results:
        return
    findings: list[Finding] = st.session_state.findings
    orchestrator = RemediationOrchestrator(guardrail_format="portkey")
    results = orchestrator.remediate_findings(findings, original_prompt=None)
    verification_orchestrator = VerificationOrchestrator()
    report = verification_orchestrator.verify_all(results, mode="quick")
    st.session_state.remediation_results = results
    st.session_state.verification_report = report


# ---------------------------------------------------------------------------
# Screen 3 — Interactive review
# ---------------------------------------------------------------------------


def _approve_current_finding() -> None:
    idx = st.session_state.current_index
    if idx not in st.session_state.approved:
        st.session_state.approved.append(idx)
        if idx in st.session_state.skipped:
            st.session_state.skipped.remove(idx)
    _advance_review()


def _skip_current_finding() -> None:
    idx = st.session_state.current_index
    if idx not in st.session_state.skipped:
        st.session_state.skipped.append(idx)
        if idx in st.session_state.approved:
            st.session_state.approved.remove(idx)
    _advance_review()


def _advance_review() -> None:
    total = len(st.session_state.findings)
    next_idx = st.session_state.current_index + 1
    if next_idx >= total:
        st.session_state.screen = "complete"
    else:
        st.session_state.current_index = next_idx


def render_review() -> None:
    # ?p=review can survive a refresh, but the underlying findings list
    # cannot — it lives in session state only. Silently bounce to
    # landing when there is nothing to review.
    if not st.session_state.findings:
        st.session_state.screen = "landing"
        st.rerun()
    _ensure_pipeline_results()
    _apply_voice_command_to_review()

    findings: list[Finding] = st.session_state.findings
    results = st.session_state.remediation_results
    report = st.session_state.verification_report
    total = len(findings)
    idx = max(0, min(st.session_state.current_index, total - 1))
    st.session_state.current_index = idx

    finding = findings[idx]
    rem_result = results[idx]
    ver_result = report.results[idx] if report and idx < len(report.results) else None

    st.progress((idx + 1) / total, text=f"Finding {idx + 1} of {total}")

    nav_prev, nav_label, nav_next = st.columns([1, 6, 1])
    if nav_prev.button("◀ Prev", use_container_width=True) and idx > 0:
        st.session_state.current_index = idx - 1
        st.rerun()
    nav_label.caption(
        f"Reviewing **{finding.probe_name}** "
        f"({finding.owasp_llm_category} / {finding.severity})"
    )
    if nav_next.button("Next ▶", use_container_width=True) and idx < total - 1:
        st.session_state.current_index = idx + 1
        st.rerun()

    ai_client = _get_ai_client()
    render_finding(finding, rem_result, ver_result, ai_client)

    is_esc = finding.owasp_llm_category in ESCALATION_CATEGORIES
    approve_label = "✅ Note it" if is_esc else "✅ Approve"
    skip_label = "⏭️ Dismiss" if is_esc else "⏭️ Skip"
    view_label = "🔗 View tools" if is_esc else "👁️ View patch"

    btn_a, btn_b, btn_c = st.columns(3)
    if btn_a.button(approve_label, use_container_width=True, type="primary"):
        _approve_current_finding()
        st.rerun()
    if btn_b.button(skip_label, use_container_width=True):
        _skip_current_finding()
        st.rerun()
    if btn_c.button(view_label, use_container_width=True):
        if is_esc:
            render_tools_panel(finding, rem_result)
        else:
            render_patch_panel(rem_result)

    # Raw data lives in a collapsed expander at the bottom of the page,
    # always present so users can inspect the underlying payload without
    # the View button hijacking the action area.
    with st.expander("📦 Raw data", expanded=False):
        st.caption(
            "Underlying garak record for this finding. Useful for debugging "
            "the pipeline; not normally needed for triage."
        )
        st.json(finding.raw_data)

    if st.session_state.tts_enabled:
        speech = (
            f"Finding {idx + 1} of {total}. "
            f"{OWASP_CONTENT.get(finding.owasp_llm_category, {}).get('name', finding.owasp_llm_category)}. "
            f"Severity {finding.severity}."
        )
        _maybe_emit_voice(speech)
    elif st.session_state.voice_enabled:
        _maybe_emit_voice("")


# ---------------------------------------------------------------------------
# Screen 4 — Review complete
# ---------------------------------------------------------------------------


def render_complete() -> None:
    # Same constraint as render_review: findings/approved/skipped are
    # in-memory only and do not survive a refresh.
    if not st.session_state.findings:
        st.session_state.screen = "landing"
        st.rerun()
    findings: list[Finding] = st.session_state.findings
    approved = st.session_state.approved
    skipped = st.session_state.skipped

    st.markdown("### ✅ Review Complete")
    if st.session_state.tts_enabled:
        _maybe_emit_voice(
            f"Review complete. {len(approved)} approved, {len(skipped)} skipped."
        )

    cols = st.columns(2)
    cols[0].metric("Approved", len(approved))
    cols[1].metric("Skipped", len(skipped))

    list_cols = st.columns(2)
    with list_cols[0]:
        st.markdown("#### ✅ Approved")
        if not approved:
            st.caption("None.")
        for idx in approved:
            f = findings[idx]
            esc = f.owasp_llm_category in ESCALATION_CATEGORIES
            note = (
                " &middot; <span style='color:#ffaa00;'>Noted — external tools required</span>"
                if esc
                else ""
            )
            st.markdown(
                f'<div style="color:#e6edf3;">• <code>{f.probe_name}</code> '
                f'<span style="color:#8b949e;">({f.owasp_llm_category} / {f.severity})</span>'
                f"{note}</div>",
                unsafe_allow_html=True,
            )

    with list_cols[1]:
        st.markdown("#### ⏭️ Skipped")
        if not skipped:
            st.caption("None.")
        for idx in skipped:
            f = findings[idx]
            st.markdown(
                f'<div style="color:#8b949e;">• <code>{f.probe_name}</code> '
                f"({f.owasp_llm_category} / {f.severity})</div>",
                unsafe_allow_html=True,
            )

    ai_client = _get_ai_client()
    summary_text: str | None = None
    if ai_client is not None:
        summary_text = ai_client.summarize_decisions(len(approved), len(skipped))
    if not summary_text:
        summary_text = (
            f"You approved {len(approved)} fix(es) and skipped {len(skipped)}. "
            "Apply the approved patches to generate your artifact bundle."
        )
    st.markdown(
        f'<div class="ai-card" style="margin-top:14px;">'
        f'<div style="color:#00d4ff;font-size:0.8rem;letter-spacing:0.06em;'
        f"margin-bottom:6px;\">"
        f"{'CLAUDE FINAL SUMMARY' if ai_client else 'FINAL SUMMARY'}"
        f'</div><div>{summary_text}</div></div>',
        unsafe_allow_html=True,
    )

    btn_apply, btn_redo, btn_export = st.columns(3)
    if btn_apply.button("🚀 Apply approved patches", use_container_width=True, type="primary"):
        _apply_and_write()
        st.rerun()
    if btn_redo.button("🔄 Re-review", use_container_width=True):
        st.session_state.current_index = 0
        st.session_state.approved = []
        st.session_state.skipped = []
        st.session_state.screen = "review"
        st.rerun()
    if btn_export.button("📋 Skip apply, export anyway", use_container_width=True):
        _apply_and_write()
        st.rerun()

    if skipped and st.session_state.get("is_admin"):
        st.divider()
        st.markdown("#### 🎯 Bug Bounty Package")
        st.caption(
            f"{len(skipped)} finding(s) skipped — ready for 0DIN submission."
        )


def _apply_and_write() -> None:
    findings: list[Finding] = st.session_state.findings
    results = st.session_state.remediation_results
    report = st.session_state.verification_report
    if results:
        config = results[0].guardrail_config
        if config is None:
            config = GuardrailGenerator().generate(findings, "portkey")
    else:
        config = GuardrailGenerator().generate(findings, "portkey")
    output_dir = _ensure_output_dir()
    final_report = OutputOrchestrator().write_all(
        findings=findings,
        remediation_results=results,
        verification_report=report,
        guardrail_config=config,
        output_dir=output_dir,
    )
    st.session_state.final_report = final_report
    st.session_state.screen = "results"


# ---------------------------------------------------------------------------
# Screen 5 — Results / downloads
# ---------------------------------------------------------------------------


def render_results() -> None:
    final_report = st.session_state.final_report
    if final_report is None:
        st.session_state.screen = "landing"
        st.rerun()

    if st.session_state.tts_enabled:
        _maybe_emit_voice("Remediation complete. Ready to download.")

    st.markdown("### 🎉 RemediAX complete")
    report = final_report.verification_report
    cols = st.columns(4)
    cols[0].metric("Patched", report.verified_count + report.partial_count)
    cols[1].metric("Verified", report.verified_count)
    cols[2].metric("Escalated", report.unverifiable_count)
    cols[3].metric("Findings", report.total_findings)

    ai_client = _get_ai_client()
    if ai_client is not None:
        msg = ai_client.summarize_decisions(
            len(st.session_state.approved), len(st.session_state.skipped)
        )
        if msg:
            st.markdown(
                f'<div class="ai-card">{msg}</div>', unsafe_allow_html=True
            )

    st.markdown("#### 📥 Download artifacts")
    for artifact in final_report.artifacts:
        cols = st.columns([4, 2, 2])
        cols[0].markdown(
            f"📄 **{artifact.filename}** &nbsp; "
            f'<span style="color:#8b949e;">{artifact.description}</span>',
            unsafe_allow_html=True,
        )
        cols[1].caption(f"{artifact.size_bytes:,} bytes")
        try:
            data = artifact.filepath.read_bytes()
        except OSError as exc:
            cols[2].caption(f"Missing: {exc}")
            continue
        cols[2].download_button(
            "⬇ Download",
            data=data,
            file_name=artifact.filename,
            key=f"dl-{artifact.filename}",
            use_container_width=True,
        )

    skipped = st.session_state.skipped
    if skipped and st.session_state.get("is_admin"):
        st.divider()
        st.markdown("#### 🐞 Bug bounty package")
        skipped_payload = [
            st.session_state.findings[i].raw_data for i in skipped
        ]
        import json

        st.download_button(
            "⬇ Download skipped_for_review.json",
            data=json.dumps(skipped_payload, indent=2).encode("utf-8"),
            file_name="skipped_for_review.json",
            mime="application/json",
        )

    escalations = [
        r
        for r in st.session_state.remediation_results
        if r.finding.owasp_llm_category in ESCALATION_CATEGORIES
        and r.finding.owasp_llm_category in {
            f.owasp_llm_category for f in st.session_state.findings
        }
    ]
    if escalations:
        st.divider()
        st.markdown("#### 📋 Escalation actions required")
        for result in escalations:
            content = OWASP_CONTENT.get(result.finding.owasp_llm_category, {})
            tools = content.get("external_tools") or []
            tools_md = "\n".join(f"- {tool}" for tool in tools)
            st.markdown(
                f"**{result.finding.owasp_llm_category} — {content.get('name', '?')}**\n\n{tools_md}"
            )

    if st.button("🔄 New scan", use_container_width=True):
        reset_to_landing()
        st.rerun()


# ---------------------------------------------------------------------------
# Top-level dispatch
# ---------------------------------------------------------------------------


def main() -> None:
    st.set_page_config(
        page_title="RemediAX",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="collapsed",
    )
    st.markdown(_GLOBAL_CSS, unsafe_allow_html=True)
    initialize_state()

    # Best-effort auto-login from browser localStorage. No-ops when the
    # user is already authenticated, no token is remembered, or we have
    # already tried this session.
    _attempt_auto_login()

    if not st.session_state.authenticated and st.session_state.screen != "access":
        st.session_state.screen = "access"

    if st.session_state.authenticated:
        # Persist the active screen to the URL so refresh stays in place.
        _sync_url_screen()
        render_sidebar()

    screen = st.session_state.screen
    if screen == "access":
        render_access()
    elif screen == "landing":
        render_landing()
    elif screen == "summary":
        render_summary()
    elif screen == "review":
        render_review()
    elif screen == "complete":
        render_complete()
    elif screen == "results":
        render_results()
    elif screen == "admin":
        render_admin_panel()
    else:  # pragma: no cover - defensive
        st.session_state.screen = "landing"
        st.rerun()


main()
