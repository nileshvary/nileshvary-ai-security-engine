"""RemediAX — Streamlit web UI wrapping the AI Security Remediation Engine.

Run with:
    streamlit run app.py

This module only orchestrates UI state and dispatches to per-screen
renderers. The actual security work is delegated to the same engine the
CLI uses (``integration_bridge``, ``remediation_engine``, ``verifier``,
``output``) — nothing in ``src/`` is modified.
"""

from __future__ import annotations

import hashlib
import html as _html
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
from components.security_score import calculate_security_score, score_status
from components.voice import (
    consume_voice_command,
    escape_for_speech,
    get_voice_js,
)
from database import (
    FirebaseAuthError,
    create_user,
    get_all_scans,
    get_all_uploads,
    get_init_error,
    get_user,
    get_user_scans,
    get_user_uploads,
    init_firebase,
    is_firebase_ready,
    login_user,
    save_scan,
    save_token_request,
    save_upload,
    scans_this_month,
    send_admin_notification,
    send_user_email,
    update_scan,
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
_FB_EMAIL_PARAM = "e"
_FB_UID_PARAM = "uid"
_FB_TIER_PARAM = "tier"
_RESTORABLE_SCREENS: frozenset[str] = frozenset(
    {
        "landing",
        "scanner",
        "analytics",
        "summary",
        "review",
        "complete",
        "results",
        "admin",
    }
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


# ---------------------------------------------------------------------------
# Firebase remember-me — URL query params (?e=, ?uid=, ?tier=)
# ---------------------------------------------------------------------------
#
# Mirrors the existing admin ``?t=RMX-*`` flow. SECURITY NOTES:
#   * URL params leak via browser history, server access logs, the
#     HTTP Referer header (any outbound link the user clicks), and
#     any URL the user copies / shares. Same exposure as the admin
#     token flow already in use.
#   * There is NO signature on these params. Anyone who knows a
#     uid + matching email can mint a working URL. uids are opaque
#     Firebase identifiers but should not be considered secret.
#   * ``?tier=`` is written for parity with the spec but the
#     auto-login path ALWAYS refetches the tier from Firestore so
#     editing ``?tier=premium`` in the address bar does NOT grant
#     premium features.


def _read_query_param(name: str) -> str | None:
    """Return ``st.query_params[name]`` as a stripped str, or ``None``."""
    try:
        raw = st.query_params.get(name)
    except Exception:  # pragma: no cover - defensive
        return None
    if raw is None:
        return None
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    if not raw:
        return None
    return str(raw).strip()


def _persist_firebase_session_to_url(uid: str, email: str, tier: str) -> None:
    """Write Firebase remember-me identity to ``?e=``, ``?uid=``, ``?tier=``."""
    try:
        st.query_params[_FB_EMAIL_PARAM] = email
        st.query_params[_FB_UID_PARAM] = uid
        st.query_params[_FB_TIER_PARAM] = tier
        logger.info(
            "FB URL remember-me SET: uid=%s email=%s tier=%s", uid, email, tier
        )
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Failed to persist Firebase session to URL: %s", exc)


def _clear_firebase_session_from_url() -> None:
    """Remove ``?e=``, ``?uid=``, ``?tier=`` from the URL (no-op if absent)."""
    try:
        cleared = False
        for key in (_FB_EMAIL_PARAM, _FB_UID_PARAM, _FB_TIER_PARAM):
            if key in st.query_params:
                del st.query_params[key]
                cleared = True
        if cleared:
            logger.info("FB URL remember-me CLEARED")
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning("Failed to clear Firebase session URL params: %s", exc)


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


def _admin_login_unlocked() -> bool:
    """True when the URL contains ``?admin=true`` — gates the admin token form.

    Hides the back-door admin token expander from the public access
    screen so casual visitors do not even see that an admin path exists.
    Admins reach the form by visiting ``/?admin=true``.
    """
    try:
        raw = st.query_params.get("admin")
    except Exception:  # pragma: no cover - defensive
        return False
    if raw is None:
        return False
    if isinstance(raw, list):
        raw = raw[0] if raw else None
    return str(raw).strip().lower() == "true"


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


def _bootstrap_admin_token_from_secrets() -> None:
    """Seed ``tokens.json`` with the ``APP_ADMIN_TOKEN`` secret.

    Streamlit Cloud deploys start with an empty ``tokens.json`` (it is
    gitignored) so the operator cannot log in unless they SSH in to run
    ``generate_token.py`` — which Cloud doesn't allow. This helper
    closes that gap: at app startup, if ``st.secrets["APP_ADMIN_TOKEN"]``
    is set, register its hash as a permanent admin token. Idempotent —
    safe to call on every rerun.

    Silently no-ops when:
    * Streamlit secrets are unavailable (local dev without
      ``.streamlit/secrets.toml``).
    * The secret is missing or empty.
    * A record with the same hash is already in ``tokens.json`` (e.g.
      the secret was already bootstrapped on a previous boot).
    """
    try:
        token = st.secrets.get("APP_ADMIN_TOKEN")
    except Exception as exc:
        # ``st.secrets`` raises StreamlitSecretNotFoundError when no
        # secrets file exists. Local dev hits this on every run.
        logger.debug("Streamlit secrets unavailable: %s", exc)
        return
    if not token:
        return
    raw = str(token).strip()
    if not raw:
        return
    try:
        new_id = TokenManager().register_token_hash(
            raw,
            permanent=True,
            for_person="Streamlit Cloud admin (bootstrapped from secret)",
        )
    except Exception as exc:
        logger.warning("Failed to bootstrap admin token from secret: %s", exc)
        return
    if new_id is not None:
        logger.info(
            "Bootstrapped permanent admin token (id %s) from APP_ADMIN_TOKEN secret",
            new_id,
        )


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
        # Authenticated wins over guest — clear the guest flag so the
        # tier check is unambiguous.
        st.session_state.guest_mode = False
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


def _attempt_firebase_url_auto_login() -> None:
    """If ``?e=`` and ``?uid=`` are present, validate and log in.

    Mirrors the admin ``?t=`` flow. Runs once per session (guarded by
    ``fb_url_login_tried``) so we do not re-hit Firestore on every
    rerun. The Firestore profile must exist AND its email must match
    the URL claim; otherwise the params are stripped and the user is
    shown the access screen. Tier is ALWAYS taken from Firestore so a
    user editing ``?tier=premium`` in the address bar cannot self-
    promote.
    """
    if st.session_state.authenticated:
        return
    if st.session_state.get("fb_url_login_tried"):
        return
    email = _read_query_param(_FB_EMAIL_PARAM)
    uid = _read_query_param(_FB_UID_PARAM)
    if not email or not uid:
        # Nothing to do; don't mark tried — there's no work to skip.
        return
    st.session_state.fb_url_login_tried = True
    logger.info("FB URL auto-login: checking uid=%s email=%s", uid, email)

    if not is_firebase_ready():
        logger.info("FB URL auto-login: Firebase not configured; skipping")
        return

    profile = get_user(uid)
    if profile is None:
        logger.warning(
            "FB URL auto-login: uid=%s not found in Firestore; clearing params",
            uid,
        )
        _clear_firebase_session_from_url()
        return

    profile_email = profile.get("email")
    if profile_email and profile_email != email:
        logger.warning(
            "FB URL auto-login: email mismatch (url=%s profile=%s); clearing",
            email,
            profile_email,
        )
        _clear_firebase_session_from_url()
        return

    # Always trust Firestore for tier (URL is user-editable).
    tier = profile.get("tier") or "basic"
    logger.info(
        "FB URL auto-login: OK uid=%s email=%s tier=%s (URL tier ignored)",
        uid,
        email,
        tier,
    )
    _activate_firebase_session(
        {
            "uid": uid,
            "email": profile_email or email,
            "name": profile.get("name") or email.split("@")[0],
            "tier": tier,
        }
    )
    # Re-write URL params with the authoritative tier so the address
    # bar reflects reality after auto-login.
    _persist_firebase_session_to_url(uid, profile_email or email, tier)
    desired = _read_query_screen()
    st.session_state.screen = desired or "landing"
    st.rerun()


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

/* === Landing redesign === */

/* Cycling subtitle: four spans stacked at the same position,
 * each animation-delayed so they appear sequentially over a 16s loop. */
.rx-subtitle-cycle {
  position: relative;
  min-height: 1.6em;
  margin: 6px 0 14px;
  color: #00d4ff;
  font-family: monospace;
  font-size: 1rem;
}
.rx-subtitle-cycle span {
  position: absolute;
  left: 0; top: 0;
  opacity: 0;
  white-space: nowrap;
  animation: rx-cycle 16s infinite;
}
.rx-subtitle-cycle span::before { content: "› "; color: #00ff88; }
.rx-subtitle-cycle span:nth-child(1) { animation-delay: 0s; }
.rx-subtitle-cycle span:nth-child(2) { animation-delay: 4s; }
.rx-subtitle-cycle span:nth-child(3) { animation-delay: 8s; }
.rx-subtitle-cycle span:nth-child(4) { animation-delay: 12s; }
@keyframes rx-cycle {
  0%, 1%   { opacity: 0; transform: translateY(4px); }
  4%, 22%  { opacity: 1; transform: translateY(0); }
  25%, 100% { opacity: 0; transform: translateY(-4px); }
}

.rx-stat-row {
  display: flex; flex-wrap: wrap; gap: 12px;
  margin: 14px 0 22px;
}
.rx-stat {
  flex: 1 1 220px;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-left: 4px solid #00d4ff;
  border-radius: 8px;
  padding: 12px 16px;
  color: #e6edf3;
}
.rx-stat .rx-stat-icon { font-size: 1.4rem; }
.rx-stat .rx-stat-value { font-size: 1.2rem; font-weight: 700; color: #00d4ff; }
.rx-stat .rx-stat-label { color: var(--text-secondary); font-size: 0.85rem; }

.rx-threat-card {
  background: var(--bg-card);
  border: 1px solid #1e3a5f;
  border-top: 3px solid #00d4ff;
  border-radius: 8px;
  padding: 18px 20px;
  height: 100%;
  transition: border-color 0.2s, box-shadow 0.2s;
}
.rx-threat-card:hover {
  border-color: #00d4ff;
  box-shadow: 0 0 12px rgba(0, 212, 255, 0.18);
}
.rx-threat-card .rx-threat-title {
  font-family: monospace;
  font-size: 0.85rem;
  letter-spacing: 0.1em;
  color: #00d4ff;
  font-weight: 700;
  margin-bottom: 8px;
}
.rx-threat-card .rx-threat-body { color: #e6edf3; line-height: 1.55; font-size: 0.92rem; }

.rx-section-header {
  font-size: 1.15rem;
  font-weight: 700;
  color: #00d4ff;
  margin: 24px 0 4px;
  font-family: monospace;
  letter-spacing: 0.04em;
}
.rx-section-subtext {
  color: var(--text-secondary);
  font-size: 0.9rem;
  margin-bottom: 10px;
}

/* Dashed cyan border for the file uploader on landing only. */
.rx-upload-frame [data-testid="stFileUploader"] section,
.rx-upload-frame [data-testid="stFileUploaderDropzone"] {
  border: 2px dashed #00d4ff !important;
  background: rgba(0, 212, 255, 0.04) !important;
  border-radius: 10px !important;
}
.rx-upload-frame [data-testid="stFileUploader"] section:hover,
.rx-upload-frame [data-testid="stFileUploaderDropzone"]:hover {
  background: rgba(0, 212, 255, 0.08) !important;
}

.rx-security-badges {
  display: flex; flex-wrap: wrap; gap: 6px 14px;
  align-items: center;
  padding: 14px 18px;
  background: var(--bg-card);
  border: 1px solid var(--border);
  border-radius: 8px;
  margin: 22px 0 10px;
  font-family: monospace;
  font-size: 0.82rem;
  color: var(--text-secondary);
}
.rx-security-badges .rx-sb { color: #e6edf3; }
.rx-security-badges .rx-sb-sep { color: #1e3a5f; }

/* === Access screen (two-column enterprise layout) === */

/* Stats bar at top */
.rx-access-stats {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
  gap: 10px;
  padding: 14px 18px;
  background: #0d1117;
  border: 1px solid #1e3a5f;
  border-radius: 8px;
  margin: 14px 0 22px;
  text-align: center;
}
.rx-access-stat-v {
  font-size: 1.05rem; font-weight: 700; color: #00d4ff;
  font-family: monospace;
}
.rx-access-stat-l {
  color: #8b949e; font-size: 0.78rem; margin-top: 2px;
}

/* Live threat ticker — 5 messages cycling every 2s (10s total loop) */
.rx-ticker {
  display: flex; align-items: center; gap: 12px;
  padding: 12px 16px;
  background: #0d1117;
  border: 1px solid #1e3a5f;
  border-left: 3px solid #ff4444;
  border-radius: 6px;
  margin-bottom: 22px;
  min-height: 3em;
}
.rx-ticker-dot {
  flex-shrink: 0;
  width: 10px; height: 10px;
  border-radius: 50%;
  background: #ff4444;
  animation: rx-pulse-red 1.5s infinite;
}
@keyframes rx-pulse-red {
  0%, 100% { box-shadow: 0 0 0 0 rgba(255, 68, 68, 0.8); }
  50% { box-shadow: 0 0 0 10px rgba(255, 68, 68, 0); }
}
.rx-ticker-msgs {
  position: relative;
  flex: 1;
  height: 1.4em;
  font-family: monospace;
  color: #e6edf3;
  font-size: 0.92rem;
  overflow: hidden;
}
.rx-ticker-msg {
  position: absolute;
  left: 0; top: 0;
  opacity: 0;
  white-space: nowrap;
  animation: rx-ticker-cycle 10s infinite;
}
.rx-ticker-msg:nth-child(1) { animation-delay: 0s; }
.rx-ticker-msg:nth-child(2) { animation-delay: 2s; }
.rx-ticker-msg:nth-child(3) { animation-delay: 4s; }
.rx-ticker-msg:nth-child(4) { animation-delay: 6s; }
.rx-ticker-msg:nth-child(5) { animation-delay: 8s; }
@keyframes rx-ticker-cycle {
  0%  { opacity: 0; transform: translateY(8px); }
  3%  { opacity: 1; transform: translateY(0); }
  18% { opacity: 1; transform: translateY(0); }
  22% { opacity: 0; transform: translateY(-8px); }
  100%{ opacity: 0; transform: translateY(-8px); }
}

/* "HOW IT WORKS" steps */
.rx-section-eyebrow {
  font-family: monospace;
  font-size: 0.82rem;
  letter-spacing: 0.12em;
  color: #00d4ff;
  margin: 8px 0 12px;
  font-weight: 700;
}
.rx-step {
  display: flex; gap: 14px; align-items: flex-start;
  padding: 12px 14px;
  margin: 8px 0;
  background: #0d1117;
  border: 1px solid #1e3a5f;
  border-radius: 8px;
  transition: box-shadow 0.2s, border-color 0.2s;
}
.rx-step:hover {
  border-color: #00d4ff;
  box-shadow: 0 0 12px rgba(0, 212, 255, 0.15);
}
.rx-step-num {
  flex-shrink: 0;
  width: 36px; height: 36px;
  border-radius: 50%;
  background: #0a0e1a;
  border: 2px solid #00d4ff;
  color: #00d4ff;
  font-family: monospace;
  font-weight: 700;
  display: flex; align-items: center; justify-content: center;
  box-shadow: 0 0 10px rgba(0, 212, 255, 0.5);
}
.rx-step-title {
  color: #00d4ff;
  font-family: monospace;
  font-size: 0.8rem;
  letter-spacing: 0.06em;
  font-weight: 700;
}
.rx-step-desc {
  color: #e6edf3;
  font-size: 0.88rem;
  margin-top: 3px;
  line-height: 1.45;
}

/* Educational callout boxes (4 colors) */
.rx-callout {
  background: #0d1117;
  border: 1px solid #1e3a5f;
  border-left-width: 4px;
  border-radius: 6px;
  padding: 12px 14px;
  margin: 8px 0;
  transition: box-shadow 0.2s;
}
.rx-callout:hover { box-shadow: 0 0 12px rgba(255, 255, 255, 0.06); }
.rx-callout-orange { border-left-color: #ff6600; }
.rx-callout-cyan   { border-left-color: #00d4ff; }
.rx-callout-green  { border-left-color: #00ff88; }
.rx-callout-red    { border-left-color: #ff4444; }
.rx-callout-title {
  font-weight: 700;
  font-size: 0.78rem;
  letter-spacing: 0.06em;
  font-family: monospace;
}
.rx-callout-orange .rx-callout-title { color: #ff6600; }
.rx-callout-cyan   .rx-callout-title { color: #00d4ff; }
.rx-callout-green  .rx-callout-title { color: #00ff88; }
.rx-callout-red    .rx-callout-title { color: #ff4444; }
.rx-callout-body {
  color: #e6edf3;
  font-size: 0.88rem;
  margin-top: 4px;
  line-height: 1.5;
}

/* Right column login card — applies the cyan glow to the Streamlit
 * column that contains the marker div. Uses :has() (Chrome 105+,
 * Safari 15.4+, Firefox 121+). Older browsers see a plain column. */
[data-testid="stColumn"]:has(.rx-login-marker) > div {
  background: #0d1117;
  border: 1px solid #00d4ff;
  border-radius: 10px;
  padding: 18px !important;
  box-shadow: 0 0 22px rgba(0, 212, 255, 0.22);
}
.rx-login-title {
  text-align: center;
  font-family: monospace;
  letter-spacing: 0.06em;
  color: #00d4ff;
  font-size: 1.5rem;
  font-weight: 700;
  margin: 4px 0 2px;
}
.rx-login-tagline {
  text-align: center;
  color: #8b949e;
  font-size: 0.85rem;
  margin-bottom: 14px;
}
.rx-access-divider {
  text-align: center;
  margin: 16px 0 10px;
  color: #8b949e;
  font-family: monospace;
  letter-spacing: 0.1em;
}
.rx-security-strip {
  display: flex; flex-wrap: wrap;
  justify-content: center;
  gap: 6px 10px;
  margin-top: 14px;
  font-family: monospace;
  font-size: 0.72rem;
  color: #8b949e;
}
.rx-security-strip .rx-sb { color: #e6edf3; }
.rx-security-strip .rx-sb-sep { color: #1e3a5f; }

/* === Access screen v3 (premium enterprise) === */

/* Section 1 — Full-width scrolling marquee threat ticker */
.rx-marquee {
  width: 100%;
  overflow: hidden;
  background: linear-gradient(90deg, #3a0000, #5a0000, #3a0000);
  border-top: 1px solid #ff4444;
  border-bottom: 1px solid #ff4444;
  padding: 9px 0;
  margin: -8px 0 18px;
  box-shadow: 0 0 18px rgba(255, 68, 68, 0.18) inset;
}
.rx-marquee-track {
  display: flex;
  width: max-content;
  animation: rx-marquee-scroll 38s linear infinite;
}
.rx-marquee-segment {
  font-family: monospace;
  color: #ffd0d0;
  white-space: nowrap;
  padding-right: 60px;
  font-size: 0.9rem;
  letter-spacing: 0.02em;
}
@keyframes rx-marquee-scroll {
  0%   { transform: translateX(0); }
  100% { transform: translateX(-50%); }
}

/* Architecture diagram boxes */
.rx-arch-box {
  background: #111827;
  border: 2px solid;
  border-radius: 10px;
  padding: 16px 18px;
  text-align: center;
  transition: box-shadow 0.2s;
}
.rx-arch-box:hover {
  box-shadow: 0 0 14px rgba(255, 255, 255, 0.06);
}
.rx-arch-box-red {
  border-color: #8b0000;
  background: linear-gradient(180deg, #111827, #1a0a0a);
}
.rx-arch-box-cyan {
  border-color: #00d4ff;
  background: linear-gradient(180deg, #0d1117, #0a1620);
  animation: rx-arch-pulse 2.4s infinite;
}
.rx-arch-box-green {
  border-color: #00ff88;
  background: linear-gradient(180deg, #111827, #0a1a13);
}
@keyframes rx-arch-pulse {
  0%, 100% { box-shadow: 0 0 12px rgba(0, 212, 255, 0.22); }
  50%      { box-shadow: 0 0 30px rgba(0, 212, 255, 0.55); }
}
.rx-arch-title {
  font-family: monospace;
  font-weight: 700;
  font-size: 0.95rem;
  letter-spacing: 0.06em;
}
.rx-arch-box-red   .rx-arch-title { color: #ff4444; }
.rx-arch-box-cyan  .rx-arch-title { color: #00d4ff; }
.rx-arch-box-green .rx-arch-title { color: #00ff88; }
.rx-arch-desc {
  color: #e6edf3;
  font-size: 0.82rem;
  margin-top: 4px;
  line-height: 1.4;
}
.rx-arch-sub {
  color: #8b949e;
  font-size: 0.75rem;
  margin-top: 2px;
}

/* Animated flowing dots between architecture boxes */
.rx-arch-flow {
  position: relative;
  height: 36px;
  margin: 0 auto;
  width: 6px;
}
.rx-arch-dot {
  position: absolute;
  left: 0;
  width: 6px; height: 6px;
  border-radius: 50%;
  background: #00d4ff;
  box-shadow: 0 0 8px #00d4ff;
  animation: rx-flow-down 1.6s linear infinite;
}
.rx-arch-dot:nth-child(1) { animation-delay: 0s; }
.rx-arch-dot:nth-child(2) { animation-delay: 0.55s; }
.rx-arch-dot:nth-child(3) { animation-delay: 1.1s; }
@keyframes rx-flow-down {
  0%   { top: -6px; opacity: 0; }
  10%  { opacity: 1; }
  90%  { opacity: 1; }
  100% { top: 100%; opacity: 0; }
}

/* Stats row (4 badges) */
.rx-stat-badges {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
  gap: 10px;
  margin: 22px 0 10px;
}
.rx-stat-badge {
  background: #111827;
  border: 1px solid #1e3a5f;
  border-left: 3px solid #00d4ff;
  border-radius: 6px;
  padding: 10px 12px;
  transition: box-shadow 0.2s, border-color 0.2s;
}
.rx-stat-badge:hover {
  border-color: #00d4ff;
  box-shadow: 0 0 12px rgba(0, 212, 255, 0.18);
}
.rx-stat-badge-v {
  color: #00d4ff;
  font-family: monospace;
  font-weight: 700;
  font-size: 1.05rem;
}
.rx-stat-badge-l {
  color: #8b949e;
  font-size: 0.78rem;
  margin-top: 2px;
}

/* Horizontal "How It Works" — 5 steps with arrows */
.rx-howit-row {
  display: flex;
  align-items: stretch;
  gap: 4px;
  flex-wrap: wrap;
  margin: 14px 0 10px;
}
.rx-howit-step {
  flex: 1 1 95px;
  background: #111827;
  border: 1px solid #1e3a5f;
  border-radius: 6px;
  padding: 10px 8px;
  text-align: center;
  transition: box-shadow 0.2s, border-color 0.2s;
}
.rx-howit-step:hover {
  border-color: #00d4ff;
  box-shadow: 0 0 10px rgba(0, 212, 255, 0.18);
}
.rx-howit-num {
  font-size: 1.4rem;
  line-height: 1;
}
.rx-howit-title {
  color: #00d4ff;
  font-family: monospace;
  font-size: 0.72rem;
  font-weight: 700;
  letter-spacing: 0.06em;
  margin-top: 4px;
}
.rx-howit-desc {
  color: #8b949e;
  font-size: 0.7rem;
  margin-top: 2px;
  line-height: 1.3;
}
.rx-howit-arrow {
  display: flex; align-items: center;
  color: #00d4ff;
  font-family: monospace;
  font-size: 1.1rem;
  padding: 0 4px;
}

/* 2x2 security concepts grid */
.rx-concepts-grid {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 10px;
  margin-top: 18px;
}
@media (max-width: 760px) {
  .rx-concepts-grid { grid-template-columns: 1fr; }
}

/* Bottom badges bar */
.rx-bottom-bar {
  display: flex;
  flex-wrap: wrap;
  gap: 8px 16px;
  justify-content: center;
  align-items: center;
  padding: 14px 20px;
  background: #0d1117;
  border: 1px solid #1e3a5f;
  border-radius: 8px;
  margin: 24px 0 4px;
  font-family: monospace;
  font-size: 0.78rem;
  color: #8b949e;
}
.rx-bottom-bar .rx-bb-item { color: #e6edf3; }
.rx-bottom-bar .rx-bb-sep { color: #1e3a5f; }
.rx-bottom-bar .rx-bb-author { color: #00d4ff; }
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


# ---------------------------------------------------------------------------
# Tier + scan quota (Firebase-backed)
# ---------------------------------------------------------------------------

_REQUEST_ACCESS_MAILTO = (
    "mailto:nileshvary@gmail.com"
    "?subject=RemediAX%20Premium%20Access%20Request"
    "&body=Hi%2C%20I%27d%20like%20premium%20RemediAX%20access.%20Thanks!"
)

_BASIC_MONTHLY_CAP = 3
_UNLIMITED_TIERS: frozenset[str] = frozenset({"premium", "developer"})


def _current_tier() -> str | None:
    """Return the authenticated user's tier, or ``None`` if unauthenticated."""
    if not st.session_state.authenticated:
        return None
    if st.session_state.get("is_admin"):
        return "developer"
    return st.session_state.get("user_tier")


def _is_unlimited_tier() -> bool:
    """True when the user has no scan quota cap (premium / developer / admin)."""
    return _current_tier() in _UNLIMITED_TIERS


def _scans_remaining_this_month() -> int:
    """Scans the current basic-tier user has left this month. ``-1`` = unlimited."""
    if _is_unlimited_tier():
        return -1
    uid = st.session_state.get("user_uid")
    if not uid:
        return 0
    used = scans_this_month(uid)
    return max(0, _BASIC_MONTHLY_CAP - used)


def _can_run_scan() -> bool:
    """True when the user is allowed to run one more scan right now."""
    if _is_unlimited_tier():
        return True
    return _scans_remaining_this_month() > 0


def _count_severities(findings: list[Finding]) -> dict[str, int]:
    """Count findings by severity bucket for analytics aggregation."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return counts


def _count_owasp(findings: list[Finding]) -> dict[str, int]:
    """Count findings by OWASP LLM category."""
    counts: dict[str, int] = {}
    for f in findings:
        code = f.owasp_llm_category
        counts[code] = counts.get(code, 0) + 1
    return counts


def _count_escalations(findings: list[Finding]) -> int:
    """Number of findings whose OWASP category is in ESCALATION_CATEGORIES."""
    return sum(1 for f in findings if f.owasp_llm_category in ESCALATION_CATEGORIES)


def _storage_uid() -> str:
    """Return a Firestore-write uid for the current user.

    Firebase users get their real uid. Admin-token users land under
    ``"admin"`` (they have no Firebase uid), and unauthenticated /
    guest sessions land under ``"guest"`` so analytics aggregations
    can still see them.
    """
    uid = st.session_state.get("user_uid")
    if uid:
        return str(uid)
    if st.session_state.get("is_admin"):
        return "admin"
    return "guest"


def _render_score_badge(score: float) -> None:
    """Render a colored SECURE / MODERATE / AT RISK / CRITICAL badge."""
    label, color = score_status(score)
    st.markdown(
        f'<div style="display:inline-block;padding:4px 10px;border-radius:4px;'
        f"background:{color}22;color:{color};font-weight:600;"
        f'font-size:0.85rem;letter-spacing:0.05em;">{label}</div>',
        unsafe_allow_html=True,
    )


def _consume_scan_quota(
    *,
    source: str = "unknown",
    findings: list[Finding] | None = None,
) -> None:
    """Record one scan against the user's quota by writing to Firestore.

    Writes for every authenticated category — Firebase users land
    under their uid, admin-token users under ``"admin"``, anonymous
    sessions under ``"guest"``. When ``findings`` is provided the
    payload carries severity + OWASP counts, escalation count, and a
    ``security_score`` so analytics can chart history without a
    second compute pass. ``filename`` (if any) is carried from the
    uploaded-file flow via ``current_upload_filename`` in session
    state.
    """
    uid = _storage_uid()
    payload: dict[str, Any] = {
        "source": source,
        "tier_at_scan": _current_tier() or "unknown",
        "status": "in_progress",
        "filename": st.session_state.get("current_upload_filename"),
    }
    if findings is not None:
        payload["total_findings"] = len(findings)
        payload["severity_counts"] = _count_severities(findings)
        payload["owasp_counts"] = _count_owasp(findings)
        payload["escalations"] = _count_escalations(findings)
        payload["security_score"] = round(calculate_security_score(findings), 1)
    scan_id = save_scan(uid, payload)
    if scan_id:
        st.session_state.current_scan_id = scan_id
        st.session_state.complete_saved_scan_id = None


def _save_completed_scan_results() -> None:
    """Merge final review stats into the current Firestore scan record.

    Idempotent: called both from ``render_complete`` (on first entry)
    and ``_apply_and_write`` (after verification). Uses the same
    ``calculate_security_score`` formula as the in-progress write so
    the score is consistent across the whole lifecycle.
    """
    scan_id = st.session_state.get("current_scan_id")
    if not scan_id:
        return
    uid = _storage_uid()
    findings = st.session_state.get("findings") or []
    approved = st.session_state.get("approved") or []
    skipped = st.session_state.get("skipped") or []
    report = st.session_state.get("verification_report")

    total = len(findings)
    fix_rate = (len(approved) / total * 100.0) if total else 0.0
    security_score = calculate_security_score(findings)

    updates: dict[str, Any] = {
        "status": "completed",
        "completed_at": datetime.utcnow().isoformat(),
        "timestamp": datetime.utcnow().isoformat(),
        "approved_count": len(approved),
        "approved": len(approved),
        "skipped_count": len(skipped),
        "skipped": len(skipped),
        "total_findings": total,
        "fix_rate": round(fix_rate, 1),
        "security_score": round(security_score, 1),
        "owasp_counts": _count_owasp(findings),
        "escalations": _count_escalations(findings),
        "filename": st.session_state.get("current_upload_filename"),
    }
    if report is not None:
        updates["verified_count"] = report.verified_count
        updates["partial_count"] = report.partial_count
        updates["failed_count"] = report.failed_count
        updates["unverifiable_count"] = report.unverifiable_count
    update_scan(uid, scan_id, updates)


def _render_quota_exceeded_message() -> None:
    """Surface the upsell banner when a basic-tier user is at limit."""
    st.warning(
        f"You have used your {_BASIC_MONTHLY_CAP} free scans this month. "
        "Upgrade for unlimited scanning."
    )
    st.link_button(
        "📧 Request Premium Access",
        _REQUEST_ACCESS_MAILTO,
        use_container_width=False,
    )


def _has_premium() -> bool:
    """True when the active user has unlocked access to premium features.

    Premium tier == anything in ``_UNLIMITED_TIERS`` (``premium``,
    ``developer``) plus admin token users. Used as the gate for every
    Security-Engineer-only feature lock.
    """
    if st.session_state.get("is_admin"):
        return True
    return _is_unlimited_tier()


def _render_locked_feature(
    feature_name: str,
    message: str,
    *,
    key_suffix: str = "",
) -> None:
    """Render the standard locked-feature card for basic-tier users.

    Args:
        feature_name: Short label shown in the card title (uppercased).
        message: One-line explanation of what unlocking buys the user.
        key_suffix: Unique-id suffix appended to the Streamlit widget key
            so the CTA button doesn't collide when the same feature is
            locked in two places on one page.
    """
    safe_name = _html.escape(feature_name, quote=True).upper()
    safe_msg = _html.escape(message, quote=True)
    st.markdown(
        '<div style="background:#0d1117;border:1px solid #1e3a5f;'
        'border-left:4px solid #ffaa00;border-radius:8px;'
        'padding:14px 16px;margin:10px 0;">'
        '<div style="color:#ffaa00;font-family:monospace;font-weight:700;'
        'letter-spacing:0.06em;font-size:0.85rem;">'
        f"🔒 {safe_name} &middot; "
        '<span style="color:#8b949e;">PREMIUM</span></div>'
        '<div style="color:#e6edf3;font-size:0.88rem;margin-top:6px;'
        f'line-height:1.5;">{safe_msg}</div>'
        "</div>",
        unsafe_allow_html=True,
    )
    cta_key = (
        "lock-cta-"
        + "".join(c if c.isalnum() else "-" for c in feature_name.lower())
        + key_suffix
    )
    st.link_button(
        "🎟️ Request Premium Access",
        _REQUEST_ACCESS_MAILTO,
        use_container_width=False,
        key=cta_key,
    )


def _do_logout() -> None:
    """Shared logout handler for every tier — public, token, admin.

    * Always clears ``?t=`` and ``?p=`` from the URL (no-op for public
      users since neither is set).
    * Always calls ``logout()`` which wipes ``st.session_state`` and
      re-initializes with defaults. ``initialize_state`` now sets
      ``screen="landing"`` so the user lands on the public landing page
      rather than the access screen.
    * Always triggers a rerun so the redirect takes effect immediately.
    """
    _clear_remembered_token()
    _clear_firebase_session_from_url()
    _clear_screen_param()
    logout()
    st.rerun()


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

        if st.button(
            "📡 Garak Scanner",
            use_container_width=True,
            key="nav-scanner",
            help="Generate ready-to-run garak commands for your target.",
        ):
            st.session_state.screen = "scanner"
            st.rerun()

        if st.button(
            "📊 Analytics",
            use_container_width=True,
            key="nav-analytics",
            help="Security operations analytics dashboard.",
        ):
            st.session_state.screen = "analytics"
            st.rerun()

        st.divider()
        st.markdown("**AI mode**")
        if not _has_premium():
            # Lock 4. Force basic mode and hide the Claude radio + API
            # key form. Premium upsell sits in its place.
            st.session_state.api_mode = False
            st.session_state.api_key = None
            st.session_state.ai_client = None
            _render_locked_feature(
                "AI Enhanced mode",
                "Upgrade for Claude-powered explanations of every finding "
                "and richer scan summaries.",
                key_suffix="-aimode",
            )
        else:
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
                    st.toast(
                        "Key saved." if st.session_state.api_key else "Key cleared."
                    )
                if remove_col.button("🗑️ Remove", use_container_width=True):
                    st.session_state.api_key = None
                    st.session_state.ai_client = None
                    st.toast("Key removed.")
                st.caption(
                    "✅ Key saved"
                    if st.session_state.api_key
                    else "❌ No key — basic mode"
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
        st.markdown("**Scan history**")
        if not _has_premium():
            _render_locked_feature(
                "Full scan history",
                "Upgrade to view your complete scan history with full "
                "findings, remediation results, and verification reports.",
                key_suffix="-history",
            )
        else:
            uid = st.session_state.get("user_uid")
            if uid:
                from database import get_user_scans

                try:
                    scans = get_user_scans(uid, limit=5)
                except Exception as exc:  # pragma: no cover - defensive
                    scans = []
                    logger.warning("Failed to load scan history: %s", exc)
                if scans:
                    for scan in scans:
                        ts = str(scan.get("created_at", ""))[:16]
                        src = scan.get("source", "?")
                        st.caption(f"`{ts}` &middot; {src}")
                else:
                    st.caption("No scans yet.")
            else:
                st.caption("Scan history is available for Firebase-authenticated users.")

        st.divider()
        st.markdown("**Access**")
        if not st.session_state.authenticated:
            # Should not reach here — main() forces unauthenticated to
            # access screen — but render defensively just in case.
            st.caption("Sign in to use RemediAX.")
        elif st.session_state.get("is_admin"):
            record = st.session_state.token_record or {}
            token_id = record.get("hash", "?")[:8] if record else "—"
            st.caption("Tier: **🛡️ ADMIN**")
            st.caption(f"Token id: `{token_id}`")
            st.caption(_ts_label())
            st.caption("Scans: unlimited")

            st.divider()
            nav_admin, nav_logout = st.columns(2)
            if nav_admin.button("👤 Admin", use_container_width=True):
                st.session_state.screen = "admin"
                st.rerun()
            if nav_logout.button(
                "🚪 Logout",
                use_container_width=True,
                key="sidebar-logout-admin",
            ):
                _do_logout()
        else:
            # Firebase-authenticated user.
            name = st.session_state.get("user_name") or "Analyst"
            email = st.session_state.get("user_email") or ""
            tier = st.session_state.get("user_tier") or "basic"
            tier_label = (
                "🛡️ SECURITY ENGINEER" if tier in _UNLIMITED_TIERS else "🔬 ANALYST"
            )
            st.caption(f"**{name}**")
            if email:
                st.caption(f"`{email}`")
            st.caption(f"Tier: **{tier_label}**")
            if tier in _UNLIMITED_TIERS:
                st.caption("Scans: unlimited")
            else:
                remaining = _scans_remaining_this_month()
                st.caption(
                    f"Scans remaining: **{remaining}/{_BASIC_MONTHLY_CAP}** this month"
                )
                if remaining == 0:
                    st.caption("⚠️ Monthly limit reached")

            st.divider()
            if tier not in _UNLIMITED_TIERS:
                if st.button(
                    "⬆️ Upgrade to Premium",
                    use_container_width=True,
                    key="sidebar-upgrade",
                ):
                    st.session_state.screen = "access"
                    st.session_state.show_premium_form = True
                    st.rerun()
            if st.button(
                "🚪 Logout",
                use_container_width=True,
                key="sidebar-logout-firebase",
            ):
                _do_logout()

        st.divider()
        st.caption("RemediAX v1.0.0")
        st.caption(f"[GitHub]({_GITHUB_URL})")


# ---------------------------------------------------------------------------
# Screen 0 — Access
# ---------------------------------------------------------------------------


def _activate_firebase_session(profile: dict[str, Any]) -> None:
    """Promote a Firebase-authenticated user into the active session."""
    st.session_state.authenticated = True
    st.session_state.user_uid = profile.get("uid")
    st.session_state.user_email = profile.get("email")
    st.session_state.user_name = profile.get("name")
    st.session_state.user_tier = profile.get("tier") or "basic"
    st.session_state.is_admin = False
    st.session_state.token_record = {}
    st.session_state.screen = "landing"


def _render_login_tab() -> None:
    """ANALYST LOGIN — email/password sign-in via the Firebase Auth REST API."""
    with st.form("fb-login-form"):
        email = st.text_input(
            "Email", key="fb-login-email", autocomplete="email"
        )
        password = st.text_input(
            "Password",
            type="password",
            key="fb-login-password",
        )
        remember_me = st.checkbox(
            "Remember me", value=False, key="fb-login-remember"
        )
        submit = st.form_submit_button(
            "🔐 AUTHENTICATE", use_container_width=True, type="primary"
        )
    if submit:
        if not is_firebase_ready():
            st.error("Firebase is not configured for this deployment.")
            return
        if not email or not password:
            st.error("Please enter both email and password.")
            return
        try:
            profile = login_user(email.strip(), password)
        except FirebaseAuthError as exc:
            st.error(f"❌ {exc}")
            return
        _activate_firebase_session(profile)
        st.success(f"Welcome back, {profile.get('name') or email}!")
        if remember_me and profile.get("uid"):
            # URL-param remember-me — same trust model as the admin
            # ``?t=`` flow. Tier is included for parity with the spec
            # but is always re-validated against Firestore on auto-
            # login, so editing the URL cannot promote a user.
            _persist_firebase_session_to_url(
                str(profile["uid"]),
                profile.get("email") or email.strip(),
                profile.get("tier") or "basic",
            )
        st.rerun()

    # Google Sign In — stub for v1.0
    if st.button(
        "🔵 Sign in with Google",
        use_container_width=True,
        key="fb-google-login",
        help="Coming soon — Google OAuth is on the roadmap.",
    ):
        st.info(
            "🔵 Google Sign In rolling out soon — please use email / "
            "password for now."
        )


def _render_signup_tab() -> None:
    """NEW OPERATOR — create a Firebase Auth user and seed their profile."""
    with st.form("fb-signup-form"):
        name = st.text_input("Full name", key="fb-signup-name")
        email = st.text_input(
            "Email", key="fb-signup-email", autocomplete="email"
        )
        password = st.text_input(
            "Password",
            type="password",
            key="fb-signup-password",
            help="Minimum 6 characters.",
        )
        confirm = st.text_input(
            "Confirm password",
            type="password",
            key="fb-signup-confirm",
        )
        submit = st.form_submit_button(
            "📝 REGISTER AS ANALYST", use_container_width=True, type="primary"
        )
    if submit:
        if not is_firebase_ready():
            st.error("Firebase is not configured for this deployment.")
            return
        if not name or not email or not password:
            st.error("Please fill in name, email, and password.")
            return
        if password != confirm:
            st.error("Passwords do not match.")
            return
        if len(password) < 6:
            st.error("Password must be at least 6 characters.")
            return
        try:
            profile = create_user(email.strip(), password, name.strip())
        except FirebaseAuthError as exc:
            st.error(f"❌ {exc}")
            return
        # Sign the new user in immediately so they can use the tool.
        try:
            login_profile = login_user(email.strip(), password)
        except FirebaseAuthError as exc:
            st.warning(
                f"Account created but auto sign-in failed: {exc}. "
                "Please sign in manually."
            )
            return
        _activate_firebase_session(login_profile)
        # New signups always get the URL remember-me — the user just
        # created the account, refusing to persist would log them out
        # on the next refresh and re-create the bug we are fixing.
        if login_profile.get("uid"):
            _persist_firebase_session_to_url(
                str(login_profile["uid"]),
                login_profile.get("email") or email.strip(),
                login_profile.get("tier") or "basic",
            )
        # Fire-and-forget admin notification.
        try:
            send_admin_notification(
                email=email.strip(),
                name=name.strip(),
                reason="new RemediAX signup",
            )
        except Exception as exc:  # pragma: no cover - SMTP transport
            logger.warning("Admin notification raised: %s", exc)
        st.success(f"Welcome, {name}!")
        st.rerun()


def _render_premium_request_form() -> None:
    """Inline form for basic users to request premium access."""
    with st.form("fb-premium-form"):
        st.caption(
            "Tell us a bit about your use case. We'll review and respond "
            "to the email on your account."
        )
        default_email = st.session_state.get("user_email") or ""
        default_name = st.session_state.get("user_name") or ""
        name = st.text_input("Name", value=default_name, key="prem-name")
        email = st.text_input("Email", value=default_email, key="prem-email")
        reason = st.text_area(
            "Why do you need premium access?",
            key="prem-reason",
            placeholder="e.g. running garak nightly against our customer support LLM…",
        )
        submit = st.form_submit_button(
            "📨 Submit request", use_container_width=True
        )
    if submit:
        if not (name and email and reason):
            st.error("Please fill in all three fields.")
            return
        name_clean = name.strip()
        email_clean = email.strip()
        reason_clean = reason.strip()

        # Auto-mint a 7-day trial token so the user can start using
        # premium immediately while we review their request.
        trial_token = TokenManager().generate_token(
            duration_hours=24 * 7,
            for_person=f"{name_clean} <{email_clean}>",
        )

        # Persist the request (best-effort) and notify the admin
        # regardless of email-to-user outcome.
        save_token_request(email_clean, name_clean, reason_clean)
        try:
            send_admin_notification(
                email=email_clean,
                name=name_clean,
                reason=(
                    f"Premium access request: {reason_clean}\n"
                    f"Generated 7-day trial token: {trial_token}"
                ),
                subject="New Premium Request — RemediAX",
            )
        except Exception as exc:  # pragma: no cover - SMTP transport
            logger.warning("Premium admin notification raised: %s", exc)

        user_body = (
            f"Hi {name_clean},\n\n"
            "Your 7-day RemediAX trial token:\n\n"
            f"    {trial_token}\n\n"
            "Enter your token at: remediax.streamlit.app\n"
            "Click 'Have an access token?' to enter it.\n\n"
            "For permanent Premium access, we will review your request "
            "and contact you.\n\n"
            "— RemediAX Security Team\n"
        )
        user_email_sent = False
        try:
            user_email_sent = send_user_email(
                to_email=email_clean,
                subject="Your RemediAX 7-day trial token",
                body=user_body,
            )
        except Exception as exc:  # pragma: no cover - SMTP transport
            logger.warning("User trial-token email raised: %s", exc)

        if user_email_sent:
            st.success(
                f"✅ Your 7-day trial token has been sent to "
                f"{email_clean}. Check your inbox!"
            )
        else:
            st.warning(
                "⚠️ We couldn't email your trial token. Copy it now — "
                "it won't be shown again:"
            )
            st.code(trial_token, language=None)
        st.session_state.show_premium_form = False


def _activate_token_session(token_input: str, *, remember_me: bool) -> None:
    """Validate an RMX-* token and activate the matching session.

    Shared by the public trial-token form and the hidden admin-token
    form. The token's ``permanent`` flag drives whether the session is
    admin: permanent tokens grant admin (``is_admin=True``); non-
    permanent trial tokens unlock premium features only. All session
    state writes match the previous admin-only flow so downstream
    screens behave identically.
    """
    tm = TokenManager()
    ok, status, record = tm.validate_token(token_input, ip=_client_id())
    if ok:
        is_admin_token = bool(record.get("permanent"))
        st.session_state.authenticated = True
        st.session_state.token_record = record
        st.session_state.is_admin = is_admin_token
        st.session_state.user_uid = None
        st.session_state.user_email = None
        st.session_state.user_name = "Admin" if is_admin_token else "Trial user"
        st.session_state.user_tier = "developer"
        st.session_state.screen = "landing"
        if remember_me:
            _persist_token(token_input.strip())
        else:
            _clear_remembered_token()
        st.rerun()
    elif status.startswith("locked:"):
        st.error(f"🚫 Too many attempts. Wait {status.split(':', 1)[1]}m.")
    elif status == "expired":
        st.error("⏰ Token expired.")
    elif status == "revoked":
        st.error("❌ Token revoked.")
    elif status.startswith("invalid:"):
        st.error(
            f"❌ Invalid token. {status.split(':', 1)[1]} attempts remaining."
        )
    else:
        st.error(f"❌ {status}")


def _render_trial_token_form() -> None:
    """Public-facing token entry for users with a 7-day trial token.

    Surfaced from a "🔑 Have an access token?" expander on the access
    screen so premium-request submitters can find where to paste the
    token from their confirmation email without needing the
    ``?admin=true`` back-door URL.
    """
    st.caption(
        "Paste the trial token from your premium-request confirmation "
        "email."
    )
    with st.form("trial-token-form"):
        token_input = st.text_input(
            "Access token",
            type="password",
            placeholder="RMX-...",
            key="trial-token-input",
        )
        remember_me = st.checkbox(
            "Remember me on this device",
            value=False,
            help=(
                "Stores your token in the URL so you stay signed in "
                "across page refreshes. Anyone with the URL can use the "
                "token. Uncheck on shared screens."
            ),
            key="trial-token-remember",
        )
        submit = st.form_submit_button(
            "🔑 Sign in with token", use_container_width=True
        )
    if submit:
        _activate_token_session(token_input, remember_me=remember_me)


def _render_admin_token_form() -> None:
    """Existing RMX-* token login, preserved for admin access."""
    st.caption(
        "For admins with an RMX-* token. Regular users should sign in "
        "above instead."
    )
    with st.form("admin-token-form"):
        token_input = st.text_input(
            "Access token",
            type="password",
            placeholder="RMX-...",
            key="admin-token-input",
        )
        remember_me = st.checkbox(
            "Remember me on this device",
            value=False,
            help=(
                "Stores your token in the URL so you stay signed in "
                "across page refreshes. Anyone with the URL can use the "
                "token. Uncheck on shared screens."
            ),
            key="admin-token-remember",
        )
        submit = st.form_submit_button(
            "🛡️ Sign in as admin", use_container_width=True
        )
    if submit:
        _activate_token_session(token_input, remember_me=remember_me)


def render_access() -> None:
    # ── SECTION 1 — Full-width scrolling threat ticker ──────────────
    ticker_text = (
        "⚡ LIVE THREAT FEED "
        "&mdash; 🔴 Prompt Injection detected &rarr; Neutralized ✅ "
        "&mdash; 🔴 Jailbreak attempt blocked &rarr; Patched ✅ "
        "&mdash; 🔴 Data exfiltration attempt &rarr; Remediated ✅ "
        "&mdash; 🔴 Supply chain compromise &rarr; Escalated ⚠️ "
        "&mdash; 🔴 Sensitive data leak &rarr; Redacted ✅"
    )
    st.markdown(
        '<div class="rx-marquee"><div class="rx-marquee-track">'
        f'<div class="rx-marquee-segment">{ticker_text}</div>'
        f'<div class="rx-marquee-segment">{ticker_text}</div>'
        "</div></div>",
        unsafe_allow_html=True,
    )

    # ── SECTION 2 — Two columns (55 / 45) ───────────────────────────
    left_col, right_col = st.columns([55, 45], gap="large")

    # ── LEFT (55%): architecture diagram + stats + steps + concepts ─
    with left_col:
        # Part A — Architecture diagram with three connected boxes
        st.markdown(
            '<div class="rx-section-eyebrow">🏗️ ARCHITECTURE</div>'
            '<div class="rx-arch-box rx-arch-box-red">'
            '<div class="rx-arch-title">☠️ YOUR LLM APP</div>'
            '<div class="rx-arch-desc">Unprotected attack surface</div>'
            '<div class="rx-arch-sub">Vulnerable to OWASP LLM Top 10</div>'
            "</div>"
            '<div class="rx-arch-flow">'
            '<div class="rx-arch-dot"></div>'
            '<div class="rx-arch-dot"></div>'
            '<div class="rx-arch-dot"></div>'
            "</div>"
            '<div class="rx-arch-box rx-arch-box-cyan">'
            '<div class="rx-arch-title">🛡️ REMEDIAX ENGINE</div>'
            '<div class="rx-arch-desc">SCAN &rarr; DETECT &rarr; REMEDIATE &rarr; VERIFY</div>'
            '<div class="rx-arch-sub">Human-in-the-loop approval required</div>'
            "</div>"
            '<div class="rx-arch-flow">'
            '<div class="rx-arch-dot"></div>'
            '<div class="rx-arch-dot"></div>'
            '<div class="rx-arch-dot"></div>'
            "</div>"
            '<div class="rx-arch-box rx-arch-box-green">'
            '<div class="rx-arch-title">✅ HARDENED LLM</div>'
            '<div class="rx-arch-desc">Protected by guardrails.yaml</div>'
            '<div class="rx-arch-sub">Zero known attack vectors</div>'
            "</div>",
            unsafe_allow_html=True,
        )

        # Part B — Stats row (4 badges)
        st.markdown(
            '<div class="rx-stat-badges">'
            '<div class="rx-stat-badge">'
            '<div class="rx-stat-badge-v">☠️ 10</div>'
            '<div class="rx-stat-badge-l">Attack Classes Covered</div></div>'
            '<div class="rx-stat-badge">'
            '<div class="rx-stat-badge-v">🛡️ 321</div>'
            '<div class="rx-stat-badge-l">Security Controls</div></div>'
            '<div class="rx-stat-badge">'
            '<div class="rx-stat-badge-v">⚡ Real-time</div>'
            '<div class="rx-stat-badge-l">Analysis</div></div>'
            '<div class="rx-stat-badge">'
            '<div class="rx-stat-badge-v">👤 HITL</div>'
            '<div class="rx-stat-badge-l">Human-in-the-Loop</div></div>'
            "</div>",
            unsafe_allow_html=True,
        )

        # Part C — Horizontal "How It Works" with arrows between
        st.markdown(
            '<div class="rx-section-eyebrow" style="margin-top:18px;">'
            "⚙️ HOW IT WORKS</div>",
            unsafe_allow_html=True,
        )
        howit_steps = [
            ("1️⃣", "SCAN",    "Run garak scanner"),
            ("2️⃣", "DETECT",  "Upload hitlog.jsonl"),
            ("3️⃣", "REVIEW",  "Review findings"),
            ("4️⃣", "APPROVE", "Approve patches"),
            ("5️⃣", "DEPLOY",  "Deploy guardrails"),
        ]
        items: list[str] = []
        for i, (num, title, desc) in enumerate(howit_steps):
            items.append(
                f'<div class="rx-howit-step">'
                f'<div class="rx-howit-num">{num}</div>'
                f'<div class="rx-howit-title">{title}</div>'
                f'<div class="rx-howit-desc">{desc}</div>'
                f"</div>"
            )
            if i < len(howit_steps) - 1:
                items.append('<div class="rx-howit-arrow">&rarr;</div>')
        st.markdown(
            '<div class="rx-howit-row">' + "".join(items) + "</div>",
            unsafe_allow_html=True,
        )

        # Part D — 2x2 security concepts grid
        st.markdown(
            '<div class="rx-section-eyebrow" style="margin-top:18px;">'
            "🛡️ SECURITY CONCEPTS</div>",
            unsafe_allow_html=True,
        )
        concepts = [
            ("orange", "PROMPT INJECTION",
             "Attackers embed hidden commands in user input to hijack "
             "your LLM behavior at runtime."),
            ("cyan", "ZERO-TRUST REMEDIATION",
             "No patch auto-applies. Every fix requires explicit human "
             "approval by design."),
            ("green", "GUARDRAILS",
             "Deployable config blocking malicious inputs before they "
             "reach your LLM model."),
            ("red", "JAILBREAK ATTACKS",
             "Bypassing LLM safety using roleplay and encoding tricks. "
             "RemediAX catches all patterns."),
        ]
        grid_inner = "".join(
            f'<div class="rx-callout rx-callout-{color}">'
            f'<div class="rx-callout-title">{title}</div>'
            f'<div class="rx-callout-body">{body}</div>'
            f"</div>"
            for color, title, body in concepts
        )
        st.markdown(
            f'<div class="rx-concepts-grid">{grid_inner}</div>',
            unsafe_allow_html=True,
        )

    # ── RIGHT (45%): authentication portal ───────────────────────────
    with right_col:
        # Marker the CSS uses to find this column and apply the cyan glow.
        st.markdown('<div class="rx-login-marker"></div>', unsafe_allow_html=True)
        st.markdown(
            '<div class="rx-login-title">🛡️ AUTHENTICATION PORTAL</div>'
            '<div class="rx-login-tagline">AI Security &middot; Human Control</div>'
            '<hr style="border:none;border-top:1px solid #00d4ff;'
            'opacity:0.4;margin:6px 0 14px;">',
            unsafe_allow_html=True,
        )

        if not is_firebase_ready():
            st.warning(
                "Firebase is not configured for this deployment. "
                "Email/password login is unavailable. Use the **Admin "
                "token login** at the bottom to sign in with an RMX-* "
                "token."
            )
            error = get_init_error()
            if error:
                with st.expander("🔍 Diagnostic — why Firebase init failed"):
                    st.code(error, language="text")
                    st.caption(
                        "This message is also visible in the Streamlit "
                        "Cloud → Manage app → Logs panel. If you fix "
                        "the secrets and reboot the app the message will "
                        "disappear."
                    )

        login_tab, signup_tab = st.tabs(["🔓 ANALYST LOGIN", "✨ NEW OPERATOR"])

        with login_tab:
            _render_login_tab()

        with signup_tab:
            _render_signup_tab()

        # Premium-access request
        st.markdown(
            '<div class="rx-access-divider">──── or ────</div>',
            unsafe_allow_html=True,
        )
        if st.button(
            "🎟️ Request Premium Access",
            use_container_width=True,
            key="access-premium",
        ):
            st.session_state.show_premium_form = True
        if st.session_state.get("show_premium_form"):
            _render_premium_request_form()

        # Trial-token entry — collapsible section visible to everyone
        # so users who received a 7-day trial token via email can find
        # where to paste it without knowing about the ``?admin=true``
        # back-door URL.
        with st.expander("🔑 Have an access token?", expanded=False):
            _render_trial_token_form()

        # Admin token login — hidden by default. Surfaced only when the
        # URL carries ``?admin=true`` so the public landing stays clean.
        # Admins bookmark ``/?admin=true`` for the back-door form.
        if _admin_login_unlocked():
            with st.expander("🛡️ Admin token login", expanded=True):
                _render_admin_token_form()

    # ── SECTION 3 — Full-width bottom badges bar ────────────────────
    bottom_items = [
        "🔒 Zero-Trust Auth",
        "🔐 TLS Encrypted",
        "👤 Human-in-the-Loop",
        "☠️ Adversarial Input Hardening",
        "🚫 No Data Persistence",
        "♾️ CI/CD Verified",
    ]
    bottom_html = (
        '<span class="rx-bb-sep">|</span>'.join(
            f'<span class="rx-bb-item">{item}</span>' for item in bottom_items
        )
        + '<span class="rx-bb-sep">|</span>'
        + '<span class="rx-bb-author">Built by Nileshwari Kadgale</span>'
    )
    st.markdown(
        f'<div class="rx-bottom-bar">{bottom_html}</div>',
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Screen 1 — Landing
# ---------------------------------------------------------------------------


def render_landing() -> None:
    # ── HERO ──────────────────────────────────────────────────────────
    st.markdown(
        '<div class="remediax-hero"><h1>🛡️ REMEDIAX</h1>'
        '<div class="tagline">Detect • Remediate • Verify • Protect</div>'
        '<div style="color:#8b949e;margin-top:6px;">'
        "Covering all 10 OWASP LLM vulnerability categories.</div></div>",
        unsafe_allow_html=True,
    )

    # Animated subtitle cycle (pure CSS — no JS).
    st.markdown(
        '<div class="rx-subtitle-cycle">'
        "<span>Scanning for prompt injection exploits&hellip;</span>"
        "<span>Neutralizing jailbreak attack vectors&hellip;</span>"
        "<span>Zero-trust remediation pipeline active&hellip;</span>"
        "<span>Threat surface hardened. Human approved &check;</span>"
        "</div>",
        unsafe_allow_html=True,
    )

    # Three stat badges row.
    st.markdown(
        '<div class="rx-stat-row">'
        '<div class="rx-stat">'
        '<div><span class="rx-stat-icon">☠️</span> '
        '<span class="rx-stat-value">10</span></div>'
        '<div class="rx-stat-label">Attack Classes Covered</div></div>'
        '<div class="rx-stat">'
        '<div><span class="rx-stat-icon">🛡️</span> '
        '<span class="rx-stat-value">321</span></div>'
        '<div class="rx-stat-label">Security Controls Verified</div></div>'
        '<div class="rx-stat">'
        '<div><span class="rx-stat-icon">⚡</span> '
        '<span class="rx-stat-value">Real-time</span></div>'
        '<div class="rx-stat-label">Threat Neutralization</div></div>'
        "</div>",
        unsafe_allow_html=True,
    )

    # ── THREE THREAT CARDS ───────────────────────────────────────────
    c1, c2, c3 = st.columns(3)
    c1.markdown(
        '<div class="rx-threat-card">'
        '<div class="rx-threat-title">☠️ EXPLOIT DETECTION</div>'
        '<div class="rx-threat-body">'
        "Surface prompt injection, jailbreaks, data exfiltration and "
        "all OWASP LLM Top 10 attack vectors across your AI threat surface."
        "</div></div>",
        unsafe_allow_html=True,
    )
    c2.markdown(
        '<div class="rx-threat-card">'
        '<div class="rx-threat-title">🔧 ZERO-TRUST REMEDIATION</div>'
        '<div class="rx-threat-body">'
        "No patch auto-applies. Every remediation requires explicit "
        "human approval &mdash; zero-trust security by design."
        "</div></div>",
        unsafe_allow_html=True,
    )
    c3.markdown(
        '<div class="rx-threat-card">'
        '<div class="rx-threat-title">🛡️ HARDENED DEPLOYMENT</div>'
        '<div class="rx-threat-body">'
        "Export battle-tested guardrail configs. Block known attack "
        "patterns at the LLM gateway layer before they execute."
        "</div></div>",
        unsafe_allow_html=True,
    )

    # ── UPLOAD / DEMO ────────────────────────────────────────────────
    st.markdown(
        '<div class="rx-section-header">⚡ Initialize Threat Analysis</div>'
        '<div class="rx-section-subtext">'
        "Upload garak <code>hitlog.jsonl</code> to scan your AI attack "
        "surface, or run our live exploit demonstration."
        "</div>",
        unsafe_allow_html=True,
    )

    # Tier-aware quota banner. Unlimited tiers get a subtle note; basic
    # users see remaining / upsell.
    at_limit = False
    if _is_unlimited_tier():
        st.caption("✅ Unlimited scans on this tier.")
    else:
        remaining = _scans_remaining_this_month()
        if remaining == 0:
            _render_quota_exceeded_message()
            at_limit = True
        else:
            st.info(
                f"🔬 Analyst tier — **{remaining}** free scan(s) remaining "
                f"this month. Upgrade for unlimited scanning."
            )

    up_col, demo_col = st.columns([3, 2])
    with up_col:
        if not _has_premium():
            _render_locked_feature(
                "Upload your own scan",
                "Upgrade to Security Engineer access to upload your own "
                "threat data (garak hitlog.jsonl / report.jsonl). Basic "
                "tier users can run the live demo to explore the engine.",
                key_suffix="-upload",
            )
        else:
            st.markdown('<div class="rx-upload-frame">', unsafe_allow_html=True)
            uploaded = st.file_uploader(
                "garak hitlog",
                type=("jsonl", "json"),
                label_visibility="collapsed",
                disabled=at_limit,
            )
            st.markdown("</div>", unsafe_allow_html=True)
            if uploaded is not None and st.button(
                "▶ Process upload",
                use_container_width=True,
                disabled=at_limit,
            ):
                if not _can_run_scan():
                    _render_quota_exceeded_message()
                else:
                    _ingest_uploaded(uploaded, source="upload")

    with demo_col:
        if st.button(
            "▶ Run Live Exploit Demo",
            use_container_width=True,
            type="primary",
            disabled=at_limit,
        ):
            if not _can_run_scan():
                _render_quota_exceeded_message()
            else:
                findings = load_demo_findings()
                st.session_state.findings = findings
                st.session_state.current_upload_filename = None
                _consume_scan_quota(source="demo", findings=findings)
                st.session_state.screen = "summary"
                st.rerun()
        st.caption("Real attack patterns • All 10 LLM categories.")

    # ── SECURITY POSTURE BADGES ──────────────────────────────────────
    badges = [
        "🔒 Zero-Trust Auth",
        "🔐 TLS Encrypted",
        "👤 Human-in-the-Loop Control",
        "☠️ Adversarial Input Hardening",
        "🚫 No Data Persistence",
        "♾️ CI/CD Verified",
    ]
    items = '<span class="rx-sb-sep">|</span>'.join(
        f'<span class="rx-sb">{b}</span>' for b in badges
    )
    st.markdown(
        f'<div class="rx-security-badges">{items}</div>',
        unsafe_allow_html=True,
    )

    st.caption(
        f"Built by Nileshwari Kadgale &middot; [GitHub]({_GITHUB_URL})"
    )


def _ingest_uploaded(uploaded: Any, *, source: str = "upload") -> None:
    """Parse the uploaded JSONL via GarakParser and advance to summary.

    Records the upload event in Firestore (collection: ``uploads``)
    BEFORE parsing so failed parses are still observable in analytics,
    then re-saves the same record with the findings count once
    parsing succeeds. Stashes the filename in session state so the
    downstream scan record can carry it through to completion.
    """
    file_bytes = uploaded.getvalue()
    file_size = len(file_bytes)
    filename = uploaded.name
    st.session_state.current_upload_filename = filename

    # Record the upload attempt first — analytics should see it even
    # if parsing fails below.
    upload_uid = _storage_uid()
    upload_payload: dict[str, Any] = {
        "timestamp": datetime.utcnow().isoformat(),
        "filename": filename,
        "file_size": file_size,
        "source": source,
        "status": "uploaded",
        "findings_count": 0,
    }
    logger.info(
        "_ingest_uploaded: calling save_upload (firebase_ready=%s) "
        "uid=%s filename=%s size=%d source=%s",
        is_firebase_ready(),
        upload_uid,
        filename,
        file_size,
        source,
    )
    upload_id = save_upload(upload_uid, upload_payload)
    if upload_id:
        st.session_state.current_upload_id = upload_id
        logger.info(
            "_ingest_uploaded: Firestore confirmed upload id=%s "
            "at users/%s/uploads/%s",
            upload_id,
            upload_uid,
            upload_id,
        )
    else:
        logger.warning(
            "_ingest_uploaded: save_upload returned None for uid=%s filename=%s "
            "(Firebase not configured or write failed — analytics will miss this upload)",
            upload_uid,
            filename,
        )

    tmp_dir = Path(tempfile.mkdtemp(prefix="remediax-upload-"))
    src_path = tmp_dir / filename
    src_path.write_bytes(file_bytes)
    try:
        findings = GarakParser(src_path).parse()
    except Exception as exc:
        st.error(f"Could not parse uploaded file: {exc}")
        # Best-effort: mark the upload record as parse-failed so
        # analytics can distinguish bad uploads from successful ones.
        if upload_id:
            try:
                save_upload(
                    upload_uid,
                    {**upload_payload, "status": "parse_failed", "error": str(exc)},
                )
            except Exception:  # pragma: no cover - defensive
                pass
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return
    if not findings:
        st.warning("No findings detected in this file.")
        if upload_id:
            try:
                save_upload(
                    upload_uid,
                    {**upload_payload, "status": "no_findings"},
                )
            except Exception:  # pragma: no cover - defensive
                pass
        shutil.rmtree(tmp_dir, ignore_errors=True)
        return
    # Re-record the upload now that we know the findings count.
    if upload_id:
        try:
            save_upload(
                upload_uid,
                {
                    **upload_payload,
                    "status": "parsed",
                    "findings_count": len(findings),
                },
            )
        except Exception:  # pragma: no cover - defensive
            pass
    st.session_state.findings = findings
    _consume_scan_quota(source=source, findings=findings)
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

    # Auto-save completion stats the moment the user reaches this
    # screen so analytics captures the scan even if they close the
    # tab without clicking Apply. Idempotent — guarded by the scan
    # id so repeated reruns of the same review don't re-write.
    current_scan_id = st.session_state.get("current_scan_id")
    if (
        current_scan_id
        and st.session_state.get("complete_saved_scan_id") != current_scan_id
    ):
        _save_completed_scan_results()
        st.session_state.complete_saved_scan_id = current_scan_id

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
    # Update the Firestore scan record with completion stats so the
    # Analytics dashboard has fix-rate / security-score data to chart.
    _save_completed_scan_results()
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
    if not _has_premium():
        # Lock 2 + 3 (artifact downloads + guardrails export combined).
        # Basic users see the artifact LIST so they know what's available,
        # but cannot download them.
        _render_locked_feature(
            "Artifact downloads",
            "Upgrade to download security artifacts and export guardrail "
            "configs — findings.json, remediation_results.json, "
            "verification_report.json, guardrails.yaml, "
            "patched_prompts.md, and summary.html.",
            key_suffix="-downloads",
        )
        for artifact in final_report.artifacts:
            st.caption(
                f"📄 {artifact.filename} &middot; {artifact.size_bytes:,} "
                f"bytes &middot; {artifact.description}"
            )
    else:
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
# Screen — Garak Scanner
# ---------------------------------------------------------------------------


_PROBE_OPTIONS: list[tuple[str, str, bool]] = [
    # (UI label, garak probe code, default-checked)
    ("Prompt Injection (DAN)", "dan", True),
    ("Jailbreak attempts", "promptinject", True),
    ("Data exfiltration", "leakreplay", True),
    ("Supply chain attacks", "knownbadsignatures", True),
    ("Hallucination probes", "snowball", False),
]

_TARGET_PROVIDERS: dict[str, list[str]] = {
    "LLM Model": [
        "OpenAI GPT-4",
        "OpenAI GPT-3.5",
        "Anthropic Claude",
        "Google Gemini",
        "Meta Llama",
        "Mistral",
        "Custom endpoint",
    ],
    "AI Agent": [
        "LangChain",
        "AutoGPT",
        "CrewAI",
        "Custom REST",
    ],
    "REST API Endpoint": ["Generic REST API"],
    "Chatbot Application": [
        "Web Chatbot (custom built)",
        "Slack Bot",
        "Discord Bot",
        "Microsoft Teams Bot",
        "WhatsApp Bot",
        "Telegram Bot",
        "Intercom",
        "Zendesk",
        "Salesforce Einstein Bot",
        "HubSpot Chatbot",
        "Drift",
        "LiveChat",
        "Custom REST API endpoint",
    ],
    "Custom Python Function": ["Python function wrapper"],
}


def _build_garak_command(
    target: str, provider: str, probe_codes: list[str]
) -> tuple[str, str, str]:
    """Return (install_step, command, estimate) for the chosen target/provider.

    ``install_step`` is the pip install line (always
    ``pip install garak``). ``command`` is the runnable garak invocation
    with the user-selected probes injected. ``estimate`` is a coarse
    expected runtime label.
    """
    install = "pip install garak"
    if probe_codes:
        probe_arg = ",".join(probe_codes)
        probe_flag = f" --probes {probe_arg}"
        estimate = "5–10 minutes (selected probes only)"
    else:
        probe_flag = ""
        estimate = "30–60 minutes (all probes)"

    cmd: str
    if target == "LLM Model":
        if "OpenAI" in provider:
            cmd = (
                f"garak --model openai "
                f"--model_type openai.OpenAIGenerator{probe_flag} "
                f"--generations 5"
            )
        elif "Claude" in provider:
            cmd = (
                f"garak --model anthropic "
                f"--model_type anthropic.AnthropicGenerator{probe_flag} "
                f"--generations 5"
            )
        elif "Gemini" in provider:
            cmd = (
                f"garak --model googleai "
                f"--model_type googleai.GoogleAIGenerator{probe_flag} "
                f"--generations 5"
            )
        elif "Llama" in provider:
            cmd = (
                f"garak --model huggingface "
                f"--model_type huggingface.Model "
                f"--model_name meta-llama/Llama-3-8B-Instruct"
                f"{probe_flag} --generations 5"
            )
        elif "Mistral" in provider:
            cmd = (
                f"garak --model huggingface "
                f"--model_type huggingface.Model "
                f"--model_name mistralai/Mistral-7B-Instruct-v0.2"
                f"{probe_flag} --generations 5"
            )
        else:  # Custom endpoint
            cmd = (
                f"garak --model rest --model_type rest.RestGenerator "
                f"--uri YOUR_ENDPOINT_URL{probe_flag} --generations 5"
            )
    elif target == "AI Agent":
        if "LangChain" in provider:
            cmd = (
                "# First wrap your LangChain agent with garak's function "
                "generator:\n"
                "# from garak.generators.function import SingleFunction\n"
                "# Save a Python file (e.g. agent_wrap.py) that exposes a\n"
                "# top-level `call(prompt: str) -> str` function which\n"
                "# invokes your agent and returns the string output.\n"
                "\n"
                f"garak --model function "
                f"--model_type function.SingleFunction "
                f"--model_name agent_wrap.call{probe_flag} --generations 5"
            )
        elif "AutoGPT" in provider or "CrewAI" in provider:
            cmd = (
                f"# Expose your agent's input/output as a callable "
                f"function, then run:\n"
                f"garak --model function "
                f"--model_type function.SingleFunction "
                f"--model_name your_module.call{probe_flag} "
                f"--generations 5"
            )
        else:  # Custom REST
            cmd = (
                f"garak --model rest --model_type rest.RestGenerator "
                f"--uri YOUR_AGENT_REST_URL{probe_flag} --generations 5"
            )
    elif target == "REST API Endpoint":
        cmd = (
            f"garak --model rest --model_type rest.RestGenerator "
            f"--uri YOUR_ENDPOINT_URL{probe_flag} --generations 5"
        )
    elif target == "Chatbot Application":
        cmd = (
            f"# Most chatbots expose a webhook URL or Bot API. Point "
            f"garak's REST generator at it:\n"
            f"garak --model rest --model_type rest.RestGenerator "
            f"--uri YOUR_CHATBOT_WEBHOOK{probe_flag} --generations 5"
        )
    else:  # Custom Python Function
        cmd = (
            f"# Save a Python file (e.g. my_target.py) exposing\n"
            f"# def call(prompt: str) -> str:\n"
            f"#     return your_model(prompt)\n"
            f"\n"
            f"garak --model function "
            f"--model_type function.SingleFunction "
            f"--model_name my_target.call{probe_flag} --generations 5"
        )
    return install, cmd, estimate


def render_scanner() -> None:
    """Garak Scanner — generate ready-to-run commands for the user's target."""
    st.markdown(
        '<div class="remediax-hero"><h1>📡 GARAK THREAT SCANNER</h1>'
        '<div class="tagline">Scan any LLM or AI agent for security '
        "vulnerabilities</div></div>",
        unsafe_allow_html=True,
    )

    # ── STEP 1 — Target type ────────────────────────────────────────
    st.markdown(
        '<div class="rx-section-eyebrow">STEP 1 — SELECT TARGET TYPE</div>',
        unsafe_allow_html=True,
    )
    target = st.radio(
        "Target type",
        list(_TARGET_PROVIDERS.keys()),
        index=0,
        key="scanner-target",
        label_visibility="collapsed",
    )

    # ── STEP 2 — Provider (depends on Step 1) ───────────────────────
    st.markdown(
        '<div class="rx-section-eyebrow" style="margin-top:18px;">'
        "STEP 2 — SELECT PROVIDER</div>",
        unsafe_allow_html=True,
    )
    providers = _TARGET_PROVIDERS[target]
    provider = st.radio(
        "Provider",
        providers,
        index=0,
        key=f"scanner-provider-{target}",
        label_visibility="collapsed",
    )
    if target == "Chatbot Application":
        st.caption(
            "Don't see your platform? Select **Custom REST API endpoint** — "
            "works for any chatbot that accepts text via HTTP."
        )

    # ── STEP 3 — Probes ─────────────────────────────────────────────
    st.markdown(
        '<div class="rx-section-eyebrow" style="margin-top:18px;">'
        "STEP 3 — SELECT ATTACK PROBES</div>",
        unsafe_allow_html=True,
    )
    selected_codes: list[str] = []
    for label, code, default_checked in _PROBE_OPTIONS:
        checked = st.checkbox(
            label,
            value=default_checked,
            key=f"scanner-probe-{code}",
        )
        if checked:
            selected_codes.append(code)

    # "All probes" — premium only.
    has_premium = _has_premium()
    all_probes_label = "All probes (full sweep)"
    if has_premium:
        all_probes = st.checkbox(
            all_probes_label,
            value=False,
            key="scanner-probe-all",
            help="Runs every garak probe — much slower but maximum coverage.",
        )
        if all_probes:
            selected_codes = []  # empty → no --probes flag → garak runs all
    else:
        st.checkbox(
            f"🔒 {all_probes_label}",
            value=False,
            key="scanner-probe-all-locked",
            disabled=True,
            help="Premium feature — upgrade for full-sweep scans.",
        )
        st.caption(
            "🔒 *All probes* is a Security Engineer feature. Run individual "
            "probes above on the basic tier."
        )

    # ── STEP 4 — Generated commands ─────────────────────────────────
    st.markdown(
        '<div class="rx-section-eyebrow" style="margin-top:18px;">'
        "STEP 4 — GENERATED COMMANDS</div>",
        unsafe_allow_html=True,
    )
    install_step, cmd, estimate = _build_garak_command(
        target, provider, selected_codes
    )
    st.caption("**Step 4a — Install garak:**")
    st.code(install_step, language="bash")
    st.caption("**Step 4b — Run the scan:**")
    st.code(cmd, language="bash")
    st.caption(f"⏱️ Estimated scan time: **{estimate}**")

    # ── STEP 5 — Find results ───────────────────────────────────────
    st.markdown(
        '<div class="rx-section-eyebrow" style="margin-top:18px;">'
        "STEP 5 — FIND YOUR RESULTS</div>",
        unsafe_allow_html=True,
    )
    st.markdown(
        "garak writes a `hitlog.jsonl` to a per-user data directory:\n\n"
        "- **Windows:** `C:\\Users\\<USERNAME>\\.local\\share\\garak\\`\n"
        "- **macOS / Linux:** `~/.local/share/garak/`\n\n"
        "Each run also produces a `report.jsonl` file in the same folder."
    )
    st.code(
        "# Windows\n"
        "explorer %USERPROFILE%\\.local\\share\\garak\n\n"
        "# macOS / Linux\n"
        "ls -la ~/.local/share/garak",
        language="bash",
    )

    # ── STEP 6 — Upload results ─────────────────────────────────────
    st.markdown(
        '<div class="rx-section-eyebrow" style="margin-top:18px;">'
        "STEP 6 — UPLOAD RESULTS TO REMEDIAX</div>",
        unsafe_allow_html=True,
    )
    if not has_premium:
        _render_locked_feature(
            "Upload scan results",
            "Upload your scan results to RemediAX for analysis and "
            "remediation. Upgrade to Security Engineer to ingest your "
            "own hitlog.jsonl / report.jsonl files.",
            key_suffix="-scanner-upload",
        )
    else:
        st.markdown(
            '<div class="rx-upload-frame">', unsafe_allow_html=True
        )
        uploaded = st.file_uploader(
            "garak hitlog or report",
            type=("jsonl", "json"),
            label_visibility="collapsed",
            key="scanner-uploader",
        )
        st.markdown("</div>", unsafe_allow_html=True)
        if uploaded is not None and st.button(
            "▶ Analyze in RemediAX",
            use_container_width=True,
            type="primary",
            key="scanner-process",
        ):
            if not _can_run_scan():
                _render_quota_exceeded_message()
            else:
                _ingest_uploaded(uploaded, source="scanner-upload")

    # ── STEP 7 — Or use the live demo ───────────────────────────────
    st.markdown(
        '<div class="rx-section-eyebrow" style="margin-top:18px;">'
        "STEP 7 — OR TRY THE LIVE DEMO</div>",
        unsafe_allow_html=True,
    )
    st.caption(
        "See how RemediAX works with sample attack data &mdash; no setup needed."
    )
    if st.button(
        "▶ Run Live Exploit Demo",
        use_container_width=True,
        type="primary",
        key="scanner-demo",
    ):
        if not _can_run_scan():
            _render_quota_exceeded_message()
        else:
            findings = load_demo_findings()
            st.session_state.findings = findings
            st.session_state.current_upload_filename = None
            _consume_scan_quota(source="scanner-demo", findings=findings)
            st.session_state.screen = "summary"
            st.rerun()

    # ── EDUCATIONAL CARDS ───────────────────────────────────────────
    st.markdown(
        '<div class="rx-section-eyebrow" style="margin-top:30px;">'
        "🛡️ ABOUT GARAK</div>",
        unsafe_allow_html=True,
    )
    edu = [
        ("cyan", "WHAT IS GARAK?",
         "Open-source LLM security testing framework by NVIDIA. Probes "
         "your AI with thousands of known attack patterns."),
        ("orange", "HOW LONG DOES IT TAKE?",
         "Quick scan: 5–10 minutes. Full scan: 30–60 minutes. Depends on "
         "the number of probes and API response speed."),
        ("green", "IS MY API KEY SAFE?",
         "Your API key never touches RemediAX servers. Garak runs entirely "
         "on your local machine. We only see the results."),
        ("red", "WHAT ATTACKS ARE TESTED?",
         "DAN jailbreaks, prompt injection, data exfiltration, encoding "
         "attacks, supply chain, and 50+ more probe types."),
    ]
    cards_html = "".join(
        f'<div class="rx-callout rx-callout-{color}">'
        f'<div class="rx-callout-title">{title}</div>'
        f'<div class="rx-callout-body">{body}</div>'
        f"</div>"
        for color, title, body in edu
    )
    st.markdown(
        f'<div class="rx-concepts-grid">{cards_html}</div>',
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Screen — Analytics
# ---------------------------------------------------------------------------


def _vuln_label_for_owasp(code: str) -> str:
    """Map an OWASP LLM code to a human-readable vulnerability name."""
    mapping = {
        "LLM01": "Prompt Injection",
        "LLM02": "Sensitive Information Disclosure",
        "LLM03": "Supply Chain Vulnerabilities",
        "LLM04": "Data and Model Poisoning",
        "LLM05": "Improper Output Handling",
        "LLM06": "Excessive Agency",
        "LLM07": "System Prompt Leakage",
        "LLM08": "Vector and Embedding Weaknesses",
        "LLM09": "Misinformation",
        "LLM10": "Unbounded Consumption",
    }
    return mapping.get(code, code)


def _load_history() -> list[dict[str, Any]]:
    """Return the active user's Firestore scan history (newest first).

    Reads ``users/{_storage_uid()}/scans`` — the same path
    ``_consume_scan_quota`` and ``_save_completed_scan_results`` write
    to, so every tier sees exactly what their session writes:

    * Firebase users → ``users/<firebase-uid>/scans``
    * Admin-token users → ``users/admin/scans`` (literal "admin" uid)
    * Guests → ``users/guest/scans``

    Previously the admin path short-circuited to ``get_all_scans()``
    which used a Firestore ``collection_group("scans")`` query — that
    requires a collection-group index on ``created_at`` and fails
    silently to ``[]`` when the index is missing. Per-uid reads need
    no index and surface the writes immediately.
    """
    uid = _storage_uid()
    logger.info("_load_history: querying users/%s/scans (limit=100)", uid)
    try:
        records = list(get_user_scans(uid, limit=100))
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning(
            "_load_history: FAILED uid=%s: %s", uid, exc
        )
        return []
    logger.info(
        "_load_history: returned %d record(s) for uid=%s", len(records), uid
    )
    return records


def _load_uploads() -> list[dict[str, Any]]:
    """Return the active user's upload history (newest first).

    Reads ``users/{_storage_uid()}/uploads``. Same per-uid strategy
    as ``_load_history`` — no collection-group index needed, matches
    the path ``_ingest_uploaded`` writes to.
    """
    uid = _storage_uid()
    logger.info("_load_uploads: querying users/%s/uploads (limit=100)", uid)
    try:
        records = list(get_user_uploads(uid, limit=100))
    except Exception as exc:  # pragma: no cover - defensive
        logger.warning(
            "_load_uploads: FAILED uid=%s: %s", uid, exc
        )
        return []
    logger.info(
        "_load_uploads: returned %d record(s) for uid=%s", len(records), uid
    )
    return records


def _completed_history(history: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Filter to scans that reached the results screen (have completion data)."""
    return [h for h in history if h.get("status") == "completed"]


def _current_scan_metrics() -> dict[str, Any] | None:
    """Compute current-scan metrics from session state when findings exist."""
    findings: list[Finding] = st.session_state.get("findings") or []
    if not findings:
        return None
    total = len(findings)
    approved = st.session_state.get("approved") or []
    skipped = st.session_state.get("skipped") or []
    sev = _count_severities(findings)
    owasp = _count_owasp(findings)
    fix_rate = (len(approved) / total * 100.0) if total else 0.0
    security_score = calculate_security_score(findings)
    return {
        "total": total,
        "approved": len(approved),
        "skipped": len(skipped),
        "fix_rate": round(fix_rate, 1),
        "security_score": round(security_score, 1),
        "severity_counts": sev,
        "owasp_counts": owasp,
    }


def _format_file_size(size: int | float | None) -> str:
    """Human-readable file size (KB/MB) for the upload history table."""
    try:
        n = float(size or 0)
    except (TypeError, ValueError):
        return "—"
    if n < 1024:
        return f"{int(n)} B"
    if n < 1024 * 1024:
        return f"{n / 1024:.1f} KB"
    return f"{n / (1024 * 1024):.1f} MB"


def _activity_totals(
    history: list[dict[str, Any]],
    uploads: list[dict[str, Any]],
) -> dict[str, int]:
    """Roll up totals for the ACTIVITY OVERVIEW section."""
    completed = _completed_history(history)
    total_uploads = len(uploads)
    total_completed_scans = len(completed)
    total_findings = sum(int(h.get("total_findings", 0)) for h in completed)
    total_approved = sum(int(h.get("approved_count", 0)) for h in completed)
    return {
        "uploads": total_uploads,
        "scans_completed": total_completed_scans,
        "vulnerabilities": total_findings,
        "approved": total_approved,
    }


def _render_activity_overview(
    history: list[dict[str, Any]],
    uploads: list[dict[str, Any]],
) -> None:
    """ACTIVITY OVERVIEW — 4 metric cards visible to every tier."""
    totals = _activity_totals(history, uploads)
    st.markdown(
        '<div class="rx-section-eyebrow">ACTIVITY OVERVIEW</div>',
        unsafe_allow_html=True,
    )
    cols = st.columns(4)
    cols[0].metric("Total files uploaded", totals["uploads"])
    cols[1].metric("Total scans completed", totals["scans_completed"])
    cols[2].metric("Total vulnerabilities found", totals["vulnerabilities"])
    cols[3].metric("Total patches approved", totals["approved"])


def _render_upload_history_table(
    uploads: list[dict[str, Any]],
    *,
    limit: int = 10,
) -> None:
    """Upload history table — surfaced for every tier."""
    st.markdown(
        '<div class="rx-section-eyebrow" style="margin-top:18px;">'
        "UPLOAD HISTORY</div>",
        unsafe_allow_html=True,
    )
    if not uploads:
        st.caption("No uploads yet.")
        return
    rows = [
        {
            "Date": str(u.get("timestamp") or u.get("created_at") or "")[:16],
            "Filename": u.get("filename") or "—",
            "Size": _format_file_size(u.get("file_size")),
            "Findings": int(u.get("findings_count", 0)),
            "Status": str(u.get("status") or "uploaded"),
        }
        for u in uploads[:limit]
    ]
    st.dataframe(rows, use_container_width=True, hide_index=True)


def _build_owasp_csv(history: list[dict[str, Any]]) -> str:
    """Build a CSV export of completed-scan history."""
    header = (
        "created_at,source,total_findings,approved,skipped,"
        "fix_rate,security_score,verified,partial,failed"
    )
    rows = [header]
    for h in history:
        rows.append(
            ",".join(
                str(x)
                for x in (
                    h.get("created_at", ""),
                    h.get("source", ""),
                    h.get("total_findings", 0),
                    h.get("approved_count", 0),
                    h.get("skipped_count", 0),
                    h.get("fix_rate", 0),
                    h.get("security_score", 0),
                    h.get("verified_count", 0),
                    h.get("partial_count", 0),
                    h.get("failed_count", 0),
                )
            )
        )
    return "\n".join(rows) + "\n"


def _render_empty_charts_placeholder() -> None:
    """Inline 'no completed scans' placeholder for the premium chart sections.

    Used in place of the trend / breakdown charts when a user (or
    admin) has not yet run a review. Kept short and inline so the
    Activity Overview and Upload History above it stay visible — the
    old behavior replaced the entire dashboard, which hid the running
    totals (even when zero) and made the page feel broken on first
    visit.
    """
    st.info(
        "📊 Run your first scan to see trends here. Head to the landing "
        "page or the Garak scanner to upload a hitlog or run the demo."
    )


def _render_analytics_basic(
    history: list[dict[str, Any]],
    uploads: list[dict[str, Any]],
) -> None:
    """Basic-tier view: always-on Activity Overview + uploads + current-scan + upsell.

    The empty-state message is gone from the top level — even brand-
    new users see the 4 Activity metric cards with zeros so they
    understand what the page will eventually show.
    """
    metrics = _current_scan_metrics()

    # ── ACTIVITY OVERVIEW — always render, zeros are fine ──────────
    _render_activity_overview(history, uploads)

    # ── CURRENT SCAN — only when there is an in-progress scan ──────
    if metrics is not None:
        st.markdown(
            '<div class="rx-section-eyebrow" style="margin-top:18px;">'
            "CURRENT SCAN</div>",
            unsafe_allow_html=True,
        )
        cols = st.columns(4)
        cols[0].metric("Security score", f"{metrics['security_score']}%")
        cols[1].metric("Total findings", metrics["total"])
        cols[2].metric("Approved (fixed)", metrics["approved"])
        cols[3].metric("Skipped", metrics["skipped"])
        _render_score_badge(metrics["security_score"])

        st.markdown(
            '<div class="rx-section-eyebrow" style="margin-top:18px;">'
            "OWASP BREAKDOWN (CURRENT SCAN)</div>",
            unsafe_allow_html=True,
        )
        owasp = metrics["owasp_counts"]
        for code in sorted(owasp):
            st.caption(
                f"**{code}** — {_vuln_label_for_owasp(code)} "
                f"&middot; {owasp[code]} finding(s)"
            )

    # ── UPLOAD HISTORY — visible to every tier ─────────────────────
    _render_upload_history_table(uploads)

    # ── Locked premium pitch ───────────────────────────────────────
    st.markdown(
        '<div class="rx-section-eyebrow" style="margin-top:24px;">'
        "PREMIUM ANALYTICS — LOCKED</div>",
        unsafe_allow_html=True,
    )
    _render_locked_feature(
        "Full scan history, trends, exports",
        "Upgrade to Security Engineer to unlock the full scan history "
        "table, security-score and fix-rate trend charts, top "
        "vulnerabilities across every scan, and PDF / CSV report "
        "exports.",
        key_suffix="-analytics",
    )


def _render_analytics_premium(
    history: list[dict[str, Any]],
    uploads: list[dict[str, Any]],
) -> None:
    """Premium-tier view: always-on Activity Overview + uploads + charts.

    Brand-new premium / admin users get the same Activity Overview
    skeleton (with zeros) as basic users instead of a top-level "no
    data" placeholder that hid the dashboard chrome. The chart
    sections fall back to an inline placeholder when no completed
    scans exist, so the layout is consistent whether the user has
    zero scans or fifty.
    """
    completed = _completed_history(history)

    # ── ACTIVITY OVERVIEW — same widget the basic tier sees ────────
    _render_activity_overview(history, uploads)

    # ── UPLOAD HISTORY — premium gets the full list (50 instead of 10)
    _render_upload_history_table(uploads, limit=50)

    if not completed:
        # Render the chart-section header so the page has a complete
        # skeleton, then fall back to a single inline message in
        # place of the charts themselves.
        st.markdown(
            '<div class="rx-section-eyebrow" style="margin-top:18px;">'
            "TRENDS &amp; CHARTS</div>",
            unsafe_allow_html=True,
        )
        _render_empty_charts_placeholder()
        return

    # Build common index (oldest → newest) for time-series charts.
    sorted_completed = sorted(
        completed, key=lambda h: str(h.get("created_at", ""))
    )
    avg_fix_rate = (
        sum(float(h.get("fix_rate", 0)) for h in completed) / len(completed)
    )

    # ── Section — Average fix rate (single headline number) ────────
    st.markdown(
        '<div class="rx-section-eyebrow" style="margin-top:18px;">'
        "AVERAGE FIX RATE (ALL COMPLETED SCANS)</div>",
        unsafe_allow_html=True,
    )
    st.metric("Average fix rate", f"{avg_fix_rate:.1f}%")

    # ── Section — Security score trend ─────────────────────────────
    st.markdown(
        '<div class="rx-section-eyebrow" style="margin-top:18px;">'
        "SECURITY SCORE TREND</div>",
        unsafe_allow_html=True,
    )
    score_data = {
        str(h.get("created_at", ""))[:16]: float(h.get("security_score", 0))
        for h in sorted_completed
    }
    if score_data:
        st.line_chart(score_data, height=240, color="#00d4ff")
        latest_score = list(score_data.values())[-1]
        _render_score_badge(latest_score)
    else:
        st.caption("Not enough completed scans to draw a trend.")

    # ── Section 3 — Threats by OWASP category ────────────────────────
    st.markdown(
        '<div class="rx-section-eyebrow" style="margin-top:18px;">'
        "THREATS BY OWASP CATEGORY</div>",
        unsafe_allow_html=True,
    )
    owasp_totals: dict[str, int] = {}
    for h in completed:
        owasp_counts = h.get("owasp_counts") or {}
        if hasattr(owasp_counts, "items"):
            for code, count in owasp_counts.items():
                owasp_totals[str(code)] = owasp_totals.get(str(code), 0) + int(count)
    if owasp_totals:
        st.bar_chart(owasp_totals, height=240, color="#ff4444")
    else:
        st.caption("No OWASP breakdown recorded for these scans.")

    # ── Section 4 — Fix rate trend ───────────────────────────────────
    st.markdown(
        '<div class="rx-section-eyebrow" style="margin-top:18px;">'
        "FIX RATE TREND</div>",
        unsafe_allow_html=True,
    )
    fix_data = {
        str(h.get("created_at", ""))[:16]: float(h.get("fix_rate", 0))
        for h in sorted_completed
    }
    if fix_data:
        st.area_chart(fix_data, height=240, color="#00ff88")
    else:
        st.caption("Not enough completed scans to draw fix-rate trend.")

    # ── Section 5 — Recent scans table ───────────────────────────────
    st.markdown(
        '<div class="rx-section-eyebrow" style="margin-top:18px;">'
        "RECENT SCANS (LAST 10)</div>",
        unsafe_allow_html=True,
    )
    recent = completed[:10]
    if recent:
        table_rows = [
            {
                "Date / time": str(h.get("created_at", ""))[:16],
                "Source": h.get("source", "?"),
                "Findings": int(h.get("total_findings", 0)),
                "Fixed": int(h.get("approved_count", 0)),
                "Skipped": int(h.get("skipped_count", 0)),
                "Fix rate %": float(h.get("fix_rate", 0)),
                "Score": float(h.get("security_score", 0)),
            }
            for h in recent
        ]
        st.dataframe(table_rows, use_container_width=True, hide_index=True)
    else:
        st.caption("No completed scans yet.")

    # ── Section 6 — Top vulnerabilities ──────────────────────────────
    st.markdown(
        '<div class="rx-section-eyebrow" style="margin-top:18px;">'
        "TOP VULNERABILITIES</div>",
        unsafe_allow_html=True,
    )
    if owasp_totals:
        ranked = sorted(owasp_totals.items(), key=lambda kv: kv[1], reverse=True)
        for i, (code, count) in enumerate(ranked[:10], 1):
            st.markdown(
                f"**{i}.** `{code}` &mdash; {_vuln_label_for_owasp(code)} "
                f"&middot; found **{count}** time(s)"
            )
    else:
        st.caption("No vulnerabilities recorded.")

    # ── Section 7 — Export reports ───────────────────────────────────
    st.markdown(
        '<div class="rx-section-eyebrow" style="margin-top:18px;">'
        "EXPORT REPORTS</div>",
        unsafe_allow_html=True,
    )
    csv_data = _build_owasp_csv(completed).encode("utf-8")
    exp_col1, exp_col2 = st.columns(2)
    if exp_col1.button(
        "📕 Download PDF report",
        use_container_width=True,
        key="analytics-pdf",
    ):
        st.toast(
            "📕 PDF export is rolling out in v1.1 — CSV is available now."
        )
    exp_col2.download_button(
        "📄 Download CSV data",
        data=csv_data,
        file_name="remediax_analytics.csv",
        mime="text/csv",
        use_container_width=True,
        key="analytics-csv",
    )


def render_analytics() -> None:
    """SECURITY OPERATIONS ANALYTICS dashboard."""
    st.markdown(
        '<div class="remediax-hero"><h1>📊 SECURITY OPERATIONS ANALYTICS</h1>'
        '<div class="tagline">Monitor your LLM security posture '
        "over time</div></div>",
        unsafe_allow_html=True,
    )

    history = _load_history()
    uploads = _load_uploads()
    if st.session_state.get("is_admin") or _has_premium():
        _render_analytics_premium(history, uploads)
    else:
        _render_analytics_basic(history, uploads)


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

    # Initialize Firebase Admin if credentials are present in
    # st.secrets. Idempotent — only the first successful call connects.
    # When secrets are missing the helper logs and returns False so the
    # UI can show a "Firebase not configured" notice instead of crashing.
    try:
        init_firebase(st.secrets)
    except Exception as exc:  # pragma: no cover - defensive boundary
        logger.warning("Firebase init raised unexpectedly: %s", exc)

    # First, ensure the admin token exists if the deploy provided it
    # via st.secrets. This MUST run before any auth check so a fresh
    # Streamlit Cloud instance has a usable admin login on first boot.
    _bootstrap_admin_token_from_secrets()

    initialize_state()

    # Best-effort auto-login from the ``?t=`` URL parameter. No-ops
    # when the user is already authenticated, no token is remembered,
    # or we have already tried this session.
    _attempt_auto_login()

    # Then try the Firebase URL remember-me (?e=, ?uid=, ?tier=).
    # Same URL-leakage profile as the admin ?t= flow above; see
    # docstring on _attempt_firebase_url_auto_login for the security
    # tradeoffs.
    _attempt_firebase_url_auto_login()

    # Only authenticated users (Firebase or admin token) can reach the
    # app. Everyone else is forced onto the access screen.
    if not st.session_state.authenticated:
        st.session_state.screen = "access"
    elif not st.session_state.get("is_admin") and st.session_state.screen == "admin":
        # Non-admin Firebase users cannot reach the admin panel.
        st.session_state.screen = "landing"

    # URL screen-persistence (?p=) for authenticated users.
    if st.session_state.authenticated:
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
    elif screen == "scanner":
        render_scanner()
    elif screen == "analytics":
        render_analytics()
    elif screen == "admin":
        render_admin_panel()
    else:  # pragma: no cover - defensive
        st.session_state.screen = "landing"
        st.rerun()


main()
