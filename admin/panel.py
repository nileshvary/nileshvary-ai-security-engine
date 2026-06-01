"""Admin dashboard: active/expired token tables, generator form, usage stats.

Gated on ``session_manager.is_admin()`` — non-admin sessions get redirected
to the landing screen with a warning.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from auth.rate_limiter import USAGE_FILE
from auth.session_manager import is_admin
from auth.token_manager import TokenManager


_DURATION_LABELS = ("2h", "24h", "48h", "7d", "permanent")
_DURATION_HOURS: dict[str, int] = {"2h": 2, "24h": 24, "48h": 48, "7d": 168}


def _is_expired(record: dict[str, Any]) -> bool:
    if record.get("permanent"):
        return False
    expires = record.get("expires")
    if not expires:
        return False
    try:
        return datetime.utcnow() > datetime.fromisoformat(expires)
    except ValueError:
        return False


def _format_dt(value: str | None) -> str:
    if not value:
        return "—"
    try:
        return datetime.fromisoformat(value).strftime("%Y-%m-%d %H:%M UTC")
    except ValueError:
        return value


def _read_usage(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def render_admin_panel(token_manager: TokenManager | None = None) -> None:
    """Render the four-section admin dashboard."""
    import streamlit as st

    if not is_admin():
        st.warning("Admin token required. Returning to landing.")
        st.session_state.screen = "landing"
        st.rerun()

    tm = token_manager or TokenManager()
    st.title("👤 Admin Panel")
    st.caption("Manage RemediAX access tokens and review usage.")

    all_tokens = tm.get_all_tokens()
    active = {tid: r for tid, r in all_tokens.items() if not r["revoked"] and not _is_expired(r)}
    revoked = {tid: r for tid, r in all_tokens.items() if r["revoked"]}
    expired = {tid: r for tid, r in all_tokens.items() if not r["revoked"] and _is_expired(r)}

    st.subheader("Active tokens")
    if not active:
        st.caption("No active tokens.")
    else:
        for tid, record in active.items():
            cols = st.columns([2, 2, 2, 2, 1, 1])
            cols[0].markdown(f"`{tid}`")
            cols[1].write(record.get("for") or "—")
            cols[2].write(_format_dt(record.get("created")))
            cols[3].write(
                "permanent" if record.get("permanent") else _format_dt(record.get("expires"))
            )
            cols[4].write(record.get("uses", 0))
            if cols[5].button("Revoke", key=f"revoke-{tid}"):
                tm.revoke_token(tid)
                st.rerun()

    st.subheader("Expired tokens")
    if not expired:
        st.caption("No expired tokens.")
    else:
        for tid, record in expired.items():
            cols = st.columns([2, 2, 2, 1, 1])
            cols[0].markdown(f"`{tid}`")
            cols[1].write(record.get("for") or "—")
            cols[2].write(_format_dt(record.get("expires")))
            cols[3].write(record.get("uses", 0))
            if cols[4].button("Delete", key=f"delete-{tid}"):
                tm.delete_token(tid)
                st.rerun()

    if revoked:
        st.subheader("Revoked tokens")
        for tid, record in revoked.items():
            cols = st.columns([2, 2, 2, 1, 1])
            cols[0].markdown(f"`{tid}`")
            cols[1].write(record.get("for") or "—")
            cols[2].write(_format_dt(record.get("created")))
            cols[3].write(record.get("uses", 0))
            if cols[4].button("Delete", key=f"delete-rev-{tid}"):
                tm.delete_token(tid)
                st.rerun()

    st.subheader("Generate new token")
    with st.form("generate-token-form"):
        for_person = st.text_input("For")
        duration = st.radio(
            "Duration", _DURATION_LABELS, horizontal=True, index=2
        )
        submitted = st.form_submit_button("🔑 Generate token")
    if submitted:
        permanent = duration == "permanent"
        hours = _DURATION_HOURS.get(duration, 48)
        raw_token = tm.generate_token(
            duration_hours=hours,
            for_person=for_person,
            permanent=permanent,
        )
        st.success(
            "Token generated. Copy it now — it will not be shown again."
        )
        st.code(raw_token, language=None)

    st.subheader("Usage stats")
    total = len(all_tokens)
    today_key = datetime.utcnow().strftime("%Y-%m-%d")
    usage = _read_usage(USAGE_FILE)
    scans_today = sum(int(v) for v in usage.get(today_key, {}).values())
    cols = st.columns(4)
    cols[0].metric("Total tokens", total)
    cols[1].metric("Active", len(active))
    cols[2].metric("Expired", len(expired))
    cols[3].metric("Scans today", scans_today)

    if st.button("← Back to landing"):
        st.session_state.screen = "landing"
        st.rerun()
