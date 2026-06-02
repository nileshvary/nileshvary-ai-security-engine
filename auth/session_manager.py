"""Streamlit session-state helpers shared across screens.

Streamlit imports are local so the rest of the ``auth`` package stays
testable without the Streamlit runtime.
"""

from __future__ import annotations

from typing import Any


_DEFAULTS: dict[str, Any] = {
    "screen": "access",
    "authenticated": False,
    # Firebase user identity (set after email/password login or signup).
    "user_uid": None,
    "user_email": None,
    "user_name": None,
    "user_tier": None,
    # Admin token branch still uses these — preserved for the existing
    # ``?t=RMX-...`` flow.
    "token_record": {},
    "findings": [],
    "remediation_results": [],
    "verification_report": None,
    "current_index": 0,
    "approved": [],
    "skipped": [],
    "api_key": None,
    "api_mode": False,
    "tts_enabled": False,
    "voice_enabled": False,
    "output_dir": None,
    "final_report": None,
    "ai_client": None,
}


def initialize_state() -> None:
    """Populate any missing session-state keys with their defaults."""
    import streamlit as st  # local import: keep auth tests Streamlit-free

    for key, value in _DEFAULTS.items():
        if key not in st.session_state:
            # Each call gets a fresh copy of mutable defaults.
            st.session_state[key] = value.copy() if isinstance(value, (list, dict)) else value


def is_admin() -> bool:
    """True when the active token is marked permanent."""
    import streamlit as st

    record = st.session_state.get("token_record") or {}
    return bool(record.get("permanent"))


def reset_to_landing() -> None:
    """Clear pipeline state and return to the landing screen."""
    import streamlit as st

    for key in (
        "findings",
        "remediation_results",
        "verification_report",
        "current_index",
        "approved",
        "skipped",
        "output_dir",
        "final_report",
    ):
        if key in st.session_state:
            default = _DEFAULTS[key]
            st.session_state[key] = (
                default.copy() if isinstance(default, (list, dict)) else default
            )
    st.session_state.screen = "landing"


def logout() -> None:
    """Wipe authentication state and return to the access screen."""
    import streamlit as st

    for key in list(st.session_state.keys()):
        del st.session_state[key]
    initialize_state()
