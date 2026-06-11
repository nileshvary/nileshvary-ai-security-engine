"""Recent security alerts feed for the RemediAX dashboard."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import streamlit as st


def _load_findings() -> list[dict[str, Any]]:
    p = Path("artifacts/findings.json")
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


_SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def render_alert_feed(findings: list[Any] | None = None, max_alerts: int = 8) -> None:
    """Render a scrollable recent-alerts feed from scan findings.

    Args:
        findings: List of Finding objects or dicts. Falls back to artifacts/findings.json.
        max_alerts: Maximum number of alerts to display.
    """
    raw = findings if findings is not None else (
        st.session_state.get("findings") or _load_findings()
    )

    if not raw:
        st.markdown(
            '<div style="color:#94A3B8;font-size:0.82rem;padding:12px 0;">'
            "No alerts yet. Run a scan to populate this feed.</div>",
            unsafe_allow_html=True,
        )
        return

    # Sort: successful attacks first, then by severity
    def _sort_key(f: Any) -> tuple[int, int]:
        sev = f.get("severity") if isinstance(f, dict) else getattr(f, "severity", "LOW")
        success = f.get("is_successful_attack") if isinstance(f, dict) else getattr(f, "is_successful_attack", False)
        return (0 if success else 1, _SEV_ORDER.get((sev or "LOW").upper(), 3))

    sorted_findings = sorted(raw, key=_sort_key)[:max_alerts]

    items_html = ""
    for f in sorted_findings:
        sev = (f.get("severity") if isinstance(f, dict) else getattr(f, "severity", "LOW") or "LOW").upper()
        probe = f.get("probe_name") if isinstance(f, dict) else getattr(f, "probe_name", "Unknown probe")
        cat = f.get("owasp_llm_category") if isinstance(f, dict) else getattr(f, "owasp_llm_category", "")
        success = f.get("is_successful_attack") if isinstance(f, dict) else getattr(f, "is_successful_attack", False)

        dot_class = sev.lower() if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "low"
        badge_class = sev.lower()
        probe_short = (probe or "Unknown")[:55]
        if len(probe or "") > 55:
            probe_short += "…"

        status_icon = "⚠️" if success else "✓"
        meta = f"{cat} · {status_icon} {'Attack succeeded' if success else 'Blocked'}"

        items_html += f"""
<div class="rx-alert-item">
  <div class="rx-alert-dot {dot_class}"></div>
  <div>
    <div class="rx-alert-probe">{probe_short}</div>
    <div class="rx-alert-meta">
      {meta}
      <span class="rx-severity-badge {badge_class}" style="margin-left:6px;">{sev}</span>
    </div>
  </div>
</div>"""

    st.markdown(
        f'<div style="max-height:300px;overflow-y:auto;">{items_html}</div>',
        unsafe_allow_html=True,
    )
