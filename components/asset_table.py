"""Top attacked assets panel with progress bars for the RemediAX dashboard."""

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


_CAT_COLORS = {
    "LLM01": "#EF4444",
    "LLM02": "#F97316",
    "LLM03": "#EAB308",
    "LLM04": "#10B981",
    "LLM05": "#3B82F6",
    "LLM06": "#8B5CF6",
    "LLM07": "#EC4899",
    "LLM08": "#06B6D4",
    "LLM09": "#A78BFA",
    "LLM10": "#34D399",
}


def render_asset_table(findings: list[Any] | None = None, top_n: int = 6) -> None:
    """Render top attacked OWASP categories as horizontal progress bars.

    Args:
        findings: List of Finding objects or dicts.
        top_n: Number of categories to display.
    """
    raw = findings if findings is not None else (
        st.session_state.get("findings") or _load_findings()
    )

    if not raw:
        st.markdown(
            '<div style="color:#94A3B8;font-size:0.82rem;padding:12px 0;">'
            "No attack data yet. Run a scan to see top targeted categories.</div>",
            unsafe_allow_html=True,
        )
        return

    # Count by OWASP category (successful attacks only for "attacked" metric)
    cat_total: dict[str, int] = {}
    cat_hits: dict[str, int] = {}
    for f in raw:
        cat = (f.get("owasp_llm_category") if isinstance(f, dict) else getattr(f, "owasp_llm_category", None)) or "Unknown"
        success = f.get("is_successful_attack") if isinstance(f, dict) else getattr(f, "is_successful_attack", False)
        cat_total[cat] = cat_total.get(cat, 0) + 1
        if success:
            cat_hits[cat] = cat_hits.get(cat, 0) + 1

    # Sort by total probes, descending
    sorted_cats = sorted(cat_total.items(), key=lambda x: x[1], reverse=True)[:top_n]
    max_count = max(c for _, c in sorted_cats) if sorted_cats else 1

    rows_html = ""
    for cat, total_count in sorted_cats:
        hits = cat_hits.get(cat, 0)
        pct = round(total_count / max_count * 100)
        color = _CAT_COLORS.get(cat, "#94A3B8")

        # Vulnerability name (short)
        from components.owasp_content import OWASP_CONTENT
        name = OWASP_CONTENT.get(cat, {}).get("name", cat)
        name_short = name[:22] + "…" if len(name) > 22 else name

        rows_html += f"""
<div class="rx-asset-row">
  <div class="rx-asset-label">
    <span class="rx-asset-name">{cat}: {name_short}</span>
    <span class="rx-asset-count">{total_count} probes · <span style="color:{color};">{hits} hits</span></span>
  </div>
  <div class="rx-progress-bar">
    <div class="rx-progress-fill" style="width:{pct}%;background:{color};"></div>
  </div>
</div>"""

    st.markdown(rows_html, unsafe_allow_html=True)
