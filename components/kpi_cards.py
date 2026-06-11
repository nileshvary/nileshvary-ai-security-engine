"""KPI metric cards for the RemediAX enterprise dashboard."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import streamlit as st

from components.security_score import calculate_security_score


def _load_findings() -> list[dict[str, Any]]:
    """Load findings from artifacts/findings.json; return empty list on any error."""
    p = Path("artifacts/findings.json")
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def _load_remediation() -> list[dict[str, Any]]:
    p = Path("artifacts/remediation_results.json")
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            return data.get("results", [])
        return []
    except Exception:
        return []


def render_kpi_cards() -> None:
    """Render 5 KPI metric cards across one row at the top of the dashboard."""
    findings = st.session_state.get("findings") or _load_findings()
    remediation = st.session_state.get("remediation_results") or _load_remediation()

    total = len(findings)
    critical_high = sum(
        1 for f in findings
        if (f.get("severity") if isinstance(f, dict) else getattr(f, "severity", "")) in ("CRITICAL", "HIGH")
        and (f.get("is_successful_attack") if isinstance(f, dict) else getattr(f, "is_successful_attack", False))
    )
    responded = len(remediation)
    data_analyzed = sum(
        len(f.get("attack_prompt", "") if isinstance(f, dict) else getattr(f, "attack_prompt", ""))
        for f in findings
    )
    data_kb = round(data_analyzed / 1024, 1) if data_analyzed > 0 else 0

    score = calculate_security_score(findings) if findings else 0

    cards = [
        {
            "label": "Security Posture",
            "value": f"{score}%",
            "trend": "Baseline scan",
            "trend_class": "neutral",
            "color": "#8B5CF6",
        },
        {
            "label": "Threats Detected",
            "value": str(total),
            "trend": f"{critical_high} critical/high",
            "trend_class": "down" if critical_high > 0 else "neutral",
            "color": "#EF4444",
        },
        {
            "label": "Active Assets",
            "value": "1",
            "trend": "Target scanned",
            "trend_class": "neutral",
            "color": "#06B6D4",
        },
        {
            "label": "Data Analyzed",
            "value": f"{data_kb} KB" if data_kb > 0 else f"{data_analyzed} B",
            "trend": f"{total} attack prompts",
            "trend_class": "neutral",
            "color": "#3B82F6",
        },
        {
            "label": "Incidents Responded",
            "value": str(responded),
            "trend": f"{responded}/{total} remediated" if total > 0 else "No scan yet",
            "trend_class": "up" if responded > 0 else "neutral",
            "color": "#10B981",
        },
    ]

    cols = st.columns(5)
    for col, card in zip(cols, cards):
        with col:
            st.markdown(
                f"""<div class="rx-kpi-card" style="--kpi-color:{card['color']};">
  <div class="rx-kpi-value">{card['value']}</div>
  <div class="rx-kpi-label">{card['label']}</div>
  <div class="rx-kpi-trend {card['trend_class']}">{card['trend']}</div>
</div>""",
                unsafe_allow_html=True,
            )
