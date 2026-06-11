"""ECharts-powered threat landscape donut and security posture trend charts."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import streamlit as st

from components.owasp_content import OWASP_CONTENT
from components.security_score import calculate_security_score


def _load_findings() -> list[dict[str, Any]]:
    p = Path("artifacts/findings.json")
    if not p.exists():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def render_threat_donut(findings: list[Any] | None = None) -> None:
    """Render OWASP category distribution as an Apache ECharts donut chart."""
    try:
        from streamlit_echarts import st_echarts
    except ImportError:
        st.info("Install streamlit-echarts for interactive charts.")
        return

    raw = findings if findings is not None else (
        st.session_state.get("findings") or _load_findings()
    )

    # Count findings per OWASP category
    cat_counts: dict[str, int] = {}
    for f in raw:
        cat = f.get("owasp_llm_category") if isinstance(f, dict) else getattr(f, "owasp_llm_category", None)
        if cat:
            cat_counts[cat] = cat_counts.get(cat, 0) + 1

    if not cat_counts:
        st.caption("No threat data. Run a scan to populate this chart.")
        return

    # Build chart data using OWASP_CONTENT colors
    data = []
    for cat, count in sorted(cat_counts.items()):
        info = OWASP_CONTENT.get(cat, {})
        color = info.get("color", "#94A3B8")
        name_str = info.get("name", cat)
        # Shorten label
        label = f"{cat}: {name_str[:18]}{'…' if len(name_str) > 18 else ''}"
        data.append({"value": count, "name": label, "itemStyle": {"color": color}})

    option = {
        "backgroundColor": "transparent",
        "tooltip": {
            "trigger": "item",
            "formatter": "{b}<br/>Findings: <b>{c}</b> ({d}%)",
            "backgroundColor": "#0D1520",
            "borderColor": "rgba(139,92,246,0.3)",
            "textStyle": {"color": "#F9FAFB", "fontSize": 12},
        },
        "legend": {
            "orient": "vertical",
            "right": "2%",
            "top": "center",
            "textStyle": {"color": "#94A3B8", "fontSize": 10},
            "itemWidth": 10,
            "itemHeight": 10,
        },
        "series": [
            {
                "type": "pie",
                "radius": ["42%", "68%"],
                "center": ["38%", "50%"],
                "avoidLabelOverlap": False,
                "label": {"show": False},
                "emphasis": {
                    "label": {
                        "show": True,
                        "fontSize": 13,
                        "fontWeight": "bold",
                        "color": "#F9FAFB",
                    }
                },
                "labelLine": {"show": False},
                "data": data,
            }
        ],
    }
    st_echarts(options=option, height="260px", key="threat_donut")


def render_posture_trend(findings: list[Any] | None = None) -> None:
    """Render security posture trend as a line chart.

    Uses Firebase scan history if available; falls back to a single data point
    from the current findings.
    """
    try:
        from streamlit_echarts import st_echarts
    except ImportError:
        st.info("Install streamlit-echarts for interactive charts.")
        return

    # Try to get scan history from Firebase
    scan_scores: list[tuple[str, int]] = []
    uid = st.session_state.get("user_uid")
    if uid:
        try:
            from database import get_user_scans
            scans = get_user_scans(uid, limit=10)
            for scan in reversed(scans):
                ts = str(scan.get("created_at", ""))[:10]
                flist = scan.get("findings", [])
                if flist and isinstance(flist, list):
                    score = calculate_security_score(flist)
                    scan_scores.append((ts, score))
        except Exception:
            pass

    # Fall back to current findings if no history
    if not scan_scores:
        raw = findings if findings is not None else (
            st.session_state.get("findings") or _load_findings()
        )
        score = calculate_security_score(raw) if raw else 0
        scan_scores = [("Scan 1", score)]

    dates = [s[0] for s in scan_scores]
    scores = [s[1] for s in scan_scores]

    option = {
        "backgroundColor": "transparent",
        "tooltip": {
            "trigger": "axis",
            "backgroundColor": "#0D1520",
            "borderColor": "rgba(139,92,246,0.3)",
            "textStyle": {"color": "#F9FAFB", "fontSize": 12},
            "formatter": "{b}<br/>Score: <b>{c}%</b>",
        },
        "grid": {"left": "8%", "right": "4%", "top": "14%", "bottom": "18%"},
        "xAxis": {
            "type": "category",
            "data": dates,
            "axisLabel": {"color": "#94A3B8", "fontSize": 10},
            "axisLine": {"lineStyle": {"color": "#1A2744"}},
            "axisTick": {"show": False},
        },
        "yAxis": {
            "type": "value",
            "min": 0,
            "max": 100,
            "axisLabel": {
                "color": "#94A3B8",
                "fontSize": 10,
                "formatter": "{value}%",
            },
            "splitLine": {"lineStyle": {"color": "#1A2744", "type": "dashed"}},
        },
        "series": [
            {
                "type": "line",
                "data": scores,
                "smooth": True,
                "symbol": "circle",
                "symbolSize": 7,
                "lineStyle": {"color": "#8B5CF6", "width": 2.5},
                "itemStyle": {"color": "#8B5CF6", "borderColor": "#F9FAFB", "borderWidth": 2},
                "areaStyle": {
                    "color": {
                        "type": "linear",
                        "x": 0, "y": 0, "x2": 0, "y2": 1,
                        "colorStops": [
                            {"offset": 0, "color": "rgba(139,92,246,0.35)"},
                            {"offset": 1, "color": "rgba(139,92,246,0.02)"},
                        ],
                    }
                },
            }
        ],
    }
    st_echarts(options=option, height="220px", key="posture_trend")
