"""Render the RemediAX v2.0 interactive architecture diagram.

The diagram is a pure HTML/CSS recreation of the architecture flow image.
Navigation is handled by Streamlit buttons below the diagram (not JS links)
so session state is never disrupted.
"""

from __future__ import annotations

import streamlit as st

# ---------------------------------------------------------------------------
# Colours matching the architecture diagram
# ---------------------------------------------------------------------------
_C = {
    "orchestrator": "#4c1d95",
    "orchestrator_border": "#7c3aed",
    "scanner": "#064e3b",
    "scanner_border": "#059669",
    "remediator": "#451a03",
    "remediator_border": "#b45309",
    "reporter": "#1e3a5f",
    "reporter_border": "#2563eb",
    "verifier": "#450a0a",
    "verifier_border": "#dc2626",
    "cve": "#0f172a",
    "cve_border": "#4b5563",
    "normalize": "#1e3a5f",
    "normalize_border": "#3b82f6",
    "artifact": "#1a1a2e",
    "artifact_border": "#334155",
    "user": "#1e293b",
    "user_border": "#475569",
    "bg": "#0a0e1a",
    "label": "#f59e0b",
    "output": "#fcd34d",
    "text": "#e2e8f0",
    "muted": "#94a3b8",
    "dim": "#6b7280",
}

# ---------------------------------------------------------------------------
# HTML/CSS diagram
# ---------------------------------------------------------------------------
_CSS = f"""
<style>
.rax-diag {{
  background: linear-gradient(180deg, {_C['bg']} 0%, #0d1420 100%);
  border-radius: 16px;
  padding: 24px 20px 18px;
  font-family: 'Segoe UI', Arial, sans-serif;
  color: {_C['text']};
  user-select: none;
  border: 1px solid #1e293b;
}}
.rax-diag * {{ box-sizing: border-box; margin: 0; padding: 0; }}
.rax-diag-title {{ text-align: center; margin-bottom: 18px; }}
.rax-diag-title h3 {{
  font-size: 1.05rem; font-weight: 700; color: #f8fafc; letter-spacing: 0.02em;
}}
.rax-diag-title p {{
  font-size: 0.7rem; color: {_C['muted']}; margin-top: 3px;
}}
.rax-row {{ display: flex; justify-content: center; align-items: stretch; gap: 12px; }}
/* Agent boxes */
.rax-agent {{
  border-radius: 10px; padding: 12px 14px; text-align: center;
  border-width: 1px; border-style: solid;
}}
.rax-agent .ag-title {{ font-size: 0.85rem; font-weight: 700; margin-bottom: 3px; }}
.rax-agent .ag-sub   {{ font-size: 0.68rem; opacity: 0.85; margin-bottom: 6px; }}
.rax-agent ul {{ list-style: none; text-align: left; }}
.rax-agent ul li {{ font-size: 0.67rem; padding: 1px 0; opacity: 0.85; }}
.rax-agent .ag-out {{
  display: inline-block; margin-top: 8px; font-size: 0.67rem; font-weight: 700;
  color: {_C['output']}; background: rgba(0,0,0,0.35);
  padding: 2px 8px; border-radius: 4px;
}}
/* Box variant colours */
.ag-orch  {{ background: {_C['orchestrator']}; border-color: {_C['orchestrator_border']}; }}
.ag-scan  {{ background: {_C['scanner']};      border-color: {_C['scanner_border']};      flex: 1; }}
.ag-remed {{ background: {_C['remediator']};   border-color: {_C['remediator_border']};   flex: 1; }}
.ag-rep   {{ background: {_C['reporter']};     border-color: {_C['reporter_border']};     flex: 1; }}
.ag-ver   {{ background: {_C['verifier']};     border-color: {_C['verifier_border']};     flex: 1; }}
.ag-cve   {{ background: {_C['cve']};          border-color: {_C['cve_border']};
             border-style: dashed; width: 100%; }}
/* User box */
.rax-user {{
  background: {_C['user']}; border: 1px solid {_C['user_border']};
  border-radius: 8px; padding: 7px 22px; font-size: 0.78rem;
  text-align: center;
}}
/* Normalize bar */
.rax-norm {{
  background: {_C['normalize']}; border: 1px solid {_C['normalize_border']};
  border-radius: 6px; padding: 9px 12px; text-align: center;
  font-size: 0.75rem; width: 100%; font-weight: 600;
}}
/* Artifact boxes */
.rax-art {{
  background: {_C['artifact']}; border: 1px solid {_C['artifact_border']};
  border-radius: 6px; padding: 9px 8px; text-align: center; flex: 1;
}}
.rax-art .art-name {{ font-size: 0.73rem; font-weight: 700; color: {_C['output']}; }}
.rax-art .art-desc {{ font-size: 0.63rem; color: {_C['muted']}; margin-top: 2px; }}
/* Connectors */
.rax-down {{
  display: flex; justify-content: center; align-items: center;
  color: {_C['dim']}; font-size: 0.95rem; padding: 3px 0; line-height: 1;
}}
.rax-split-arrows {{
  display: flex; justify-content: space-around; padding: 2px 80px;
  color: {_C['dim']}; font-size: 0.9rem;
}}
.rax-mid-arrow {{
  display: flex; align-items: center; justify-content: center;
  flex-direction: column; min-width: 56px;
}}
.rax-arrow-lbl {{
  font-size: 0.62rem; color: {_C['label']}; background: #1a1a2e;
  padding: 2px 7px; border-radius: 10px; border: 1px solid {_C['label']};
  white-space: nowrap;
}}
.rax-dashed-wrap {{
  border: 1px dashed #374151; border-radius: 10px; padding: 10px; margin: 2px 0;
}}
/* Legend */
.rax-legend {{
  display: flex; justify-content: center; gap: 14px;
  margin-top: 12px; flex-wrap: wrap;
}}
.leg-item {{
  display: flex; align-items: center; gap: 5px;
  font-size: 0.66rem; color: {_C['muted']};
}}
.leg-dot {{
  width: 11px; height: 11px; border-radius: 3px; display: inline-block; flex-shrink: 0;
}}
</style>
"""

_BODY = f"""
<div class="rax-diag">

  <!-- Title -->
  <div class="rax-diag-title">
    <h3>RemediAX v2.0 — Architecture Flow Diagram</h3>
    <p>How the 6-Agent Pipeline Works: Find → Fix → Verify → Report → Stay Current</p>
  </div>

  <!-- User/Developer -->
  <div class="rax-row">
    <div class="rax-user">
      👤 <strong>User / Developer</strong><br>
      <span style="font-size:0.67rem;color:{_C['muted']};">remediax scan --target &lt;URL&gt;</span>
    </div>
  </div>
  <div class="rax-down">↓</div>

  <!-- Orchestrator -->
  <div class="rax-row">
    <div class="rax-agent ag-orch" style="width:320px;">
      <div class="ag-title">Agent 5 — Orchestrator</div>
      <div class="ag-sub">Claude API · coordinates all agents · reads findings · decides sequence</div>
    </div>
  </div>
  <div class="rax-split-arrows"><span>↙</span><span>↘</span></div>

  <!-- Scanner + Remediator -->
  <div class="rax-dashed-wrap">
    <div class="rax-row" style="align-items:flex-start;">
      <div class="rax-agent ag-scan">
        <div class="ag-title">Agent 1 — Scanner</div>
        <div class="ag-sub">Garak (NVIDIA) + PyRIT (Microsoft)</div>
        <ul>
          <li>Single-turn: 50+ probe scans</li>
          <li>Multi-turn: Crescendo attacks</li>
          <li>Maps to OWASP LLM Top 10</li>
        </ul>
        <span class="ag-out">Output: findings.json</span>
      </div>

      <div class="rax-mid-arrow">
        <span class="rax-arrow-lbl">findings.json</span>
        <span style="color:{_C['dim']};font-size:1.1rem;margin-top:4px;">→</span>
      </div>

      <div class="rax-agent ag-remed">
        <div class="ag-title">Agent 2 — Remediator</div>
        <div class="ag-sub">LLM Guard + NeMo + Claude API</div>
        <ul>
          <li>LLM Guard: input/output scanners</li>
          <li>NeMo: Colang dialog rails</li>
          <li>Claude API: smart mapping</li>
        </ul>
        <span class="ag-out">Output: guardrails.yaml</span>
      </div>
    </div>
  </div>

  <!-- Normalize -->
  <div class="rax-down">↓</div>
  <div class="rax-row">
    <div class="rax-norm">
      Normalize — map all results to OWASP LLM Top 10 unified schema
    </div>
  </div>
  <div class="rax-down">↓</div>

  <!-- Reporter + Verifier -->
  <div class="rax-dashed-wrap">
    <div class="rax-row" style="align-items:flex-start;">
      <div class="rax-agent ag-rep">
        <div class="ag-title">Agent 3 — Reporter</div>
        <div class="ag-sub">Claude API + Jinja2</div>
        <ul>
          <li>Unique context per finding</li>
          <li>Before / after benchmark</li>
          <li>Professional HTML report</li>
        </ul>
        <span class="ag-out">Output: summary.html</span>
      </div>

      <div class="rax-mid-arrow">
        <span class="rax-arrow-lbl">summary.html</span>
        <span style="color:{_C['dim']};font-size:1.1rem;margin-top:4px;">→</span>
      </div>

      <div class="rax-agent ag-ver">
        <div class="ag-title">Agent 4 — Verifier</div>
        <div class="ag-sub">Promptfoo + Garak re-scan</div>
        <ul>
          <li>Auto-generates regression tests</li>
          <li>Runs in GitHub Actions CI</li>
          <li>Fails PR on regression</li>
        </ul>
        <span class="ag-out">Output: benchmark.json</span>
      </div>
    </div>
  </div>

  <!-- Artifacts row -->
  <div class="rax-down">↓</div>
  <div class="rax-row" style="gap:8px;">
    <div class="rax-art"><div class="art-name">findings.json</div><div class="art-desc">All attack results</div></div>
    <div class="rax-art"><div class="art-name">guardrails.yaml</div><div class="art-desc">Auto-gen defenses</div></div>
    <div class="rax-art"><div class="art-name">summary.html</div><div class="art-desc">HTML report</div></div>
    <div class="rax-art"><div class="art-name">benchmark.json</div><div class="art-desc">Before/after stats</div></div>
  </div>
  <div style="text-align:center;font-size:0.63rem;color:{_C['dim']};margin:5px 0 0;">
    All artifacts committed to GitHub · auto-deployed to remediax.streamlit.app
  </div>

  <!-- Nightly arrow to CVE Watcher -->
  <div class="rax-down" style="font-size:0.72rem;color:{_C['dim']};flex-direction:column;gap:1px;">
    <span style="font-size:0.62rem;">nightly</span>
    <span>↓</span>
  </div>

  <!-- CVE Watcher -->
  <div class="rax-row">
    <div class="rax-agent ag-cve" style="padding:12px 16px;">
      <div class="ag-title" style="color:#f8fafc;">Agent 6 — CVE Watcher · Auto-Update Engine</div>
      <div style="font-size:0.68rem;color:{_C['muted']};margin:4px 0;">
        Sources: NVD API (NIST) · MITRE ATLAS · OWASP Updates · Garak probes · GitHub Advisories
      </div>
      <div style="font-size:0.67rem;color:{_C['muted']};">
        New CVE → Claude API analyzes → generates probe → tests target → updates guardrails → alerts
      </div>
      <div style="font-size:0.7rem;font-weight:700;color:#4ade80;margin-top:6px;">
        Fully automated · RemediAX never becomes outdated
      </div>
    </div>
  </div>

  <!-- Legend -->
  <div class="rax-legend">
    <div class="leg-item"><span class="leg-dot" style="background:{_C['orchestrator_border']};"></span>Orchestrator</div>
    <div class="leg-item"><span class="leg-dot" style="background:{_C['scanner_border']};"></span>Scan</div>
    <div class="leg-item"><span class="leg-dot" style="background:{_C['remediator_border']};"></span>Remediate</div>
    <div class="leg-item"><span class="leg-dot" style="background:{_C['reporter_border']};"></span>Report</div>
    <div class="leg-item"><span class="leg-dot" style="background:{_C['verifier_border']};"></span>Verify</div>
    <div class="leg-item"><span class="leg-dot" style="background:{_C['cve_border']};"></span>Auto-Update</div>
  </div>

</div>
"""

_DIAGRAM_HTML: str = _CSS + _BODY


def render_pipeline_diagram() -> None:
    """Render the static v2.0 architecture diagram as HTML/CSS."""
    st.markdown(_DIAGRAM_HTML, unsafe_allow_html=True)


# Agent metadata for the navigation buttons rendered BELOW the diagram
AGENT_NAV: list[dict] = [
    {
        "label": "1️⃣ Scanner",
        "screen": "scanner",
        "tools": "Garak + PyRIT",
        "output": "findings.json",
        "color": _C["scanner_border"],
        "key": "nav-agent1",
    },
    {
        "label": "2️⃣ Remediator",
        "screen": "pipeline_v2",
        "tools": "LLM Guard + NeMo",
        "output": "guardrails.yaml",
        "color": _C["remediator_border"],
        "key": "nav-agent2",
    },
    {
        "label": "3️⃣ Reporter",
        "screen": "results",
        "tools": "Claude + Jinja2",
        "output": "summary.html",
        "color": _C["reporter_border"],
        "key": "nav-agent3",
    },
    {
        "label": "4️⃣ Verifier",
        "screen": "pipeline_v2",
        "tools": "Promptfoo + Garak",
        "output": "benchmark.json",
        "color": _C["verifier_border"],
        "key": "nav-agent4",
    },
    {
        "label": "5️⃣ Orchestrator",
        "screen": "pipeline_v2",
        "tools": "All agents",
        "output": "pipeline_summary.json",
        "color": _C["orchestrator_border"],
        "key": "nav-agent5",
    },
    {
        "label": "6️⃣ CVE Watcher",
        "screen": "pipeline_v2",
        "tools": "NVD API (NIST)",
        "output": "cve_database.json",
        "color": "#4b5563",
        "key": "nav-agent6",
    },
]


def render_agent_nav_buttons() -> None:
    """Render the six clickable agent navigation cards below the diagram."""
    st.markdown(
        '<p style="text-align:center;font-size:0.78rem;color:#94a3b8;margin:12px 0 8px;">'
        "Click an agent to navigate ↓</p>",
        unsafe_allow_html=True,
    )

    cols = st.columns(6)
    for col, agent in zip(cols, AGENT_NAV):
        color = agent["color"]
        with col:
            st.markdown(
                f'<div style="border:1px solid {color};border-radius:8px;'
                f'padding:8px 6px;text-align:center;background:rgba(0,0,0,0.25);'
                f'margin-bottom:4px;">'
                f'<div style="font-size:0.72rem;font-weight:700;color:{color};">'
                f'{agent["label"]}</div>'
                f'<div style="font-size:0.63rem;color:#94a3b8;margin:2px 0;">'
                f'{agent["tools"]}</div>'
                f'<div style="font-size:0.6rem;color:#fcd34d;">'
                f'{agent["output"]}</div>'
                f"</div>",
                unsafe_allow_html=True,
            )
            if st.button("Open →", key=agent["key"], use_container_width=True):
                st.session_state.screen = agent["screen"]
                st.rerun()
