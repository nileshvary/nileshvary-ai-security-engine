"""Live network traffic animation using GSAP loaded from CDN.

Renders an animated SVG showing packets flowing from Internet → Firewall →
App Server → Data Center, colored by threat severity.
"""

from __future__ import annotations

import json
from typing import Any

import streamlit as st
import streamlit.components.v1 as components


def render_network_animation(
    findings: list[Any] | None = None,
    height: int = 340,
) -> None:
    """Render an animated network topology diagram in an iframe.

    Args:
        findings: Optional list of Finding objects or dicts for threat coloring.
        height: Pixel height of the component iframe.
    """
    # Build threat summary from findings
    critical = high = medium = low = 0
    if findings:
        for f in findings:
            sev = f.get("severity") if isinstance(f, dict) else getattr(f, "severity", "LOW")
            sev = (sev or "LOW").upper()
            if sev == "CRITICAL":
                critical += 1
            elif sev == "HIGH":
                high += 1
            elif sev == "MEDIUM":
                medium += 1
            else:
                low += 1

    total = critical + high + medium + low
    threat_color = (
        "#EF4444" if critical > 0
        else "#F97316" if high > 0
        else "#EAB308" if medium > 0
        else "#10B981"
    )
    threat_label = (
        f"{critical} Critical" if critical > 0
        else f"{high} High" if high > 0
        else f"{medium} Medium" if medium > 0
        else "Clean"
    )

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
* {{ margin:0; padding:0; box-sizing:border-box; }}
body {{
  background: #0A0F1E;
  font-family: system-ui, sans-serif;
  overflow: hidden;
  display: flex;
  flex-direction: column;
  align-items: center;
  padding: 16px;
}}
.title {{
  font-size: 0.68rem;
  font-weight: 700;
  color: #94A3B8;
  letter-spacing: 0.12em;
  text-transform: uppercase;
  margin-bottom: 14px;
  display: flex; align-items: center; gap: 6px;
}}
.live-dot {{
  width: 7px; height: 7px; border-radius: 50%;
  background: #EF4444;
  animation: pulse-red 1.5s infinite;
}}
@keyframes pulse-red {{
  0%,100% {{ box-shadow: 0 0 0 0 rgba(239,68,68,0.6); }}
  50%      {{ box-shadow: 0 0 0 6px rgba(239,68,68,0); }}
}}
svg {{ width: 100%; max-width: 620px; }}
.node-label {{
  font-size: 10px;
  fill: #94A3B8;
  text-anchor: middle;
  font-family: system-ui, sans-serif;
}}
.node-title {{
  font-size: 11px;
  fill: #F9FAFB;
  text-anchor: middle;
  font-weight: 600;
  font-family: system-ui, sans-serif;
}}
.stat-bar {{
  display: flex; justify-content: center; gap: 20px;
  margin-top: 14px; flex-wrap: wrap;
}}
.stat {{ text-align: center; }}
.stat-v {{ font-size: 1.1rem; font-weight: 800; }}
.stat-l {{ font-size: 0.62rem; color: #94A3B8; letter-spacing: 0.05em; text-transform: uppercase; }}
</style>
</head>
<body>
<div class="title"><div class="live-dot"></div> Live Network Traffic</div>
<svg viewBox="0 0 620 260" id="net-svg">
  <defs>
    <filter id="glow-purple">
      <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
      <feMerge><feMergeNode in="coloredBlur"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
    <filter id="glow-red">
      <feGaussianBlur stdDeviation="4" result="coloredBlur"/>
      <feMerge><feMergeNode in="coloredBlur"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
    <filter id="glow-green">
      <feGaussianBlur stdDeviation="3" result="coloredBlur"/>
      <feMerge><feMergeNode in="coloredBlur"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>
    <marker id="arrow" markerWidth="6" markerHeight="6" refX="3" refY="3" orient="auto">
      <path d="M0,0 L6,3 L0,6 Z" fill="#1A2744"/>
    </marker>
  </defs>

  <!-- Connection lines -->
  <line x1="120" y1="130" x2="215" y2="130" stroke="#1A2744" stroke-width="1.5" marker-end="url(#arrow)"/>
  <line x1="275" y1="130" x2="345" y2="130" stroke="#1A2744" stroke-width="1.5" marker-end="url(#arrow)"/>
  <line x1="405" y1="130" x2="478" y2="130" stroke="#1A2744" stroke-width="1.5" marker-end="url(#arrow)"/>
  <!-- Branch lines down -->
  <line x1="245" y1="155" x2="245" y2="200" stroke="#1A2744" stroke-width="1" stroke-dasharray="3,3"/>
  <line x1="375" y1="155" x2="375" y2="200" stroke="#1A2744" stroke-width="1" stroke-dasharray="3,3"/>

  <!-- Internet node -->
  <circle cx="90" cy="130" r="38" fill="#0D1520" stroke="#3B82F6" stroke-width="1.5" filter="url(#glow-purple)"/>
  <text x="90" y="125" class="node-title">🌐</text>
  <text x="90" y="140" class="node-label">Internet</text>
  <text x="90" y="153" class="node-label" fill="#3B82F6" style="font-size:9px;">{total} probes</text>

  <!-- Firewall node -->
  <circle cx="245" cy="130" r="38" fill="#0D1520" stroke="{threat_color}" stroke-width="1.5" filter="url(#glow-red)"/>
  <text x="245" y="125" class="node-title">🔥</text>
  <text x="245" y="140" class="node-label">Firewall</text>
  <text x="245" y="153" class="node-label" fill="{threat_color}" style="font-size:9px;">{threat_label}</text>

  <!-- App Server node -->
  <circle cx="375" cy="130" r="38" fill="#0D1520" stroke="#8B5CF6" stroke-width="1.5" filter="url(#glow-purple)"/>
  <text x="375" y="125" class="node-title">⚡</text>
  <text x="375" y="140" class="node-label">AI Model</text>
  <text x="375" y="153" class="node-label" fill="#8B5CF6" style="font-size:9px;">LLM Target</text>

  <!-- Data Center node -->
  <circle cx="510" cy="130" r="38" fill="#0D1520" stroke="#10B981" stroke-width="1.5" filter="url(#glow-green)"/>
  <text x="510" y="125" class="node-title">🗄️</text>
  <text x="510" y="140" class="node-label">RemediAX</text>
  <text x="510" y="153" class="node-label" fill="#10B981" style="font-size:9px;">Protected</text>

  <!-- Threat sub-nodes -->
  <rect x="205" y="200" width="80" height="26" rx="5" fill="#1A0A0A" stroke="#EF4444" stroke-width="1"/>
  <text x="245" y="217" class="node-label" fill="#EF4444">Threats: {critical + high}</text>

  <rect x="335" y="200" width="80" height="26" rx="5" fill="#0A1A13" stroke="#10B981" stroke-width="1"/>
  <text x="375" y="217" class="node-label" fill="#10B981">Guardrails Active</text>

  <!-- Animated packets: Internet → Firewall -->
  <circle class="pkt pkt-threat" r="5" fill="{threat_color}" filter="url(#glow-red)" opacity="0"/>
  <circle class="pkt pkt-threat2" r="4" fill="{threat_color}" opacity="0"/>
  <circle class="pkt pkt-normal" r="4" fill="#3B82F6" opacity="0"/>

  <!-- Animated packets: Firewall → App Server -->
  <circle class="pkt pkt-fw" r="4" fill="#8B5CF6" filter="url(#glow-purple)" opacity="0"/>
  <circle class="pkt pkt-fw2" r="3" fill="#8B5CF6" opacity="0"/>

  <!-- Animated packets: App Server → Data Center -->
  <circle class="pkt pkt-srv" r="4" fill="#10B981" filter="url(#glow-green)" opacity="0"/>
</svg>

<div class="stat-bar">
  <div class="stat">
    <div class="stat-v" style="color:#EF4444;">{critical}</div>
    <div class="stat-l">Critical</div>
  </div>
  <div class="stat">
    <div class="stat-v" style="color:#F97316;">{high}</div>
    <div class="stat-l">High</div>
  </div>
  <div class="stat">
    <div class="stat-v" style="color:#EAB308;">{medium}</div>
    <div class="stat-l">Medium</div>
  </div>
  <div class="stat">
    <div class="stat-v" style="color:#10B981;">{low}</div>
    <div class="stat-l">Low</div>
  </div>
</div>

<script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.5/gsap.min.js"
  crossorigin="anonymous" referrerpolicy="no-referrer"></script>
<script src="https://cdnjs.cloudflare.com/ajax/libs/gsap/3.12.5/MotionPathPlugin.min.js"
  crossorigin="anonymous" referrerpolicy="no-referrer"></script>
<script>
(function() {{
  // Wait for GSAP to load then start animations
  function initAnimations() {{
    if (typeof gsap === 'undefined') {{
      setTimeout(initAnimations, 200);
      return;
    }}
    gsap.registerPlugin(MotionPathPlugin);

    // Internet → Firewall: threat packets
    function animPkt(sel, x1, y1, x2, y2, color, delay, dur) {{
      var el = document.querySelector(sel);
      if (!el) return;
      gsap.set(el, {{attr: {{cx: x1, cy: y1}}, opacity: 0}});
      gsap.timeline({{repeat: -1, delay: delay}})
        .to(el, {{opacity: 1, duration: 0.15}})
        .to(el, {{
          attr: {{cx: x2, cy: y2}},
          duration: dur,
          ease: "power1.inOut"
        }})
        .to(el, {{opacity: 0, duration: 0.15}})
        .set(el, {{attr: {{cx: x1, cy: y1}}}});
    }}

    // Threat packets: Internet(90,130) → Firewall(245,130)
    animPkt('.pkt-threat',  90, 130, 245, 130, '{threat_color}', 0,    1.4);
    animPkt('.pkt-threat2', 90, 130, 245, 130, '{threat_color}', 0.6,  1.4);
    animPkt('.pkt-normal',  90, 130, 245, 130, '#3B82F6',        1.1,  1.2);

    // Filtered packets: Firewall(245,130) → AI Model(375,130)
    animPkt('.pkt-fw',  245, 130, 375, 130, '#8B5CF6', 0.3, 1.2);
    animPkt('.pkt-fw2', 245, 130, 375, 130, '#8B5CF6', 0.9, 1.2);

    // Clean packets: AI Model(375,130) → RemediAX(510,130)
    animPkt('.pkt-srv', 375, 130, 510, 130, '#10B981', 0.5, 1.1);

    // Pulse rings on nodes
    function pulseNode(cx, cy, color) {{
      var ring = document.createElementNS('http://www.w3.org/2000/svg','circle');
      ring.setAttribute('cx', cx); ring.setAttribute('cy', cy);
      ring.setAttribute('r', '38'); ring.setAttribute('fill', 'none');
      ring.setAttribute('stroke', color); ring.setAttribute('stroke-width', '1.5');
      ring.setAttribute('opacity', '0.6');
      document.getElementById('net-svg').appendChild(ring);
      gsap.to(ring, {{
        attr: {{r: 54}}, opacity: 0, duration: 2,
        repeat: -1, delay: Math.random() * 2, ease: "power2.out"
      }});
    }}
    pulseNode(245, 130, '{threat_color}');
    pulseNode(375, 130, '#8B5CF6');
    pulseNode(510, 130, '#10B981');
  }}
  initAnimations();
}})();
</script>
</body>
</html>"""

    components.html(html, height=height, scrolling=False)
