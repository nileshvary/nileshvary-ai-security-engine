"""Renderers for the per-finding review screen.

Two layouts:

- ``render_active_finding`` — for the six runtime-remediable categories
  (LLM01, 02, 05, 06, 07, 10). Two columns: vulnerability vs remediation.
- ``render_escalation_finding`` — for the four out-of-band categories
  (LLM03, 04, 08, 09). Full-width amber banner plus an external-tools
  panel; no patched-prompt or sanitized-response section because no
  runtime fix exists.

Both layouts read colors / icons / pre-written text from
``components.owasp_content.OWASP_CONTENT`` so each OWASP category gets
its own visual identity automatically.
"""

from __future__ import annotations

import html

from integration_bridge.models import Finding
from remediation_engine.models import RemediationResult
from verifier.models import VerificationResult

from components.ai_client import RemediAXAI
from components.owasp_content import get as owasp_get
from components.owasp_content import (
    get_asi,
    get_tool_url,
    is_escalation,
    split_tool_entry,
)


_STRATEGY_COLORS: dict[str, str] = {
    "harden": "#00d4ff",
    "sanitize": "#00ff88",
    "guardrail": "#0080ff",
    "log_only": "#8b949e",
    "block": "#ff4444",
}
_STRATEGY_TEXT_COLORS: dict[str, str] = {
    "harden": "#000000",
    "sanitize": "#000000",
    "guardrail": "#ffffff",
    "log_only": "#ffffff",
    "block": "#ffffff",
}

_SEVERITY_COLORS: dict[str, tuple[str, str]] = {
    "CRITICAL": ("#ff4444", "#ffffff"),
    "HIGH": ("#ff6600", "#ffffff"),
    "MEDIUM": ("#ffaa00", "#000000"),
    "LOW": ("#0080ff", "#ffffff"),
}

_STATUS_COLORS: dict[str, str] = {
    "VERIFIED": "#00ff88",
    "PARTIAL": "#ffaa00",
    "FAILED": "#ff4444",
    "UNVERIFIABLE": "#8b949e",
}


def _badge(text: str, bg: str, fg: str = "#000000") -> str:
    safe = html.escape(text, quote=True)
    return (
        f'<span style="display:inline-block;padding:3px 10px;'
        f'border-radius:999px;font-size:0.8rem;font-weight:600;'
        f'background:{bg};color:{fg};margin-right:6px;">{safe}</span>'
    )


def _severity_badge(severity: str) -> str:
    bg, fg = _SEVERITY_COLORS.get(severity, ("#8b949e", "#ffffff"))
    return _badge(severity, bg, fg)


def _strategy_badge(strategy: str) -> str:
    key = strategy.lower()
    return _badge(
        strategy.upper(),
        _STRATEGY_COLORS.get(key, "#8b949e"),
        _STRATEGY_TEXT_COLORS.get(key, "#ffffff"),
    )


def _status_badge(status: str) -> str:
    return _badge(status, _STATUS_COLORS.get(status, "#8b949e"), "#000000")


def _category_header(
    content: dict,
    severity: str,
    strategy: str,
    agentic_codes: list[str] | None = None,
) -> str:
    color = content["color"]
    icon = content["icon"]
    name = html.escape(content["name"], quote=True)
    asi_row = _agentic_badges_row(agentic_codes or [])
    return (
        f'<div style="background:{color}22;border-left:6px solid {color};'
        f'padding:14px 18px;border-radius:6px;margin-bottom:12px;">'
        f'<div style="font-size:1.25rem;font-weight:700;color:{color};">'
        f'{icon} {name}</div>'
        f'<div style="margin-top:6px;">{_severity_badge(severity)}'
        f'{_strategy_badge(strategy)}</div>'
        f'{asi_row}'
        f"</div>"
    )


def _agentic_badge(code: str, name: str, color: str) -> str:
    """Render a single OWASP Agentic Top 10 chip (code + name, colored)."""
    safe_code = html.escape(code, quote=True)
    safe_name = html.escape(name, quote=True)
    return (
        f'<span style="display:inline-flex;align-items:center;'
        f"padding:3px 10px;border-radius:999px;font-size:0.78rem;"
        f"font-weight:600;border:1px solid {color};"
        f'color:{color};background:{color}11;margin:4px 6px 0 0;">'
        f"{safe_code} &middot; {safe_name}</span>"
    )


def _agentic_badges_row(codes: list[str]) -> str:
    """Render the row of ASI chips shown under the LLM category header.

    Returns the empty string when there are no agentic cross-mappings
    for this finding, so the existing layout is unchanged for the
    common LLM-only case.
    """
    if not codes:
        return ""
    chips: list[str] = []
    for code in codes:
        entry = get_asi(code)
        if entry is None:
            # Unknown ASI code — render as a neutral chip rather
            # than dropping so the operator can spot bad data.
            chips.append(_agentic_badge(code, "Unknown ASI category", "#8b949e"))
            continue
        chips.append(_agentic_badge(code, entry["name"], entry["color"]))
    return (
        '<div style="margin-top:8px;display:flex;flex-wrap:wrap;'
        'align-items:center;gap:0;font-size:0.78rem;">'
        '<span style="color:#8b949e;text-transform:uppercase;'
        'letter-spacing:0.06em;margin-right:8px;">Agentic Top 10:</span>'
        + "".join(chips)
        + "</div>"
    )


def _card_block(title: str, body_html: str, border_color: str = "#1e3a5f") -> str:
    return (
        f'<div style="background:#0d1117;border:1px solid {border_color};'
        f'border-radius:8px;padding:16px 18px;margin:10px 0;">'
        f'<div style="font-size:0.85rem;color:#8b949e;'
        f'text-transform:uppercase;letter-spacing:0.06em;'
        f'margin-bottom:8px;">{html.escape(title, quote=True)}</div>'
        f'<div style="color:#e6edf3;">{body_html}</div>'
        f"</div>"
    )


def _ai_card(label: str, body: str, accent: str) -> str:
    return (
        f'<div style="background:#0d1117;border:1px solid {accent};'
        f'border-radius:8px;padding:18px 20px;margin:14px 0;'
        f'box-shadow:0 0 15px {accent}40;">'
        f'<div style="font-size:0.8rem;letter-spacing:0.08em;'
        f'text-transform:uppercase;color:{accent};'
        f'margin-bottom:8px;">{html.escape(label, quote=True)}</div>'
        f'<div style="color:#e6edf3;line-height:1.55;">'
        f'{html.escape(body, quote=True).replace(chr(10), "<br>")}</div>'
        f"</div>"
    )


def _success_rate_bar(rate: float | None) -> str:
    pct = max(0.0, min(1.0, rate or 0.0)) * 100
    return (
        '<div style="background:#1e3a5f;border-radius:6px;height:10px;'
        'overflow:hidden;margin-top:6px;">'
        f'<div style="background:linear-gradient(90deg,#ff6600,#ff4444);'
        f'height:100%;width:{pct:.1f}%;"></div>'
        "</div>"
        f'<div style="color:#8b949e;font-size:0.8rem;margin-top:4px;">'
        f"Estimated attack success rate: {pct:.0f}%</div>"
    )


def _techniques_list(techniques: list[str]) -> str:
    if not techniques:
        return '<div style="color:#8b949e;font-style:italic;">No techniques recorded.</div>'
    items = "".join(
        f'<li style="margin:4px 0;color:#e6edf3;">'
        f'<span style="color:#00ff88;">✓</span> '
        f'<code style="background:#161b22;padding:2px 6px;border-radius:4px;'
        f'color:#00d4ff;">{html.escape(t, quote=True)}</code></li>'
        for t in techniques
    )
    return f'<ul style="list-style:none;padding-left:0;margin:0;">{items}</ul>'


def _tools_list(tools: list[str]) -> str:
    if not tools:
        return ""
    items = "".join(
        f'<div style="background:#161b22;border:1px solid #1e3a5f;'
        f'border-radius:6px;padding:10px 12px;margin:8px 0;color:#e6edf3;">'
        f'🔧 {html.escape(tool, quote=True)}</div>'
        for tool in tools
    )
    return items


def _truncate(text: str, limit: int = 400) -> str:
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + "..."


def render_active_finding(
    finding: Finding,
    remediation_result: RemediationResult,
    verification_result: VerificationResult | None,
    ai_client: RemediAXAI | None,
) -> None:
    """Render the two-column active-remediation layout."""
    import streamlit as st

    content = owasp_get(finding.owasp_llm_category)
    st.markdown(
        _category_header(
            content,
            finding.severity,
            str(remediation_result.strategy),
            agentic_codes=finding.owasp_agentic_categories,
        ),
        unsafe_allow_html=True,
    )

    left, right = st.columns(2)

    with left:
        st.markdown("#### The Vulnerability")
        st.markdown(
            _card_block(
                "Probe",
                f'<code style="color:#00d4ff;">{html.escape(finding.probe_name, quote=True)}</code>',
            ),
            unsafe_allow_html=True,
        )
        st.markdown(
            _card_block(
                "Attack prompt",
                html.escape(_truncate(finding.attack_prompt), quote=True),
                border_color="#ff4444",
            ),
            unsafe_allow_html=True,
        )
        st.markdown(
            _card_block(
                "Model response",
                html.escape(_truncate(finding.model_response), quote=True),
                border_color="#ffaa00",
            ),
            unsafe_allow_html=True,
        )
        if verification_result is not None:
            st.markdown(
                _success_rate_bar(verification_result.before_success_rate),
                unsafe_allow_html=True,
            )

    with right:
        st.markdown("#### The Remediation")
        strategy_label = (
            f"{content['strategy_icon']} {str(remediation_result.strategy).upper()}"
        )
        st.markdown(
            _card_block("Strategy", html.escape(strategy_label, quote=True)),
            unsafe_allow_html=True,
        )

        patch = remediation_result.prompt_patch
        if patch is not None:
            st.markdown(
                _card_block(
                    "Techniques applied",
                    _techniques_list(patch.injection_resistance_techniques),
                ),
                unsafe_allow_html=True,
            )

        san = remediation_result.response_sanitization
        if san is not None and (san.detected_issues or san.actions_taken):
            issues_html = "".join(
                f'<div style="color:#e6edf3;">• {html.escape(i, quote=True)}</div>'
                for i in san.detected_issues
            )
            actions_html = "".join(
                f'<div style="color:#00ff88;">→ {html.escape(a, quote=True)}</div>'
                for a in san.actions_taken
            )
            st.markdown(
                _card_block(
                    "Sanitization",
                    f'<div style="margin-bottom:8px;">{issues_html}</div>'
                    f"{actions_html}",
                ),
                unsafe_allow_html=True,
            )

        config = remediation_result.guardrail_config
        if config is not None and (config.input_filters or config.output_filters or config.rate_limits):
            preview_lines: list[str] = []
            for rule in config.input_filters[:2]:
                preview_lines.append(f"input: {rule.get('id', '?')}")
            for rule in config.output_filters[:2]:
                preview_lines.append(f"output: {rule.get('id', '?')}")
            for key, value in list(config.rate_limits.items())[:2]:
                preview_lines.append(f"limit: {key}={value}")
            if preview_lines:
                preview_html = "<br>".join(
                    html.escape(line, quote=True) for line in preview_lines
                )
                st.markdown(
                    _card_block(
                        "Guardrail preview",
                        f'<code style="color:#00d4ff;">{preview_html}</code>',
                    ),
                    unsafe_allow_html=True,
                )

    # Wide AI explanation blocks.
    # ``finding`` is passed to BOTH AI calls so Claude has the actual
    # attack context. For ``explain_fix`` this is what stops Claude
    # asking clarifying questions on LOG_ONLY findings — without the
    # finding the prompt has nothing concrete to anchor to.
    danger_text = (
        ai_client.explain_finding(finding) if ai_client is not None else None
    ) or content["danger_explanation"]
    fix_text = (
        ai_client.explain_fix(remediation_result, finding=finding)
        if ai_client is not None
        else None
    ) or content["fix_explanation"]

    st.markdown(
        _ai_card("Why this is dangerous", danger_text, "#00d4ff"),
        unsafe_allow_html=True,
    )
    st.markdown(
        _ai_card("Why this fix works", fix_text, "#0080ff"),
        unsafe_allow_html=True,
    )

    if verification_result is not None:
        st.markdown(
            f'<div style="margin-top:8px;">{_status_badge(verification_result.verification_status)}'
            f'<span style="color:#8b949e;font-size:0.85rem;">Verifier confidence: '
            f'{verification_result.confidence:.0%}</span></div>',
            unsafe_allow_html=True,
        )


def render_escalation_finding(
    finding: Finding,
    remediation_result: RemediationResult,
    verification_result: VerificationResult | None,
) -> None:
    """Render the full-width amber escalation layout."""
    import streamlit as st

    content = owasp_get(finding.owasp_llm_category)
    st.markdown(
        _category_header(
            content,
            finding.severity,
            str(remediation_result.strategy),
            agentic_codes=finding.owasp_agentic_categories,
        ),
        unsafe_allow_html=True,
    )

    escalation_note = content.get("escalation_note") or (
        "This finding cannot be remediated at runtime."
    )
    st.markdown(
        f'<div style="background:#ffaa0022;border-left:6px solid #ffaa00;'
        f"padding:18px 22px;border-radius:6px;margin-bottom:14px;\">"
        f'<div style="font-size:1.05rem;font-weight:700;color:#ffaa00;'
        f"margin-bottom:6px;\">⚠️ ESCALATION REQUIRED</div>"
        f'<div style="color:#e6edf3;">{html.escape(escalation_note, quote=True)}</div>'
        "</div>",
        unsafe_allow_html=True,
    )

    left, right = st.columns(2)

    with left:
        st.markdown("#### The Vulnerability")
        st.markdown(
            _card_block(
                "Probe",
                f'<code style="color:#ffaa00;">{html.escape(finding.probe_name, quote=True)}</code>',
                border_color="#ffaa00",
            ),
            unsafe_allow_html=True,
        )
        st.markdown(
            _card_block(
                "Attack prompt",
                html.escape(_truncate(finding.attack_prompt), quote=True),
                border_color="#ffaa00",
            ),
            unsafe_allow_html=True,
        )
        st.markdown(
            _card_block(
                "Model response",
                html.escape(_truncate(finding.model_response), quote=True),
                border_color="#ffcc00",
            ),
            unsafe_allow_html=True,
        )

    with right:
        st.markdown("#### Recommended External Tools")
        tools = content.get("external_tools") or []
        if tools:
            st.markdown(_tools_list(tools), unsafe_allow_html=True)
        else:
            st.markdown(
                '<div style="color:#8b949e;font-style:italic;">'
                "No external tool recommendations recorded.</div>",
                unsafe_allow_html=True,
            )

        if remediation_result.notes:
            note_html = "<br>".join(
                html.escape(n, quote=True) for n in remediation_result.notes
            )
            st.markdown(
                _card_block(
                    "Engine notes",
                    f'<div style="color:#e6edf3;">{note_html}</div>',
                    border_color="#1e3a5f",
                ),
                unsafe_allow_html=True,
            )

    st.markdown(
        _ai_card(
            "Why this is dangerous",
            content["danger_explanation"],
            "#ffaa00",
        ),
        unsafe_allow_html=True,
    )
    st.markdown(
        _ai_card(
            "Why runtime fix isn't enough",
            content["fix_explanation"],
            "#ffcc00",
        ),
        unsafe_allow_html=True,
    )

    if verification_result is not None:
        st.markdown(
            f'<div style="margin-top:8px;">{_status_badge(verification_result.verification_status)}'
            f'<span style="color:#8b949e;font-size:0.85rem;">'
            "Runtime verification not applicable.</span></div>",
            unsafe_allow_html=True,
        )


def render_finding(
    finding: Finding,
    remediation_result: RemediationResult,
    verification_result: VerificationResult | None,
    ai_client: RemediAXAI | None,
) -> None:
    """Dispatch to the right layout based on OWASP category."""
    if is_escalation(finding.owasp_llm_category):
        render_escalation_finding(finding, remediation_result, verification_result)
    else:
        render_active_finding(
            finding, remediation_result, verification_result, ai_client
        )


def render_listen_widget(finding: Finding, idx: int, total: int) -> None:
    """Embed a 🔊 Listen button that reads the pre-written finding script.

    The button is fully client-side (Web Speech API) — clicking it
    triggers ``speechSynthesis.speak`` with the script built by
    ``components.voice.build_finding_speech``. Content comes from
    ``OWASP_CONTENT``, so the same text is read in Basic mode AND
    Enhanced mode and there is no API call, no cost, no latency.

    Caller is expected to gate the call on
    ``st.session_state.tts_enabled`` — if the user has disabled TTS
    we don't render the widget at all.
    """
    import streamlit as st

    from components.voice import (
        build_finding_speech,
        escape_for_speech,
        get_voice_js,
    )

    script = escape_for_speech(build_finding_speech(finding, idx, total))
    st.components.v1.html(
        get_voice_js(script, manual_listen_button=True),
        height=55,
    )


# ---------------------------------------------------------------------------
# "View" panel renderers (triggered by the third action button in the review
# screen). Both deliberately render clean structured content rather than the
# raw JSON dump that lived here previously.
# ---------------------------------------------------------------------------


def _tool_card(name: str, description: str, url: str | None) -> str:
    """Render one tool as a card with name, description, and (optional) link."""
    safe_name = html.escape(name, quote=True)
    safe_desc = html.escape(description, quote=True) if description else ""
    link_html = ""
    if url:
        safe_url = html.escape(url, quote=True)
        link_html = (
            f'<div style="margin-top:8px;">'
            f'<a href="{safe_url}" target="_blank" rel="noopener noreferrer" '
            f'style="color:#00d4ff;text-decoration:none;'
            f'border:1px solid #00d4ff;border-radius:4px;'
            f'padding:3px 10px;font-size:0.8rem;">🔗 Visit website</a>'
            f"</div>"
        )
    desc_html = (
        f'<div style="color:#8b949e;margin-top:4px;font-size:0.9rem;">{safe_desc}</div>'
        if safe_desc
        else ""
    )
    return (
        f'<div style="background:#161b22;border:1px solid #1e3a5f;'
        f'border-radius:8px;padding:14px 16px;margin:8px 0;">'
        f'<div style="color:#e6edf3;font-weight:600;font-size:1rem;">🔧 {safe_name}</div>'
        f"{desc_html}{link_html}"
        "</div>"
    )


def render_tools_panel(
    finding: Finding,
    remediation_result: RemediationResult,
) -> None:
    """Render the escalation "View tools" panel.

    Shows one card per recommended external tool (with optional clickable
    link) followed by the engine notes attached to the finding. Does NOT
    show the raw finding payload — that lives in the Raw Data expander
    at the bottom of the review screen.
    """
    import streamlit as st

    content = owasp_get(finding.owasp_llm_category)
    tools = content.get("external_tools") or []

    st.markdown(
        '<div style="background:#0d1117;border:1px solid #00d4ff;'
        'border-radius:8px;padding:18px 20px;margin:14px 0;'
        'box-shadow:0 0 15px rgba(0,212,255,0.2);">'
        '<div style="color:#00d4ff;font-size:0.8rem;letter-spacing:0.08em;'
        'text-transform:uppercase;margin-bottom:10px;">'
        "🔗 Recommended external tools</div>"
        "</div>",
        unsafe_allow_html=True,
    )

    if not tools:
        st.info("No external tool recommendations were recorded for this finding.")
    else:
        cards_html = "".join(
            _tool_card(*split_tool_entry(entry), get_tool_url(split_tool_entry(entry)[0]))
            for entry in tools
        )
        st.markdown(cards_html, unsafe_allow_html=True)

    notes = remediation_result.notes or []
    if notes:
        st.markdown(
            '<div style="color:#8b949e;font-size:0.8rem;letter-spacing:0.08em;'
            'text-transform:uppercase;margin:18px 0 6px;">📝 Engine notes</div>',
            unsafe_allow_html=True,
        )
        notes_html = "".join(
            f'<div style="background:#0d1117;border-left:3px solid #ffaa00;'
            f'padding:8px 12px;margin:6px 0;color:#e6edf3;font-size:0.9rem;">'
            f"{html.escape(note, quote=True)}</div>"
            for note in notes
        )
        st.markdown(notes_html, unsafe_allow_html=True)


def render_patch_panel(remediation_result: RemediationResult) -> None:
    """Render the active-finding "View patch" panel.

    Shows the full patched prompt and, when present, the guardrail YAML
    preview. Does NOT show the raw finding payload.
    """
    import streamlit as st

    patch = remediation_result.prompt_patch
    if patch is not None:
        st.markdown(
            '<div style="color:#00d4ff;font-size:0.8rem;letter-spacing:0.08em;'
            'text-transform:uppercase;margin:14px 0 6px;">🛡️ Patched system prompt</div>',
            unsafe_allow_html=True,
        )
        st.code(patch.patched_prompt, language="text")

    san = remediation_result.response_sanitization
    if san is not None and (san.detected_issues or san.actions_taken):
        st.markdown(
            '<div style="color:#00ff88;font-size:0.8rem;letter-spacing:0.08em;'
            'text-transform:uppercase;margin:14px 0 6px;">🧹 Sanitization details</div>',
            unsafe_allow_html=True,
        )
        if san.original_response != san.sanitized_response:
            st.markdown("**Before:**")
            st.code(san.original_response, language="text")
            st.markdown("**After:**")
            st.code(san.sanitized_response, language="text")

    config = remediation_result.guardrail_config
    if config is not None and config.yaml_export:
        st.markdown(
            '<div style="color:#0080ff;font-size:0.8rem;letter-spacing:0.08em;'
            'text-transform:uppercase;margin:14px 0 6px;">⚡ Guardrail config</div>',
            unsafe_allow_html=True,
        )
        # Cap at ~1200 chars so a verbose YAML doesn't overrun the page.
        snippet = config.yaml_export[:1200]
        if len(config.yaml_export) > 1200:
            snippet += "\n# ... (truncated; see Raw Data expander for full export)"
        st.code(snippet, language="yaml")

    if patch is None and san is None and (config is None or not config.yaml_export):
        st.info(
            "No additional remediation artifact to display. See Raw Data "
            "below for the underlying finding payload."
        )
