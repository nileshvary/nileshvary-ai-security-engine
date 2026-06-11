"""AI Security Assistant chat panel for the RemediAX dashboard.

Wraps the existing RemediAXAI client (components/ai_client.py).
Falls back to rule-based answers when no API key is configured.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import streamlit as st

# ---------------------------------------------------------------------------
# Rule-based fallback answers (no API key needed)
# ---------------------------------------------------------------------------

_QUICK_ANSWERS: dict[str, str] = {
    "what is llm01": "LLM01 — Prompt Injection. Attackers craft inputs that override the model's original instructions, causing it to ignore safety guidelines or leak sensitive data.",
    "llm01": "LLM01 — Prompt Injection. Attackers craft inputs that override the model's original instructions, causing it to ignore safety guidelines or leak sensitive data.",
    "what is llm07": "LLM07 — System Prompt Leakage. The model reveals its confidential system prompt, exposing business logic, secrets, or instructions intended to be hidden.",
    "llm07": "LLM07 — System Prompt Leakage. The model reveals its confidential system prompt, exposing business logic, secrets, or instructions intended to be hidden.",
    "what is remediax": "RemediAX is a free open-source AI security platform. It scans LLM applications for vulnerabilities, auto-generates guardrails to fix them, and verifies fixes via CI pipeline — covering all 20 OWASP LLM + ASI categories.",
    "how does remediax work": "RemediAX runs a 6-agent pipeline: (1) Scanner uses Garak probes, (2) Remediator generates guardrails via Claude, (3) Reporter creates HTML reports, (4) Verifier confirms fixes work, (5) Orchestrator coordinates all agents, (6) CVE Watcher monitors NVD for new threats.",
    "what vulnerabilities were found": None,  # Dynamic answer below
    "how to fix prompt injection": "To fix LLM01 Prompt Injection: (1) Add input guardrails to detect injection patterns, (2) Separate system prompt from user input using delimiters, (3) Use NeMo Guardrails or LlamaGuard for runtime filtering, (4) Apply least privilege — don't grant LLM access to sensitive tools unnecessarily.",
    "what is owasp llm top 10": "The OWASP LLM Top 10 is the definitive list of the 10 most critical LLM security risks: LLM01 Prompt Injection, LLM02 Sensitive Info Disclosure, LLM03 Supply Chain, LLM04 Data and Model Poisoning, LLM05 Insecure Output Handling, LLM06 Excessive Agency, LLM07 System Prompt Leakage, LLM08 Vector and Embedding Weaknesses, LLM09 Misinformation, LLM10 Unbounded Consumption.",
    "security posture": None,  # Dynamic
    "score": None,  # Dynamic
}


def _dynamic_answer(question: str) -> str | None:
    """Generate a dynamic answer based on current scan data."""
    from components.security_score import calculate_security_score

    q = question.lower()
    raw = st.session_state.get("findings") or []
    if not raw:
        try:
            p = Path("artifacts/findings.json")
            if p.exists():
                raw = json.loads(p.read_text(encoding="utf-8"))
        except Exception:
            pass

    total = len(raw)

    if any(kw in q for kw in ("vuln", "found", "detect", "threat", "finding")):
        if not raw:
            return "No scan data yet. Run a Garak scan to detect vulnerabilities."
        sev_counts: dict[str, int] = {}
        cats: set[str] = set()
        for f in raw:
            sev = (f.get("severity") if isinstance(f, dict) else getattr(f, "severity", "LOW") or "LOW").upper()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
            cat = f.get("owasp_llm_category") if isinstance(f, dict) else getattr(f, "owasp_llm_category", "")
            if cat:
                cats.add(cat)
        summary = ", ".join(f"{v} {k}" for k, v in sorted(sev_counts.items()))
        return (
            f"RemediAX found **{total} vulnerabilities** in the last scan: {summary}. "
            f"Categories affected: {', '.join(sorted(cats))}. "
            "Run Full Pipeline v2 to auto-generate guardrails and fix them."
        )

    if any(kw in q for kw in ("score", "posture", "safe", "secure")):
        score = calculate_security_score(raw) if raw else 0
        level = "Critical" if score < 40 else "At Risk" if score < 70 else "Fair" if score < 85 else "Good"
        return (
            f"Your current Security Posture Score is **{score}%** ({level}). "
            "The score is calculated based on the number and severity of successful attacks. "
            "Run Full Pipeline v2 to generate guardrails and improve your score."
        )

    return None


def _fallback_answer(question: str) -> str:
    q = question.lower().strip()

    # Check quick answers
    for key, answer in _QUICK_ANSWERS.items():
        if key in q:
            if answer is None:
                dynamic = _dynamic_answer(question)
                if dynamic:
                    return dynamic
                continue
            return answer

    # Dynamic answers
    dynamic = _dynamic_answer(question)
    if dynamic:
        return dynamic

    return (
        "I can answer questions about your scan results, OWASP LLM categories, "
        "and RemediAX features. Try asking: 'What vulnerabilities were found?' "
        "or 'What is LLM01?' or 'How does RemediAX work?'"
    )


# ---------------------------------------------------------------------------
# Main render function
# ---------------------------------------------------------------------------


def render_ai_assistant() -> None:
    """Render an AI security assistant chat panel."""
    # Initialize chat history
    if "assistant_messages" not in st.session_state:
        st.session_state.assistant_messages = [
            {
                "role": "assistant",
                "content": "Hello! I'm your AI Security Assistant. Ask me about your scan results, OWASP vulnerabilities, or how RemediAX works.",
            }
        ]

    # Display chat history
    msgs_html = ""
    for msg in st.session_state.assistant_messages[-6:]:  # Show last 6 messages
        css_class = "user" if msg["role"] == "user" else "ai"
        icon = "👤" if msg["role"] == "user" else "🛡️"
        content = msg["content"]
        msgs_html += (
            f'<div class="rx-assistant-msg {css_class}">'
            f'<span style="font-size:0.7rem;color:#94A3B8;font-weight:600;">{icon} '
            f'{"You" if msg["role"] == "user" else "RemediAX AI"}</span><br>'
            f"{content}</div>"
        )

    if msgs_html:
        st.markdown(
            f'<div style="max-height:220px;overflow-y:auto;margin-bottom:8px;">{msgs_html}</div>',
            unsafe_allow_html=True,
        )

    # Input
    user_input = st.text_input(
        "Ask a security question…",
        key="assistant_input",
        label_visibility="collapsed",
        placeholder="e.g. What vulnerabilities were found?",
    )

    col_send, col_clear = st.columns([3, 1])
    with col_send:
        send = st.button("Ask", key="assistant_send", use_container_width=True, type="primary")
    with col_clear:
        if st.button("Clear", key="assistant_clear", use_container_width=True):
            st.session_state.assistant_messages = [
                {
                    "role": "assistant",
                    "content": "Chat cleared. Ask me anything about your security posture.",
                }
            ]
            st.rerun()

    if send and user_input.strip():
        st.session_state.assistant_messages.append(
            {"role": "user", "content": user_input.strip()}
        )

        # Try enhanced Claude answer first (uses RemediAXAI._call directly)
        answer: str | None = None
        ai_client = st.session_state.get("ai_client")
        if ai_client and st.session_state.get("api_mode"):
            try:
                prompt = (
                    "You are RemediAX AI Security Assistant. Answer concisely (2-4 sentences). "
                    "Focus on LLM security, OWASP Top 10 for LLMs, and AI threat analysis.\n\n"
                    f"Question: {user_input.strip()}"
                )
                answer = ai_client._call(prompt, max_tokens=300)
            except Exception:
                pass

        if not answer:
            answer = _fallback_answer(user_input.strip())

        st.session_state.assistant_messages.append(
            {"role": "assistant", "content": answer}
        )
        st.rerun()
