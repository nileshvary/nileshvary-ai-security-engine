"""Per-category OWASP LLM Top 10 content for the RemediAX UI.

Pre-written ``danger_explanation`` / ``fix_explanation`` strings are used
when Claude AI mode is off (or when an API call fails). Every entry has
the same shape so callers can index without per-category branching.
"""

from __future__ import annotations

from typing import Any


OWASP_CONTENT: dict[str, dict[str, Any]] = {
    "LLM01": {
        "name": "Prompt Injection",
        "color": "#ff4444",
        "icon": "🔴",
        "danger_explanation": (
            "The attacker overrides your system instructions by embedding "
            "commands in user input. With 66% success rate, your LLM "
            "abandons its role and follows attacker commands instead."
        ),
        "fix_explanation": (
            "Instruction hierarchy tells the LLM system rules take "
            "absolute priority. Delimiter tagging wraps user input so "
            "LLM treats it as data not commands. Combined these reduce "
            "DAN attacks by 87%."
        ),
        "strategy_icon": "🛡️",
        "escalation_note": None,
        "external_tools": [],
    },
    "LLM02": {
        "name": "Sensitive Information Disclosure",
        "color": "#ff6600",
        "icon": "🟠",
        "danger_explanation": (
            "The model leaks sensitive data — SSNs, API keys, emails, "
            "credit cards — in its responses. This exposes your users "
            "and violates privacy regulations like GDPR and HIPAA."
        ),
        "fix_explanation": (
            "Response sanitization uses regex patterns to detect and "
            "redact PII and secrets before they reach users. "
            "AWS keys become [REDACTED-AWS-KEY]. "
            "SSNs become [REDACTED-SSN]."
        ),
        "strategy_icon": "🧹",
        "escalation_note": None,
        "external_tools": [],
    },
    "LLM03": {
        "name": "Supply Chain Vulnerabilities",
        "color": "#ffaa00",
        "icon": "🟡",
        "danger_explanation": (
            "Compromised model weights, poisoned training data, or "
            "vulnerable dependencies introduced before deployment. "
            "Cannot be fixed at runtime — must be caught before deployment."
        ),
        "fix_explanation": (
            "Runtime remediation not applicable. This requires "
            "pre-deployment scanning of your ML supply chain and "
            "dependencies."
        ),
        "strategy_icon": "📋",
        "escalation_note": (
            "This finding is escalated — runtime patching cannot fix "
            "supply chain issues."
        ),
        "external_tools": [
            "Sigstore/cosign — model signature verification",
            "pip-audit — dependency vulnerability scanning",
            "Snyk — transitive dependency analysis",
            "CycloneDX — SBOM generation",
        ],
    },
    "LLM04": {
        "name": "Data and Model Poisoning",
        "color": "#ffcc00",
        "icon": "🟡",
        "danger_explanation": (
            "Malicious data was injected during training, causing the "
            "model to behave incorrectly in specific scenarios. The "
            "backdoor is baked into model weights — invisible at runtime."
        ),
        "fix_explanation": (
            "Runtime remediation not applicable. Poisoning requires "
            "training-time defenses and dataset provenance verification."
        ),
        "strategy_icon": "📋",
        "escalation_note": (
            "This finding requires retraining with clean, audited datasets."
        ),
        "external_tools": [
            "Neural Cleanse — backdoor detection",
            "STRIP — runtime trojan detection",
            "MLflow — dataset provenance tracking",
            "DVC — data version control",
        ],
    },
    "LLM05": {
        "name": "Improper Output Handling",
        "color": "#00d4ff",
        "icon": "🔵",
        "danger_explanation": (
            "The model generates dangerous content — XSS scripts, SQL "
            "injection, malicious URLs — that gets executed downstream. "
            "If your app renders LLM output in a browser, attackers can "
            "run arbitrary JavaScript."
        ),
        "fix_explanation": (
            "Output sanitization strips script tags, javascript: URIs, "
            "event handlers, and SQL injection patterns. HTML entities "
            "are escaped so browsers cannot execute injected code."
        ),
        "strategy_icon": "🧹",
        "escalation_note": None,
        "external_tools": [],
    },
    "LLM06": {
        "name": "Excessive Agency",
        "color": "#0080ff",
        "icon": "🔵",
        "danger_explanation": (
            "The LLM is taking dangerous autonomous actions — calling "
            "tools, executing commands, or making decisions beyond its "
            "intended scope. In agentic systems this can cause "
            "irreversible damage."
        ),
        "fix_explanation": (
            "Tool invocation patterns are detected and flagged for human "
            "review before execution. Dangerous phrases like 'calling "
            "tool:', 'executing:', and 'function_call:' trigger immediate "
            "alerts."
        ),
        "strategy_icon": "🚨",
        "escalation_note": None,
        "external_tools": [],
    },
    "LLM07": {
        "name": "System Prompt Leakage",
        "color": "#8b00ff",
        "icon": "🟣",
        "danger_explanation": (
            "The model reveals its confidential system prompt when "
            "asked. Attackers use this to understand your business "
            "logic, find weaknesses, and craft more targeted attacks "
            "against your application."
        ),
        "fix_explanation": (
            "Non-disclosure clauses are prepended to your system prompt. "
            "The model is explicitly instructed to never reveal, "
            "paraphrase, or hint at its instructions even when directly "
            "asked."
        ),
        "strategy_icon": "🛡️",
        "escalation_note": None,
        "external_tools": [],
    },
    "LLM08": {
        "name": "Vector and Embedding Weaknesses",
        "color": "#00ff88",
        "icon": "🟢",
        "danger_explanation": (
            "Your RAG system's vector store has improper access "
            "controls. Attackers can retrieve documents they should not "
            "access, or poison the vector store with malicious embeddings."
        ),
        "fix_explanation": (
            "Runtime remediation not applicable. Vector store weaknesses "
            "require infrastructure-level access controls and RAG "
            "architecture changes."
        ),
        "strategy_icon": "📋",
        "escalation_note": (
            "Requires RAG architecture review and vector store access "
            "control audit."
        ),
        "external_tools": [
            "Pinecone RBAC — vector store access control",
            "Weaviate ACLs — multi-tenant isolation",
            "Langfuse — RAG observability",
            "LangSmith — retrieval auditing",
        ],
    },
    "LLM09": {
        "name": "Misinformation",
        "color": "#ff00aa",
        "icon": "🟣",
        "danger_explanation": (
            "The model confidently generates false information — fake "
            "citations, fabricated statistics, incorrect facts. In "
            "production this erodes user trust and can cause real-world "
            "harm in high-stakes domains."
        ),
        "fix_explanation": (
            "Runtime remediation is limited — truthfulness requires "
            "training-level fixes. Basic output scanning can flag obvious "
            "hallucination patterns like fake URLs and fabricated "
            "citations."
        ),
        "strategy_icon": "📋",
        "escalation_note": (
            "Requires grounding with verified sources and human review "
            "for sensitive content."
        ),
        "external_tools": [
            "SelfCheckGPT — hallucination detection",
            "FActScore — factual accuracy scoring",
            "BBQ — bias evaluation",
            "RAG with verified sources — grounding",
        ],
    },
    "LLM10": {
        "name": "Unbounded Consumption",
        "color": "#ff4444",
        "icon": "🔴",
        "danger_explanation": (
            "The model can be abused to consume unlimited tokens and "
            "API calls — causing massive costs and service denial for "
            "legitimate users. One attacker can drain your entire budget."
        ),
        "fix_explanation": (
            "Rate limiting guardrails are generated for your AI gateway. "
            "Requests are capped at 60/minute, tokens at 100K/minute, "
            "and individual requests at 5K tokens maximum."
        ),
        "strategy_icon": "⚡",
        "escalation_note": None,
        "external_tools": [],
    },
}

ACTIVE_CATEGORIES: frozenset[str] = frozenset(
    {"LLM01", "LLM02", "LLM05", "LLM06", "LLM07", "LLM10"}
)
ESCALATION_CATEGORIES: frozenset[str] = frozenset(
    {"LLM03", "LLM04", "LLM08", "LLM09"}
)

# Canonical homepages for the tools surfaced in escalation cards.
# Keyed by the tool *name* part of the "Name — description" strings in
# each category's ``external_tools`` list. Tools without a confidently
# canonical URL (research-method papers like Neural Cleanse / STRIP /
# BBQ, or non-tools like "RAG with verified sources") are intentionally
# omitted so the renderer shows them as plain text instead of a guessed
# link.
_TOOL_URLS: dict[str, str] = {
    # User-specified (LLM08, LLM09)
    "Pinecone RBAC": "https://www.pinecone.io",
    "Weaviate ACLs": "https://weaviate.io",
    "Langfuse": "https://langfuse.com",
    "LangSmith": "https://smith.langchain.com",
    "SelfCheckGPT": "https://github.com/potsawee/selfcheckgpt",
    "FActScore": "https://github.com/shmsw25/FActScore",
    # Well-known canonical pages (LLM03, LLM04)
    "Sigstore/cosign": "https://www.sigstore.dev",
    "pip-audit": "https://github.com/pypa/pip-audit",
    "Snyk": "https://snyk.io",
    "CycloneDX": "https://cyclonedx.org",
    "MLflow": "https://mlflow.org",
    "DVC": "https://dvc.org",
}


def get(code: str) -> dict[str, Any]:
    """Return the content dict for an OWASP LLM code.

    Raises:
        KeyError: If ``code`` is not in ``OWASP_CONTENT``.
    """
    return OWASP_CONTENT[code]


def is_escalation(code: str) -> bool:
    """True for the four out-of-band categories that need external tooling."""
    return code in ESCALATION_CATEGORIES


def split_tool_entry(text: str) -> tuple[str, str]:
    """Split a ``"Name — description"`` tool string into its two parts.

    Returns ``(name, description)``. If the entry has no em-dash
    separator the whole string is the name and the description is empty.
    """
    if " — " in text:
        name, desc = text.split(" — ", 1)
        return name.strip(), desc.strip()
    return text.strip(), ""


def get_tool_url(name: str) -> str | None:
    """Return the canonical URL for ``name`` or ``None`` if unknown.

    Lookups are case-sensitive against the tool-name strings used in
    ``OWASP_CONTENT[...][\"external_tools\"]``.
    """
    return _TOOL_URLS.get(name)
