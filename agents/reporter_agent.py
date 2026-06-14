"""Agent 3 — Reporter: generates a professional HTML security report.

This is the third stage of the RemediAX v2.0 pipeline:

    Scanner → findings.json → Remediator → results → Reporter → summary.html

The ReporterAgent takes findings from Agent 1 and remediation results from Agent 2,
optionally enriches each finding with Claude-generated context (danger + fix text),
and renders a professional HTML report via Jinja2.

Connection from Agent 2:
    findings = scanner.scan()
    results  = remediator.remediate(findings)
    html     = reporter.generate_report(findings, results, target="mistral.ai")
    reporter.save_report(html, "artifacts/summary.html")
"""

from __future__ import annotations

import logging
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_SRC = Path(__file__).parent.parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

_TEMPLATES_DIR = Path(__file__).parent.parent / "templates"
_TEMPLATE_NAME = "summary.html.j2"

_OWASP_NAMES: dict[str, str] = {
    "LLM01": "Prompt Injection",
    "LLM02": "Sensitive Information Disclosure",
    "LLM03": "Supply Chain",
    "LLM04": "Data and Model Poisoning",
    "LLM05": "Improper Output Handling",
    "LLM06": "Excessive Agency",
    "LLM07": "System Prompt Leakage",
    "LLM08": "Vector and Embedding Weaknesses",
    "LLM09": "Misinformation",
    "LLM10": "Unbounded Consumption",
}

_DEFAULT_DANGER: dict[str, str] = {
    "LLM01": "This prompt injection attack successfully manipulated the model into ignoring its safety guidelines and following attacker-supplied instructions.",
    "LLM02": "This attack caused the model to disclose sensitive information that should remain private, exposing PII or credentials to unauthorized parties.",
    "LLM03": "A supply-chain compromise was detected — a model, dataset, or dependency may have been tampered with before deployment.",
    "LLM04": "Data or model poisoning was detected — malicious training-time influence may have introduced backdoors into model behavior.",
    "LLM05": "The model produced output that was not sufficiently validated, enabling downstream injection or code execution attacks.",
    "LLM06": "The AI agent took actions beyond its intended scope due to excessive permissions or insufficient authorization checks.",
    "LLM07": "The model leaked its system prompt in response to a direct extraction attack, exposing confidential instructions.",
    "LLM08": "A vector store or embedding weakness was exploited, potentially allowing poisoned documents to influence model responses.",
    "LLM09": "The model produced false or misleading information that could harm users or decision-making processes.",
    "LLM10": "The model was exploited to consume unbounded compute or make excessive downstream API calls.",
}

_DEFAULT_FIX: dict[str, str] = {
    "LLM01": "Apply input guardrails that detect and block prompt injection patterns before they reach the model. Use instruction-hierarchy hardening in the system prompt.",
    "LLM02": "Deploy output filters that detect and redact PII, credentials, and sensitive data before responses reach end users.",
    "LLM03": "Implement model signature verification and dependency scanning in your CI/CD pipeline to detect supply-chain tampering.",
    "LLM04": "Enforce dataset provenance checks and backdoor detection scans (Neural Cleanse, STRIP) before deploying new model versions.",
    "LLM05": "Validate and sanitize all LLM-generated output before passing it to downstream systems or rendering it in user interfaces.",
    "LLM06": "Apply the principle of least privilege to agent tool access. Require human-in-the-loop approval for sensitive operations.",
    "LLM07": "Add system prompt protection instructions that resist repetition/extraction attacks. Deploy a guardrail that detects prompt-leak patterns in responses.",
    "LLM08": "Enforce access controls on your vector store. Audit retrieved documents before including them in model context.",
    "LLM09": "Implement grounded generation with citation requirements (RAG with verified sources) and deploy hallucination-detection tooling.",
    "LLM10": "Apply rate limiting and resource budgets at the LLM gateway layer. Monitor for recursive or unbounded agent loops.",
}


class ReporterAgent:
    """Render a professional HTML security report from findings and remediation results.

    Args:
        ai_client:         Optional ``RemediAXAI`` instance. When supplied,
                           Claude generates per-finding danger and fix text plus
                           an executive summary. Falls back to pre-written content
                           when ``None`` or when every Claude call fails.
        anthropic_api_key: Convenience shortcut — constructs a ``RemediAXAI``
                           client automatically when ``ai_client`` is not given.
        template_path:     Path to an alternative Jinja2 template file. Defaults
                           to ``templates/summary.html.j2`` next to this package.
    """

    def __init__(
        self,
        ai_client: Any | None = None,
        anthropic_api_key: str | None = None,
        template_path: str | Path | None = None,
    ) -> None:
        if ai_client is not None:
            self._ai_client = ai_client
        elif anthropic_api_key:
            from components.ai_client import RemediAXAI
            self._ai_client = RemediAXAI(api_key=anthropic_api_key)
        else:
            self._ai_client = None

        self._template_path = Path(template_path) if template_path else _TEMPLATES_DIR / _TEMPLATE_NAME

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def generate_report(
        self,
        findings: list[Any],
        results: list[Any],
        target: str = "",
    ) -> str:
        """Build and return the full HTML report as a string.

        Args:
            findings: List of ``Finding`` objects from Agent 1.
            results:  List of ``RemediationResult`` objects from Agent 2.
                      Must be the same length and order as ``findings``.
            target:   Human-readable name for the scanned system, e.g.
                      ``"mistral.ai"`` or ``"internal-chatbot-v2"``.

        Returns:
            HTML string ready to write to ``summary.html``.
        """
        try:
            from jinja2 import Environment, FileSystemLoader, select_autoescape
        except ImportError as exc:
            raise ImportError("jinja2 is not installed — run: pip install jinja2") from exc

        context = self._build_context(findings, results, target)

        env = Environment(
            loader=FileSystemLoader(str(self._template_path.parent)),
            autoescape=select_autoescape(["html"]),
        )
        template = env.get_template(self._template_path.name)
        html = template.render(**context)
        logger.info("ReporterAgent: rendered report (%d bytes)", len(html))
        return html

    def save_report(
        self,
        html: str,
        output_path: str | Path,
    ) -> Path:
        """Write the HTML report to disk.

        Args:
            html:        The string returned by ``generate_report()``.
            output_path: File path (or directory — ``summary.html`` is
                         appended when a directory is given).

        Returns:
            The resolved ``Path`` that was written.
        """
        dest = Path(output_path)
        if dest.is_dir():
            dest = dest / "summary.html"
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(html, encoding="utf-8")
        logger.info("ReporterAgent: wrote report to %s", dest)
        return dest

    # ------------------------------------------------------------------ #
    #  Context builder                                                     #
    # ------------------------------------------------------------------ #

    def _build_context(
        self,
        findings: list[Any],
        results: list[Any],
        target: str,
    ) -> dict[str, Any]:
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = getattr(f, "severity", "LOW").upper()
            if sev in severity_counts:
                severity_counts[sev] += 1

        category_counts: dict[str, int] = {}
        for f in findings:
            cat = getattr(f, "owasp_llm_category", "")
            category_counts[cat] = category_counts.get(cat, 0) + 1

        owasp_rows = [
            {
                "code": code,
                "name": name,
                "count": category_counts.get(code, 0),
            }
            for code, name in _OWASP_NAMES.items()
        ]

        owasp_coverage = sum(1 for row in owasp_rows if row["count"] > 0)

        strategy_counts: dict[str, int] = {}
        remediated_count = 0
        for r in results:
            strat = str(getattr(r, "strategy", "log_only"))
            strat_key = strat.split(".")[-1].lower() if "." in strat else strat.lower()
            strategy_counts[strat_key] = strategy_counts.get(strat_key, 0) + 1
            if strat_key not in ("log_only",):
                remediated_count += 1

        exec_summary = self._build_exec_summary(findings, target)

        # Use positional zip — RemediatorAgent guarantees one result per finding
        # in order. A probe-name dict would silently overwrite duplicate entries.
        finding_items = []
        for finding, result in zip(findings, results):
            item = self._build_finding_item(finding, result)
            finding_items.append(item)
        # Append any unmatched findings (if findings > results) with no result
        for finding in findings[len(results):]:
            finding_items.append(self._build_finding_item(finding, None))

        return {
            "target": target,
            "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M UTC"),
            "findings": findings,
            "results": results,
            "severity_counts": severity_counts,
            "owasp_coverage": owasp_coverage,
            "owasp_rows": owasp_rows,
            "strategy_counts": strategy_counts,
            "remediated_count": remediated_count,
            "exec_summary": exec_summary,
            "finding_items": finding_items,
        }

    def _build_exec_summary(self, findings: list[Any], target: str) -> str:
        if self._ai_client is not None:
            try:
                summary = self._ai_client.summarize_scan(findings, target or None)
                if summary:
                    return summary
            except Exception as exc:
                logger.warning("ReporterAgent: summarize_scan failed: %s", exc)

        total = len(findings)
        cats = sorted({getattr(f, "owasp_llm_category", "") for f in findings} - {""})
        critical_high = sum(
            1 for f in findings
            if getattr(f, "severity", "").upper() in ("CRITICAL", "HIGH")
        )
        return (
            f"Security scan of {target or 'the target system'} found {total} "
            f"vulnerabilities across {len(cats)} OWASP LLM Top 10 categories "
            f"({', '.join(cats)}). "
            f"{critical_high} finding(s) are rated CRITICAL or HIGH and require "
            "immediate remediation — apply the guardrails generated below before deployment."
        )

    def _build_finding_item(self, finding: Any, result: Any | None) -> dict[str, Any]:
        category = getattr(finding, "owasp_llm_category", "")
        strategy_str = "log_only"
        if result is not None:
            raw = str(getattr(result, "strategy", "log_only"))
            strategy_str = raw.split(".")[-1].lower() if "." in raw else raw.lower()

        danger_text = self._get_danger_text(finding, result)
        fix_text = self._get_fix_text(finding, result)
        guardrail_snippet = self._get_guardrail_snippet(result)

        return {
            "finding": finding,
            "result": result,
            "strategy_str": strategy_str,
            "danger_text": danger_text,
            "fix_text": fix_text,
            "guardrail_snippet": guardrail_snippet,
        }

    def _get_danger_text(self, finding: Any, result: Any | None) -> str:
        if self._ai_client is not None:
            try:
                text = self._ai_client.explain_finding(finding)
                if text:
                    return text
            except Exception as exc:
                logger.warning("ReporterAgent: explain_finding failed: %s", exc)
        category = getattr(finding, "owasp_llm_category", "")
        return _DEFAULT_DANGER.get(category, "This attack exploited a vulnerability in the AI system's input or output handling.")

    def _get_fix_text(self, finding: Any, result: Any | None) -> str:
        if self._ai_client is not None and result is not None:
            try:
                text = self._ai_client.explain_fix(result, finding)
                if text:
                    return text
            except Exception as exc:
                logger.warning("ReporterAgent: explain_fix failed: %s", exc)
        category = getattr(finding, "owasp_llm_category", "")
        return _DEFAULT_FIX.get(category, "Apply input and output guardrails at the LLM gateway layer to block this attack pattern.")

    def _get_guardrail_snippet(self, result: Any | None) -> str:
        if result is None:
            return ""
        gc = getattr(result, "guardrail_config", None)
        if gc is None:
            return ""
        yaml_export = getattr(gc, "yaml_export", "")
        if not yaml_export:
            return ""
        lines = yaml_export.splitlines()
        snippet_lines = lines[:20]
        if len(lines) > 20:
            snippet_lines.append(f"... ({len(lines) - 20} more lines)")
        return "\n".join(snippet_lines)
