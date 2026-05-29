"""Writer classes that emit pipeline artifacts to disk.

Four writers, one per format:

- ``JsonWriter``  — three structured JSON files (findings, remediation
  results, verification report).
- ``YamlWriter``  — the Phase 3 guardrail config, byte-for-byte.
- ``MarkdownWriter`` — human-readable view of every patched prompt.
- ``HtmlWriter``  — self-contained visual summary with inline CSS,
  no JS, no external resources.

All writers use UTF-8 and stat the file post-write to populate
``OutputArtifact.size_bytes``.
"""

from __future__ import annotations

import html
import json
import logging
from collections import Counter
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from integration_bridge.models import Finding
from remediation_engine.models import GuardrailConfig, RemediationResult
from verifier.models import VerificationReport, VerificationResult

from output.models import OutputArtifact

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared serialization helpers
# ---------------------------------------------------------------------------


def _json_default(obj: object) -> object:
    """``json.dump`` ``default=`` hook for Path, datetime, enums, and dataclasses."""
    if isinstance(obj, Path):
        return str(obj)
    if isinstance(obj, datetime):
        return obj.isoformat()
    if isinstance(obj, Enum):
        return obj.value
    if is_dataclass(obj) and not isinstance(obj, type):
        return asdict(obj)
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def _build_artifact(path: Path, fmt: str, description: str) -> OutputArtifact:
    """Stat a freshly-written file and wrap it as an ``OutputArtifact``."""
    size = path.stat().st_size
    logger.info("Wrote %s (%d bytes)", path.name, size)
    return OutputArtifact(
        filename=path.name,
        filepath=path.resolve(),
        format=fmt,
        description=description,
        size_bytes=size,
    )


def _collapse_remediation_result(result: RemediationResult) -> dict[str, Any]:
    """Serialize a ``RemediationResult`` with its bulky guardrail config replaced by a reference.

    The full guardrail YAML is written separately as ``guardrails.yaml``;
    duplicating it inside every result would bloat the JSON considerably.
    """
    data = asdict(result)
    data["guardrail_config"] = (
        {"format": result.guardrail_config.format, "ref": "guardrails.yaml"}
        if result.guardrail_config is not None
        else None
    )
    return data


def _collapse_verification_report(report: VerificationReport) -> dict[str, Any]:
    """Serialize a ``VerificationReport`` collapsing nested remediation results to refs.

    Each ``VerificationResult.remediation_result`` is replaced by a small
    descriptor that points at the corresponding entry in
    ``remediation_results.json`` via ``probe_name``.
    """

    def _collapse_one(vr: VerificationResult) -> dict[str, Any]:
        data = asdict(vr)
        finding = vr.remediation_result.finding
        data["remediation_result"] = {
            "probe_name": finding.probe_name,
            "owasp_llm_category": finding.owasp_llm_category,
            "severity": finding.severity,
            "ref": "remediation_results.json",
        }
        return data

    return {
        "results": [_collapse_one(r) for r in report.results],
        "total_findings": report.total_findings,
        "verified_count": report.verified_count,
        "partial_count": report.partial_count,
        "failed_count": report.failed_count,
        "unverifiable_count": report.unverifiable_count,
        "overall_improvement_percent": report.overall_improvement_percent,
        "summary": report.summary,
    }


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------


class JsonWriter:
    """Writes three structured JSON files: findings, remediation, verification."""

    def write(
        self,
        findings: list[Finding],
        remediation_results: list[RemediationResult],
        verification_report: VerificationReport,
        output_dir: Path,
    ) -> list[OutputArtifact]:
        """Write the three JSON files and return one artifact per file."""
        findings_path = output_dir / "findings.json"
        findings_path.write_text(
            json.dumps([asdict(f) for f in findings], indent=2, default=_json_default),
            encoding="utf-8",
        )

        remediation_path = output_dir / "remediation_results.json"
        remediation_path.write_text(
            json.dumps(
                [_collapse_remediation_result(r) for r in remediation_results],
                indent=2,
                default=_json_default,
            ),
            encoding="utf-8",
        )

        verification_path = output_dir / "verification_report.json"
        verification_path.write_text(
            json.dumps(
                _collapse_verification_report(verification_report),
                indent=2,
                default=_json_default,
            ),
            encoding="utf-8",
        )

        return [
            _build_artifact(findings_path, "json", "Parsed garak findings"),
            _build_artifact(
                remediation_path, "json", "Per-finding remediation results"
            ),
            _build_artifact(
                verification_path, "json", "Aggregate verification report"
            ),
        ]


# ---------------------------------------------------------------------------
# YAML
# ---------------------------------------------------------------------------


class YamlWriter:
    """Writes the Phase 3 guardrail config to ``guardrails.yaml``."""

    def write(
        self, guardrail_config: GuardrailConfig, output_dir: Path
    ) -> OutputArtifact:
        path = output_dir / "guardrails.yaml"
        path.write_text(guardrail_config.yaml_export, encoding="utf-8")
        return _build_artifact(
            path,
            "yaml",
            f"Guardrail config ({guardrail_config.format} format)",
        )


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------


class MarkdownWriter:
    """Writes a human-readable summary of every patched prompt."""

    def write(
        self,
        remediation_results: list[RemediationResult],
        output_dir: Path,
    ) -> OutputArtifact:
        path = output_dir / "patched_prompts.md"
        lines: list[str] = []
        lines.append("# Patched System Prompts")
        lines.append("")
        lines.append(
            f"_Generated at {datetime.now(timezone.utc).isoformat()} UTC._"
        )
        lines.append("")

        patched = [r for r in remediation_results if r.prompt_patch is not None]
        patched.sort(key=lambda r: r.finding.probe_name)

        if not patched:
            lines.append("No prompt patches were produced for this run.")
            lines.append("")
            lines.append(
                "_LLM01 / LLM07 patches require ``--prompt`` to be supplied._"
            )
        else:
            for result in patched:
                patch = result.prompt_patch
                assert patch is not None  # narrowed by filter above
                finding = result.finding
                lines.append(
                    f"## `{finding.probe_name}` "
                    f"({finding.owasp_llm_category} / severity {finding.severity})"
                )
                lines.append("")
                lines.append(f"**Why this patch:** {patch.patch_explanation}")
                lines.append("")
                if patch.injection_resistance_techniques:
                    lines.append("**Techniques applied:**")
                    for technique in patch.injection_resistance_techniques:
                        lines.append(f"- `{technique}`")
                    lines.append("")
                lines.append("### Original prompt")
                lines.append("```text")
                lines.append(patch.original_prompt)
                lines.append("```")
                lines.append("")
                lines.append("### Patched prompt")
                lines.append("```text")
                lines.append(patch.patched_prompt)
                lines.append("```")
                lines.append("")

        path.write_text("\n".join(lines), encoding="utf-8")
        return _build_artifact(
            path, "markdown", "Human-readable patched prompts"
        )


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------


_HTML_CSS = """\
:root {
  --bg: #f7f7f9;
  --card-bg: #ffffff;
  --border: #e1e4e8;
  --text: #1f2328;
  --muted: #59636e;
  --accent: #0969da;
  --verified: #1a7f37;
  --partial: #9a6700;
  --failed: #cf222e;
  --unverifiable: #59636e;
  --crit: #cf222e;
  --high: #d1242f;
  --med: #9a6700;
  --low: #1a7f37;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  padding: 2rem;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, sans-serif;
  background: var(--bg);
  color: var(--text);
  line-height: 1.5;
}
header { margin-bottom: 2rem; }
h1 { margin: 0 0 0.25rem; font-size: 1.75rem; }
.tagline { color: var(--muted); margin: 0; }
.card {
  background: var(--card-bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 1.5rem;
  margin-bottom: 1.5rem;
}
.stat-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
  gap: 1rem;
  margin-bottom: 1rem;
}
.stat {
  padding: 1rem;
  border: 1px solid var(--border);
  border-radius: 6px;
  text-align: center;
}
.stat .value { font-size: 1.75rem; font-weight: 600; }
.stat .label { color: var(--muted); font-size: 0.875rem; }
.improvement {
  font-size: 2.5rem;
  font-weight: 700;
  color: var(--accent);
}
table { width: 100%; border-collapse: collapse; }
th, td {
  padding: 0.5rem 0.75rem;
  text-align: left;
  border-bottom: 1px solid var(--border);
  font-size: 0.9rem;
}
th { background: var(--bg); font-weight: 600; }
.badge {
  display: inline-block;
  padding: 0.15rem 0.55rem;
  border-radius: 999px;
  font-size: 0.75rem;
  font-weight: 600;
  color: #fff;
}
.status-verified { background: var(--verified); }
.status-partial { background: var(--partial); }
.status-failed { background: var(--failed); }
.status-unverifiable { background: var(--unverifiable); }
.sev-critical { background: var(--crit); }
.sev-high { background: var(--high); }
.sev-medium { background: var(--med); }
.sev-low { background: var(--low); }
.bar {
  display: flex;
  height: 0.6rem;
  border-radius: 3px;
  overflow: hidden;
  background: var(--border);
}
.bar > span { display: block; height: 100%; }
.bar .seg-verified { background: var(--verified); }
.bar .seg-partial { background: var(--partial); }
.bar .seg-failed { background: var(--failed); }
.bar .seg-unverifiable { background: var(--unverifiable); }
footer { color: var(--muted); font-size: 0.85rem; margin-top: 2rem; }
"""


def _badge(text: str, css_class: str) -> str:
    return f'<span class="badge {css_class}">{html.escape(text, quote=True)}</span>'


def _severity_badge(severity: str) -> str:
    return _badge(severity, f"sev-{severity.lower()}")


def _status_badge(status: str) -> str:
    return _badge(status, f"status-{status.lower()}")


class HtmlWriter:
    """Writes a self-contained visual summary report."""

    def write(
        self,
        findings: list[Finding],
        remediation_results: list[RemediationResult],
        verification_report: VerificationReport,
        output_dir: Path,
    ) -> OutputArtifact:
        path = output_dir / "summary.html"
        timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")
        improvement = verification_report.overall_improvement_percent
        total = verification_report.total_findings

        # Aggregate per-category status counts for the breakdown table.
        per_cat_status: dict[str, Counter] = {}
        for vr in verification_report.results:
            category = vr.remediation_result.finding.owasp_llm_category
            per_cat_status.setdefault(category, Counter())[vr.verification_status] += 1

        body: list[str] = []
        body.append("<!doctype html>")
        body.append('<html lang="en">')
        body.append("<head>")
        body.append('<meta charset="utf-8">')
        body.append('<meta name="viewport" content="width=device-width, initial-scale=1">')
        body.append("<title>AI Security Engine - Report</title>")
        body.append(f"<style>{_HTML_CSS}</style>")
        body.append("</head>")
        body.append("<body>")
        body.append("<header>")
        body.append("<h1>AI Security Engine Report</h1>")
        body.append(
            f'<p class="tagline">Generated {html.escape(timestamp, quote=True)} UTC</p>'
        )
        body.append("</header>")

        # Stats card
        body.append('<section class="card">')
        body.append("<h2>Overall</h2>")
        body.append(
            f'<div class="improvement">{improvement:.1f}% overall improvement</div>'
        )
        body.append('<div class="stat-grid">')
        for label, value in [
            ("Findings", total),
            ("Verified", verification_report.verified_count),
            ("Partial", verification_report.partial_count),
            ("Failed", verification_report.failed_count),
            ("Unverifiable", verification_report.unverifiable_count),
        ]:
            body.append(
                f'<div class="stat"><div class="value">{value}</div>'
                f'<div class="label">{html.escape(label, quote=True)}</div></div>'
            )
        body.append("</div></section>")

        # Per-category breakdown
        body.append('<section class="card">')
        body.append("<h2>By OWASP category</h2>")
        body.append("<table><thead><tr>")
        body.append(
            "<th>Category</th><th>Findings</th><th>Status breakdown</th>"
        )
        body.append("</tr></thead><tbody>")
        for category in sorted(per_cat_status):
            counts = per_cat_status[category]
            cat_total = sum(counts.values())
            segs = []
            for status_key, css in (
                ("VERIFIED", "seg-verified"),
                ("PARTIAL", "seg-partial"),
                ("FAILED", "seg-failed"),
                ("UNVERIFIABLE", "seg-unverifiable"),
            ):
                pct = (counts.get(status_key, 0) / cat_total) * 100 if cat_total else 0
                if pct > 0:
                    segs.append(f'<span class="{css}" style="width:{pct:.1f}%"></span>')
            bar = f'<div class="bar">{"".join(segs)}</div>' if segs else ""
            body.append(
                f"<tr><td><code>{html.escape(category, quote=True)}</code></td>"
                f"<td>{cat_total}</td><td>{bar}</td></tr>"
            )
        body.append("</tbody></table>")
        body.append("</section>")

        # Findings table
        body.append('<section class="card">')
        body.append("<h2>Findings</h2>")
        body.append("<table><thead><tr>")
        body.append(
            "<th>Probe</th><th>Category</th><th>Severity</th>"
            "<th>Status</th><th>Improvement</th>"
        )
        body.append("</tr></thead><tbody>")
        for vr in verification_report.results:
            finding = vr.remediation_result.finding
            improvement_cell = (
                f"{vr.improvement_percent:.1f}%"
                if vr.improvement_percent is not None
                else "&mdash;"
            )
            body.append(
                "<tr>"
                f"<td><code>{html.escape(finding.probe_name, quote=True)}</code></td>"
                f"<td>{html.escape(finding.owasp_llm_category, quote=True)}</td>"
                f"<td>{_severity_badge(finding.severity)}</td>"
                f"<td>{_status_badge(vr.verification_status)}</td>"
                f"<td>{improvement_cell}</td>"
                "</tr>"
            )
        body.append("</tbody></table>")
        body.append("</section>")

        body.append(
            "<footer>Strategies: <code>HARDEN</code> patches prompts, "
            "<code>SANITIZE</code> redacts responses, <code>GUARDRAIL</code> "
            "emits gateway rules, <code>LOG_ONLY</code> flags for review.</footer>"
        )
        body.append("</body></html>")

        path.write_text("\n".join(body), encoding="utf-8")
        return _build_artifact(path, "html", "Self-contained visual summary")
