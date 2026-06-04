"""Tests for the four output writers."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from output.writers import HtmlWriter, JsonWriter, MarkdownWriter, YamlWriter


class TestJsonWriter:
    def test_writes_three_files(
        self,
        tmp_path: Path,
        sample_findings_list,
        sample_remediation_results,
        sample_verification_report,
    ) -> None:
        writer = JsonWriter()
        artifacts = writer.write(
            sample_findings_list,
            sample_remediation_results,
            sample_verification_report,
            tmp_path,
        )
        assert len(artifacts) == 3
        names = {a.filename for a in artifacts}
        assert names == {
            "findings.json",
            "remediation_results.json",
            "verification_report.json",
        }
        for artifact in artifacts:
            assert artifact.format == "json"
            assert artifact.filepath.is_file()
            assert artifact.size_bytes > 0

    def test_findings_json_parses_back(
        self,
        tmp_path: Path,
        sample_findings_list,
        sample_remediation_results,
        sample_verification_report,
    ) -> None:
        JsonWriter().write(
            sample_findings_list,
            sample_remediation_results,
            sample_verification_report,
            tmp_path,
        )
        data = json.loads((tmp_path / "findings.json").read_text(encoding="utf-8"))
        assert isinstance(data, list)
        assert len(data) == len(sample_findings_list)
        assert "probe_name" in data[0]
        assert "owasp_llm_category" in data[0]

    def test_remediation_collapses_guardrail_config(
        self,
        tmp_path: Path,
        sample_findings_list,
        sample_remediation_results,
        sample_verification_report,
    ) -> None:
        JsonWriter().write(
            sample_findings_list,
            sample_remediation_results,
            sample_verification_report,
            tmp_path,
        )
        data = json.loads(
            (tmp_path / "remediation_results.json").read_text(encoding="utf-8")
        )
        first = data[0]
        # guardrail_config is replaced by a small ref dict, not the full YAML.
        assert first["guardrail_config"] == {
            "format": "portkey",
            "ref": "guardrails.yaml",
        }

    def test_verification_report_parses_back(
        self,
        tmp_path: Path,
        sample_findings_list,
        sample_remediation_results,
        sample_verification_report,
    ) -> None:
        JsonWriter().write(
            sample_findings_list,
            sample_remediation_results,
            sample_verification_report,
            tmp_path,
        )
        data = json.loads(
            (tmp_path / "verification_report.json").read_text(encoding="utf-8")
        )
        assert "results" in data
        assert "summary" in data
        assert "overall_improvement_percent" in data
        # Each nested remediation_result is collapsed to a ref dict.
        assert data["results"][0]["remediation_result"]["ref"] == "remediation_results.json"


class TestYamlWriter:
    def test_writes_yaml_byte_for_byte(
        self,
        tmp_path: Path,
        sample_guardrail_config,
    ) -> None:
        artifact = YamlWriter().write(sample_guardrail_config, tmp_path)
        assert artifact.filename == "guardrails.yaml"
        assert artifact.format == "yaml"
        assert artifact.filepath.is_file()
        assert (
            artifact.filepath.read_text(encoding="utf-8")
            == sample_guardrail_config.yaml_export
        )

    def test_yaml_parses_back(
        self,
        tmp_path: Path,
        sample_guardrail_config,
    ) -> None:
        YamlWriter().write(sample_guardrail_config, tmp_path)
        parsed = yaml.safe_load((tmp_path / "guardrails.yaml").read_text(encoding="utf-8"))
        assert isinstance(parsed, dict)
        assert "version" in parsed


class TestMarkdownWriter:
    def test_writes_markdown_with_h1(
        self,
        tmp_path: Path,
        sample_remediation_results,
    ) -> None:
        artifact = MarkdownWriter().write(sample_remediation_results, tmp_path)
        assert artifact.filename == "patched_prompts.md"
        assert artifact.format == "markdown"
        content = artifact.filepath.read_text(encoding="utf-8")
        assert content.startswith("# Patched System Prompts")

    def test_includes_llm01_patch_body(
        self,
        tmp_path: Path,
        sample_remediation_results,
    ) -> None:
        MarkdownWriter().write(sample_remediation_results, tmp_path)
        content = (tmp_path / "patched_prompts.md").read_text(encoding="utf-8")
        # The LLM01 sample patch carries "instruction-hierarchy" as a technique.
        assert "instruction-hierarchy" in content
        assert "### Original prompt" in content
        assert "### Patched prompt" in content

    def test_handles_empty_patches_with_stub(self, tmp_path: Path) -> None:
        artifact = MarkdownWriter().write([], tmp_path)
        content = artifact.filepath.read_text(encoding="utf-8")
        assert "No prompt patches were produced" in content


class TestHtmlWriter:
    def test_writes_self_contained_html(
        self,
        tmp_path: Path,
        sample_findings_list,
        sample_remediation_results,
        sample_verification_report,
    ) -> None:
        artifact = HtmlWriter().write(
            sample_findings_list,
            sample_remediation_results,
            sample_verification_report,
            tmp_path,
        )
        assert artifact.filename == "summary.html"
        assert artifact.format == "html"
        content = artifact.filepath.read_text(encoding="utf-8")
        assert content.startswith("<!doctype html>")
        assert "<style>" in content
        assert "<script>" not in content  # JS-free
        # No insecure http://, and the only allowed https:// is the
        # RemediAX GitHub link in section 7. ``TestHtmlWriterBehavior``
        # enforces the whitelist more strictly.
        assert "http://" not in content

    def test_html_includes_executive_summary_block(
        self,
        tmp_path: Path,
        sample_findings_list,
        sample_remediation_results,
        sample_verification_report,
    ) -> None:
        HtmlWriter().write(
            sample_findings_list,
            sample_remediation_results,
            sample_verification_report,
            tmp_path,
        )
        content = (tmp_path / "summary.html").read_text(encoding="utf-8")
        assert "Executive Summary" in content
        # Auto-generated narrative mentions the finding count.
        assert f"{len(sample_findings_list)} vulnerability finding" in content

    @pytest.mark.parametrize("category", [f"LLM{i:02d}" for i in range(1, 11)])
    def test_html_lists_every_category(
        self,
        tmp_path: Path,
        sample_findings_list,
        sample_remediation_results,
        sample_verification_report,
        category: str,
    ) -> None:
        HtmlWriter().write(
            sample_findings_list,
            sample_remediation_results,
            sample_verification_report,
            tmp_path,
        )
        content = (tmp_path / "summary.html").read_text(encoding="utf-8")
        assert category in content


# ---------------------------------------------------------------------------
# New product-spec coverage — the eight-section bug report
# ---------------------------------------------------------------------------


class TestHtmlWriterSpecSections:
    """One test per spec section + behavioral guarantees."""

    def test_section_1_header_carries_title_subtitle_and_reference(
        self,
        tmp_path: Path,
        sample_findings_list,
        sample_remediation_results,
        sample_verification_report,
    ) -> None:
        HtmlWriter().write(
            sample_findings_list,
            sample_remediation_results,
            sample_verification_report,
            tmp_path,
        )
        content = (tmp_path / "summary.html").read_text(encoding="utf-8")
        assert "<h1>Security Vulnerability Report</h1>" in content
        assert "AI Security Engine - RemediAX v1.0.0" in content
        # Reference number follows the RMX-{YEAR}-{LLMnn} pattern.
        import re

        match = re.search(r"RMX-(\d{4})-(LLM\d{2})", content)
        assert match is not None
        year, code = match.group(1), match.group(2)
        from datetime import datetime, timezone
        assert year == str(datetime.now(timezone.utc).year)
        assert code in {f"LLM{i:02d}" for i in range(1, 11)}

    def test_section_2_executive_summary_has_four_metric_cards(
        self,
        tmp_path: Path,
        sample_findings_list,
        sample_remediation_results,
        sample_verification_report,
    ) -> None:
        HtmlWriter().write(
            sample_findings_list,
            sample_remediation_results,
            sample_verification_report,
            tmp_path,
        )
        content = (tmp_path / "summary.html").read_text(encoding="utf-8")
        for label in (
            "Total findings",
            "Overall risk",
            "OWASP category",
            "Patched count",
        ):
            assert label in content

    def test_section_3_report_info_includes_researcher_target_tool_cvss(
        self,
        tmp_path: Path,
        sample_findings_list,
        sample_remediation_results,
        sample_verification_report,
    ) -> None:
        HtmlWriter().write(
            sample_findings_list,
            sample_remediation_results,
            sample_verification_report,
            tmp_path,
        )
        content = (tmp_path / "summary.html").read_text(encoding="utf-8")
        assert "Report Information" in content
        for label in (
            "Researcher",
            "Target",
            "Test date",
            "Tool",
            "OWASP category",
            "CVSS score",
        ):
            assert f"<th>{label}</th>" in content
        # Default values used when fixture findings carry no notes.
        assert "Security Researcher" in content
        assert "AI System" in content
        assert "RemediAX v1.0.0" in content
        # CVSS rendered numerically as one of the spec values.
        assert any(
            f"{v:.1f}" in content for v in (9.0, 7.5, 5.3, 3.1)
        )

    def test_section_4_finding_card_has_attack_response_danger_fix(
        self,
        tmp_path: Path,
        sample_findings_list,
        sample_remediation_results,
        sample_verification_report,
    ) -> None:
        HtmlWriter().write(
            sample_findings_list,
            sample_remediation_results,
            sample_verification_report,
            tmp_path,
        )
        content = (tmp_path / "summary.html").read_text(encoding="utf-8")
        assert content.count('class="finding-card') == len(sample_findings_list)
        # Each card surfaces all four labeled blocks.
        assert "Attack prompt used" in content
        assert "Model response received" in content
        assert "Why this is dangerous" in content
        assert "Recommended fix" in content
        # The fixture's attack prompt for LLM01 contains the substring
        # "LLM01" — confirms the actual finding content is rendered.
        sample = sample_findings_list[0]
        assert sample.probe_name in content

    def test_section_5_includes_guardrail_yaml_when_provided(
        self,
        tmp_path: Path,
        sample_findings_list,
        sample_remediation_results,
        sample_verification_report,
        sample_guardrail_config,
    ) -> None:
        HtmlWriter().write(
            sample_findings_list,
            sample_remediation_results,
            sample_verification_report,
            tmp_path,
            guardrail_config=sample_guardrail_config,
        )
        content = (tmp_path / "summary.html").read_text(encoding="utf-8")
        assert "Recommended Guardrails" in content
        # A line from the actual YAML must appear inside a <pre> block.
        assert "version: 1" in content
        assert '<pre class="yaml">' in content

    def test_section_5_handles_missing_guardrail_config_gracefully(
        self,
        tmp_path: Path,
        sample_findings_list,
        sample_remediation_results,
        sample_verification_report,
    ) -> None:
        HtmlWriter().write(
            sample_findings_list,
            sample_remediation_results,
            sample_verification_report,
            tmp_path,
            guardrail_config=None,
        )
        content = (tmp_path / "summary.html").read_text(encoding="utf-8")
        assert "Recommended Guardrails" in content
        assert "No guardrail YAML was generated" in content

    def test_section_6_lists_up_to_four_actionable_recommendations(
        self,
        tmp_path: Path,
        sample_findings_list,
        sample_remediation_results,
        sample_verification_report,
    ) -> None:
        HtmlWriter().write(
            sample_findings_list,
            sample_remediation_results,
            sample_verification_report,
            tmp_path,
        )
        content = (tmp_path / "summary.html").read_text(encoding="utf-8")
        assert "Recommendations" in content
        # The fixture has 10 distinct categories so we cap at exactly 4.
        ol_section = content.split('<ol class="recs">')[1].split("</ol>")[0]
        assert ol_section.count("<li>") == 4

    def test_section_7_has_researcher_and_github_link(
        self,
        tmp_path: Path,
        sample_findings_list,
        sample_remediation_results,
        sample_verification_report,
    ) -> None:
        HtmlWriter().write(
            sample_findings_list,
            sample_remediation_results,
            sample_verification_report,
            tmp_path,
        )
        content = (tmp_path / "summary.html").read_text(encoding="utf-8")
        assert "Researcher Information" in content
        assert "github.com/nileshvary/nileshvary-ai-security-engine" in content

    def test_section_8_footer_carries_version_date_and_disclosure(
        self,
        tmp_path: Path,
        sample_findings_list,
        sample_remediation_results,
        sample_verification_report,
    ) -> None:
        HtmlWriter().write(
            sample_findings_list,
            sample_remediation_results,
            sample_verification_report,
            tmp_path,
        )
        content = (tmp_path / "summary.html").read_text(encoding="utf-8")
        from datetime import datetime, timezone
        assert f"Generated by RemediAX v1.0.0" in content
        assert str(datetime.now(timezone.utc).year) in content
        assert "Responsible disclosure" in content


class TestHtmlWriterHelpers:
    """Pure-function helpers — covered directly since they drive the rendering."""

    def test_cvss_from_severity_uses_spec_mapping(self) -> None:
        from output.writers import _cvss_from_severity

        assert _cvss_from_severity("CRITICAL") == 9.0
        assert _cvss_from_severity("HIGH") == 7.5
        assert _cvss_from_severity("MEDIUM") == 5.3
        assert _cvss_from_severity("LOW") == 3.1
        assert _cvss_from_severity("WEIRD") is None

    def test_overall_risk_picks_highest_severity(self) -> None:
        from output.writers import _overall_risk

        from tests.remediation_engine.fixtures.sample_findings import make_finding

        findings = [
            make_finding("LLM01", severity="MEDIUM"),
            make_finding("LLM02", severity="CRITICAL"),
            make_finding("LLM03", severity="LOW"),
        ]
        assert _overall_risk(findings) == "CRITICAL"

    def test_overall_risk_empty_findings_default_low(self) -> None:
        from output.writers import _overall_risk

        assert _overall_risk([]) == "LOW"

    def test_dominant_category_uses_mode_with_alphabetical_tiebreak(self) -> None:
        from output.writers import _dominant_category

        from tests.remediation_engine.fixtures.sample_findings import make_finding

        findings = [
            make_finding("LLM07"),
            make_finding("LLM01"),
            make_finding("LLM01"),
            make_finding("LLM07"),  # tie 2-2
        ]
        # LLM01 wins on alphabetical tiebreak.
        assert _dominant_category(findings) == "LLM01"

    def test_extract_finding_note_walks_raw_data_first_match(self) -> None:
        from output.writers import _extract_finding_note

        from tests.remediation_engine.fixtures.sample_findings import make_finding

        findings = [
            make_finding("LLM01", raw_data={"unrelated": "x"}),
            make_finding(
                "LLM01",
                raw_data={"notes": {"target": "Mistral-7B"}},
            ),
            make_finding("LLM01", raw_data={"target": "ignored"}),
        ]
        assert (
            _extract_finding_note(findings, "target", "AI System") == "Mistral-7B"
        )

    def test_extract_finding_note_falls_back_to_default(self) -> None:
        from output.writers import _extract_finding_note

        from tests.remediation_engine.fixtures.sample_findings import make_finding

        findings = [make_finding("LLM01", raw_data={})]
        assert (
            _extract_finding_note(findings, "target", "AI System") == "AI System"
        )

    def test_extract_finding_note_prefers_top_level_when_no_notes_dict(self) -> None:
        from output.writers import _extract_finding_note

        from tests.remediation_engine.fixtures.sample_findings import make_finding

        findings = [
            make_finding(
                "LLM01", raw_data={"researcher": "Alice"}
            )
        ]
        assert (
            _extract_finding_note(findings, "researcher", "Security Researcher")
            == "Alice"
        )

    def test_top_recommendations_caps_at_four_and_is_actionable(self) -> None:
        from output.writers import _top_recommendations

        from tests.remediation_engine.fixtures.sample_findings import (
            all_category_findings,
        )

        recs = _top_recommendations(all_category_findings(), max_n=4)
        assert len(recs) == 4
        # Each recommendation is a non-trivial actionable sentence.
        for rec in recs:
            assert len(rec) > 30


class TestHtmlWriterBehavior:
    """Behavioral guarantees — no hardcoded target, default fallbacks, no JS."""

    def test_no_hardcoded_mistral_in_output(
        self,
        tmp_path: Path,
        sample_findings_list,
        sample_remediation_results,
        sample_verification_report,
    ) -> None:
        """Spec: 'No hardcoding of Mistral specific content'."""
        HtmlWriter().write(
            sample_findings_list,
            sample_remediation_results,
            sample_verification_report,
            tmp_path,
        )
        content = (tmp_path / "summary.html").read_text(encoding="utf-8")
        assert "Mistral" not in content
        assert "mistral" not in content.lower()

    def test_target_read_from_notes_when_present(
        self,
        tmp_path: Path,
        sample_remediation_results,
        sample_verification_report,
    ) -> None:
        """Target propagates from raw_data.notes.target into the report."""
        from tests.remediation_engine.fixtures.sample_findings import make_finding

        findings = [
            make_finding(
                "LLM01",
                raw_data={"notes": {"target": "GPT-2 (custom-finetune)"}},
            )
        ]
        HtmlWriter().write(
            findings, sample_remediation_results, sample_verification_report, tmp_path
        )
        content = (tmp_path / "summary.html").read_text(encoding="utf-8")
        assert "GPT-2 (custom-finetune)" in content

    def test_researcher_read_from_notes_when_present(
        self,
        tmp_path: Path,
        sample_remediation_results,
        sample_verification_report,
    ) -> None:
        from tests.remediation_engine.fixtures.sample_findings import make_finding

        findings = [
            make_finding(
                "LLM01",
                raw_data={"notes": {"researcher": "A. Researcher"}},
            )
        ]
        HtmlWriter().write(
            findings, sample_remediation_results, sample_verification_report, tmp_path
        )
        content = (tmp_path / "summary.html").read_text(encoding="utf-8")
        assert "A. Researcher" in content

    def test_html_still_self_contained_no_external_resources(
        self,
        tmp_path: Path,
        sample_findings_list,
        sample_remediation_results,
        sample_verification_report,
    ) -> None:
        """No external CDN, no <script> — the GitHub link is the one https:// reference."""
        HtmlWriter().write(
            sample_findings_list,
            sample_remediation_results,
            sample_verification_report,
            tmp_path,
        )
        content = (tmp_path / "summary.html").read_text(encoding="utf-8")
        assert "<script>" not in content
        # The GitHub link is the only allowed outbound reference.
        outbound = [
            line
            for line in content.splitlines()
            if "http://" in line or ("https://" in line and "github.com" not in line)
        ]
        assert outbound == []

    def test_html_includes_print_media_query_for_pdf_friendly_layout(
        self,
        tmp_path: Path,
        sample_findings_list,
        sample_remediation_results,
        sample_verification_report,
    ) -> None:
        HtmlWriter().write(
            sample_findings_list,
            sample_remediation_results,
            sample_verification_report,
            tmp_path,
        )
        content = (tmp_path / "summary.html").read_text(encoding="utf-8")
        assert "@media print" in content

    def test_html_includes_mobile_responsive_breakpoint(
        self,
        tmp_path: Path,
        sample_findings_list,
        sample_remediation_results,
        sample_verification_report,
    ) -> None:
        HtmlWriter().write(
            sample_findings_list,
            sample_remediation_results,
            sample_verification_report,
            tmp_path,
        )
        content = (tmp_path / "summary.html").read_text(encoding="utf-8")
        assert "@media (max-width" in content
        assert "viewport" in content
