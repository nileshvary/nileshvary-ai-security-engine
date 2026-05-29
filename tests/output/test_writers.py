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
        assert "http://" not in content  # no external CDN
        assert "https://" not in content

    def test_html_includes_overall_improvement(
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
        expected = f"{sample_verification_report.overall_improvement_percent:.1f}% overall improvement"
        assert expected in content

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
