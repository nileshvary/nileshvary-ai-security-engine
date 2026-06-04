"""Tests for ``GuardrailGenerator`` YAML output across all three formats."""

from __future__ import annotations

import pytest
import yaml

from remediation_engine.guardrail_generator.generator import GuardrailGenerator

from tests.remediation_engine.fixtures.sample_findings import make_finding


@pytest.fixture
def generator() -> GuardrailGenerator:
    return GuardrailGenerator()


@pytest.fixture
def mixed_findings() -> list:
    return [make_finding("LLM01"), make_finding("LLM02"), make_finding("LLM10")]


class TestPortkeyFormat:
    def test_yaml_round_trips(
        self, generator: GuardrailGenerator, mixed_findings: list
    ) -> None:
        config = generator.generate(mixed_findings, output_format="portkey")
        parsed = yaml.safe_load(config.yaml_export)
        assert parsed["version"] == 1
        assert "input_guardrails" in parsed
        assert "output_guardrails" in parsed
        assert "rate_limits" in parsed
        assert "covered_owasp_categories" in parsed

    def test_input_filter_for_llm01(
        self, generator: GuardrailGenerator, mixed_findings: list
    ) -> None:
        config = generator.generate(mixed_findings, output_format="portkey")
        ids = [rule["id"] for rule in config.input_filters]
        assert "prompt-injection-defense" in ids

    def test_output_filter_for_llm02(
        self, generator: GuardrailGenerator, mixed_findings: list
    ) -> None:
        config = generator.generate(mixed_findings, output_format="portkey")
        ids = [rule["id"] for rule in config.output_filters]
        assert "pii-and-secrets-redaction" in ids

    def test_rate_limits_for_llm10(
        self, generator: GuardrailGenerator, mixed_findings: list
    ) -> None:
        config = generator.generate(mixed_findings, output_format="portkey")
        assert config.rate_limits["requests_per_minute"] == 60
        assert config.rate_limits["tokens_per_minute"] == 100_000

    def test_format_field_set(
        self, generator: GuardrailGenerator, mixed_findings: list
    ) -> None:
        config = generator.generate(mixed_findings, output_format="portkey")
        assert config.format == "portkey"


class TestLitellmFormat:
    def test_yaml_round_trips(
        self, generator: GuardrailGenerator, mixed_findings: list
    ) -> None:
        config = generator.generate(mixed_findings, output_format="litellm")
        parsed = yaml.safe_load(config.yaml_export)
        assert "guardrails" in parsed
        assert "router_settings" in parsed

    def test_guardrails_have_litellm_shape(
        self, generator: GuardrailGenerator, mixed_findings: list
    ) -> None:
        config = generator.generate(mixed_findings, output_format="litellm")
        parsed = yaml.safe_load(config.yaml_export)
        for rule in parsed["guardrails"]:
            assert "guardrail_name" in rule
            assert "litellm_params" in rule
            assert rule["litellm_params"]["mode"] in {"pre_call", "post_call"}

    def test_router_settings_carry_rate_limits(
        self, generator: GuardrailGenerator, mixed_findings: list
    ) -> None:
        config = generator.generate(mixed_findings, output_format="litellm")
        parsed = yaml.safe_load(config.yaml_export)
        assert parsed["router_settings"]["rpm"] == 60
        assert parsed["router_settings"]["tpm"] == 100_000


class TestGenericFormat:
    def test_yaml_round_trips(
        self, generator: GuardrailGenerator, mixed_findings: list
    ) -> None:
        config = generator.generate(mixed_findings, output_format="generic")
        parsed = yaml.safe_load(config.yaml_export)
        assert "input_filters" in parsed
        assert "output_filters" in parsed
        assert "rate_limits" in parsed


class TestCoverage:
    def test_no_findings_produces_empty_rules(
        self, generator: GuardrailGenerator
    ) -> None:
        config = generator.generate([], output_format="portkey")
        assert config.input_filters == []
        assert config.output_filters == []
        assert config.rate_limits == {}
        # YAML still parseable.
        yaml.safe_load(config.yaml_export)

    def test_llm05_adds_xss_output_filter(
        self, generator: GuardrailGenerator
    ) -> None:
        config = generator.generate(
            [make_finding("LLM05")], output_format="portkey"
        )
        ids = [r["id"] for r in config.output_filters]
        assert "xss-and-sqli-sanitization" in ids

    def test_covered_categories_lists_distinct_codes(
        self, generator: GuardrailGenerator
    ) -> None:
        findings = [make_finding("LLM01"), make_finding("LLM01"), make_finding("LLM05")]
        config = generator.generate(findings, output_format="generic")
        parsed = yaml.safe_load(config.yaml_export)
        assert parsed["covered_owasp_categories"] == ["LLM01", "LLM05"]


class TestInvalidFormat:
    def test_raises_value_error(self, generator: GuardrailGenerator) -> None:
        with pytest.raises(ValueError, match="unsupported output_format"):
            generator.generate([make_finding("LLM01")], output_format="bogus")


class TestAutonomousAIMode:
    """Generator merges Claude per-finding YAML when ai_client is provided."""

    def _fake_client(self, analyses: list[dict] | dict) -> object:
        """Return a stub ai_client whose generate_complete_analysis cycles
        through the supplied analyses (or returns the same one each call).
        """
        from unittest.mock import MagicMock

        client = MagicMock()
        if isinstance(analyses, dict):
            client.generate_complete_analysis.return_value = analyses
        else:
            client.generate_complete_analysis.side_effect = list(analyses)
        return client

    def test_no_ai_client_keeps_deterministic_behavior_unchanged(
        self, generator: GuardrailGenerator, mixed_findings: list
    ) -> None:
        """Backward-compat: existing call sites without ai_client are untouched."""
        before = generator.generate(mixed_findings, output_format="portkey")
        after = generator.generate(mixed_findings, output_format="portkey")
        # No Claude involvement, deterministic output.
        assert before.input_filters == after.input_filters
        assert before.output_filters == after.output_filters

    def test_ai_client_yaml_rules_get_appended(
        self, generator: GuardrailGenerator
    ) -> None:
        analysis = {
            "why_dangerous": "x",
            "why_fix_works": "y",
            "guardrail_yaml": (
                "input_guardrails:\n"
                "  - id: claude-prompt-injection-block\n"
                "    type: regex\n"
                "    patterns:\n"
                "      - 'jailbreak'\n"
                "    on_match: block\n"
                "output_guardrails:\n"
                "  - id: claude-pii-mask\n"
                "    type: regex\n"
                "    on_match: redact\n"
            ),
        }
        client = self._fake_client(analysis)
        config = generator.generate(
            [make_finding("LLM01")],
            output_format="portkey",
            ai_client=client,
        )
        input_ids = [r["id"] for r in config.input_filters]
        output_ids = [r["id"] for r in config.output_filters]
        assert "claude-prompt-injection-block" in input_ids
        assert "claude-pii-mask" in output_ids
        # Deterministic rule for LLM01 is still present alongside.
        assert "prompt-injection-defense" in input_ids

    def test_duplicate_ids_across_findings_are_deduped(
        self, generator: GuardrailGenerator
    ) -> None:
        analysis = {
            "guardrail_yaml": (
                "input_guardrails:\n"
                "  - id: claude-dedupe-me\n"
                "    type: regex\n"
                "    patterns: ['x']\n"
            ),
        }
        client = self._fake_client(analysis)
        config = generator.generate(
            [make_finding("LLM01"), make_finding("LLM01")],
            output_format="portkey",
            ai_client=client,
        )
        ids = [r["id"] for r in config.input_filters]
        assert ids.count("claude-dedupe-me") == 1

    def test_malformed_yaml_is_dropped_silently(
        self, generator: GuardrailGenerator
    ) -> None:
        """Bad YAML must not crash generate — we fall back to deterministic rules."""
        client = self._fake_client({"guardrail_yaml": "not: valid: yaml: ::: :"})
        # Should not raise.
        config = generator.generate(
            [make_finding("LLM01")],
            output_format="portkey",
            ai_client=client,
        )
        # The deterministic LLM01 rule still appears.
        ids = [r["id"] for r in config.input_filters]
        assert "prompt-injection-defense" in ids

    def test_rate_limits_use_min_when_multiple_findings_supply_them(
        self, generator: GuardrailGenerator
    ) -> None:
        analyses = [
            {
                "guardrail_yaml": (
                    "rate_limits:\n"
                    "  requests_per_minute: 30\n"
                    "  tokens_per_minute: 200000\n"
                ),
            },
            {
                "guardrail_yaml": (
                    "rate_limits:\n"
                    "  requests_per_minute: 90\n"
                    "  tokens_per_minute: 50000\n"
                ),
            },
        ]
        client = self._fake_client(analyses)
        config = generator.generate(
            # Use two LLM10 findings so deterministic rate limits also
            # populate; the autonomous merger then takes the minimum
            # against those.
            [make_finding("LLM10"), make_finding("LLM10")],
            output_format="portkey",
            ai_client=client,
        )
        # Deterministic LLM10 starts at requests_per_minute=60,
        # tokens_per_minute=100_000. Claude proposed (30, 200k) and
        # (90, 50k). Strictest values per key:
        #   requests_per_minute: min(60, 30, 90) = 30
        #   tokens_per_minute: min(100_000, 200_000, 50_000) = 50_000
        assert config.rate_limits["requests_per_minute"] == 30
        assert config.rate_limits["tokens_per_minute"] == 50_000

    def test_ai_call_failure_does_not_abort_generation(
        self, generator: GuardrailGenerator
    ) -> None:
        from unittest.mock import MagicMock

        client = MagicMock()
        client.generate_complete_analysis.return_value = None  # parse failure
        config = generator.generate(
            [make_finding("LLM01")],
            output_format="portkey",
            ai_client=client,
        )
        # Deterministic LLM01 rule still emitted.
        ids = [r["id"] for r in config.input_filters]
        assert "prompt-injection-defense" in ids


class TestAgenticGuardrails:
    """OWASP Agentic Top 10 (2026) policy rules emitted alongside LLM rules."""

    def test_asi02_adds_tool_authorization_input_rule(
        self, generator: GuardrailGenerator
    ) -> None:
        finding = make_finding(
            "LLM06",
            owasp_agentic_categories=["ASI03", "ASI02"],
        )
        config = generator.generate([finding], output_format="portkey")
        ids = [r["id"] for r in config.input_filters]
        assert "asi02-tool-authorization" in ids

    def test_asi02_adds_tool_audit_output_rule(
        self, generator: GuardrailGenerator
    ) -> None:
        finding = make_finding(
            "LLM06",
            owasp_agentic_categories=["ASI02"],
        )
        config = generator.generate([finding], output_format="portkey")
        ids = [r["id"] for r in config.output_filters]
        assert "asi02-tool-call-audit" in ids

    def test_asi07_emits_signed_message_policy(
        self, generator: GuardrailGenerator
    ) -> None:
        finding = make_finding(
            "LLM06",
            owasp_agentic_categories=["ASI07"],
        )
        config = generator.generate([finding], output_format="portkey")
        ids = [r["id"] for r in config.input_filters]
        assert "asi07-inter-agent-trust" in ids
        # Pattern text should mention signing somewhere.
        rule = next(r for r in config.input_filters if r["id"] == "asi07-inter-agent-trust")
        assert any("signature" in p.lower() for p in rule["patterns"])

    def test_asi10_emits_behavioral_monitoring_policy(
        self, generator: GuardrailGenerator
    ) -> None:
        finding = make_finding(
            "LLM06",
            owasp_agentic_categories=["ASI10"],
        )
        config = generator.generate([finding], output_format="portkey")
        ids = [r["id"] for r in config.input_filters]
        assert "asi10-behavioral-monitoring" in ids

    def test_no_asi_findings_means_no_asi_rules(
        self, generator: GuardrailGenerator
    ) -> None:
        """Pure LLM-only findings must not leak ASI policy rules."""
        config = generator.generate(
            [make_finding("LLM02")], output_format="portkey"
        )
        for rule in config.input_filters + config.output_filters:
            assert not rule["id"].startswith("asi")

    def test_covered_agentic_categories_lists_distinct_codes(
        self, generator: GuardrailGenerator
    ) -> None:
        findings = [
            make_finding("LLM06", owasp_agentic_categories=["ASI03", "ASI02"]),
            make_finding("LLM06", owasp_agentic_categories=["ASI02", "ASI10"]),
        ]
        config = generator.generate(findings, output_format="portkey")
        parsed = yaml.safe_load(config.yaml_export)
        assert parsed["covered_agentic_categories"] == ["ASI02", "ASI03", "ASI10"]

    def test_asi_rules_are_deterministic_order(
        self, generator: GuardrailGenerator
    ) -> None:
        """Independent of finding-list ordering, ASI rules emit in ASI01..ASI10 order."""
        findings = [
            make_finding("LLM06", owasp_agentic_categories=["ASI10"]),
            make_finding("LLM06", owasp_agentic_categories=["ASI02"]),
            make_finding("LLM06", owasp_agentic_categories=["ASI07"]),
        ]
        config = generator.generate(findings, output_format="portkey")
        asi_ids = [r["id"] for r in config.input_filters if r["id"].startswith("asi")]
        # Sorted ASI order regardless of input.
        assert asi_ids == [
            "asi02-tool-authorization",
            "asi07-inter-agent-trust",
            "asi10-behavioral-monitoring",
        ]
