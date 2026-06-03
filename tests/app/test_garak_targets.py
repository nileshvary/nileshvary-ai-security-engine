"""Tests for the Garak Scanner provider catalog + command builder."""

from __future__ import annotations

import pytest

from components.garak_targets import (
    PROVIDERS_BY_TARGET,
    TARGET_TYPES,
    build_command,
    get_provider,
)


# ---------------------------------------------------------------------------
# Catalog shape — every target the spec calls out is present
# ---------------------------------------------------------------------------


def test_all_five_target_types_present() -> None:
    assert TARGET_TYPES == (
        "LLM Model",
        "AI Agent",
        "REST API Endpoint",
        "Chatbot Application",
        "Custom Python Function",
    )


@pytest.mark.parametrize("target", TARGET_TYPES)
def test_every_target_has_an_other_custom_entry(target: str) -> None:
    providers = PROVIDERS_BY_TARGET[target]
    customs = [p for p in providers if p.is_custom]
    assert len(customs) == 1, f"{target} must expose exactly one Other/Custom entry"
    assert customs[0] is providers[-1], "Other/Custom must be the last radio option"


def test_llm_model_includes_all_spec_providers() -> None:
    labels = [p.label for p in PROVIDERS_BY_TARGET["LLM Model"]]
    for expected in (
        "OpenAI GPT-4",
        "OpenAI GPT-3.5",
        "Anthropic Claude 3",
        "Google Gemini Pro",
        "Meta Llama 3",
        "Mistral 7B",
        "Hugging Face GPT-2",
        "Hugging Face OPT-125M",
        "Hugging Face DialoGPT",
        "Hugging Face GPT-J",
        "Cohere Command",
        "AWS Bedrock",
        "Azure OpenAI",
        "Other/Custom Model",
    ):
        assert expected in labels, f"missing LLM provider: {expected}"


def test_huggingface_free_models_flagged_is_free() -> None:
    for label in (
        "Hugging Face GPT-2",
        "Hugging Face OPT-125M",
        "Hugging Face DialoGPT",
        "Hugging Face GPT-J",
    ):
        p = get_provider("LLM Model", label)
        assert p is not None, f"missing free provider: {label}"
        assert p.is_free is True, f"{label} must be flagged is_free"
        assert p.api_key_env == "", f"{label} must not declare an api_key_env"


def test_paid_llm_providers_carry_api_key_env() -> None:
    for label in (
        "OpenAI GPT-4",
        "OpenAI GPT-3.5",
        "Anthropic Claude 3",
        "Google Gemini Pro",
        "Cohere Command",
        "AWS Bedrock",
        "Azure OpenAI",
    ):
        p = get_provider("LLM Model", label)
        assert p is not None
        assert p.api_key_env, f"{label} should declare an api_key_env"


def test_chatbot_providers_match_spec() -> None:
    labels = [p.label for p in PROVIDERS_BY_TARGET["Chatbot Application"]]
    for expected in (
        "Slack Bot",
        "Discord Bot",
        "Microsoft Teams Bot",
        "WhatsApp Bot",
        "Telegram Bot",
        "Intercom",
        "Zendesk",
        "Salesforce Einstein Bot",
        "HubSpot Chatbot",
        "Drift",
        "Other/Custom Chatbot",
    ):
        assert expected in labels


def test_ai_agent_includes_autogen_llamaindex_haystack_semantic_kernel() -> None:
    labels = [p.label for p in PROVIDERS_BY_TARGET["AI Agent"]]
    for expected in (
        "LangChain Agent",
        "AutoGPT",
        "CrewAI",
        "Microsoft AutoGen",
        "LlamaIndex Agent",
        "Haystack Agent",
        "Semantic Kernel",
        "Other/Custom Agent",
    ):
        assert expected in labels


def test_rest_api_includes_all_five_frameworks() -> None:
    labels = [p.label for p in PROVIDERS_BY_TARGET["REST API Endpoint"]]
    for expected in (
        "FastAPI endpoint",
        "Flask endpoint",
        "Django REST endpoint",
        "Express.js endpoint",
        "Spring Boot endpoint",
        "Other/Custom endpoint",
    ):
        assert expected in labels


def test_python_function_includes_all_six_kinds() -> None:
    labels = [p.label for p in PROVIDERS_BY_TARGET["Custom Python Function"]]
    for expected in (
        "Standard Python function",
        "Async Python function",
        "Class method",
        "FastAPI route handler",
        "Flask route handler",
        "Other/Custom",
    ):
        assert expected in labels


def test_get_provider_returns_none_for_unknown_label() -> None:
    assert get_provider("LLM Model", "made up") is None
    assert get_provider("nonexistent target", "OpenAI GPT-4") is None


# ---------------------------------------------------------------------------
# build_command — spec command formats
# ---------------------------------------------------------------------------


def test_openai_gpt4_renders_spec_command() -> None:
    p = get_provider("LLM Model", "OpenAI GPT-4")
    assert p is not None
    export, cmd = build_command(p, probe_codes=["dan", "promptinject"])
    assert export == 'export OPENAI_API_KEY="your-key-here"'
    assert cmd == (
        "python -m garak --target_type openai --target_name gpt-4 "
        "--probes dan,promptinject"
    )


def test_openai_gpt35_uses_gpt35_turbo_target_name() -> None:
    p = get_provider("LLM Model", "OpenAI GPT-3.5")
    assert p is not None
    _, cmd = build_command(p, probe_codes=["dan"])
    assert "--target_name gpt-3.5-turbo" in cmd
    assert "--target_type openai" in cmd


def test_anthropic_renders_spec_command() -> None:
    p = get_provider("LLM Model", "Anthropic Claude 3")
    assert p is not None
    export, cmd = build_command(p, probe_codes=["dan", "promptinject"])
    assert export == 'export ANTHROPIC_API_KEY="your-key-here"'
    assert cmd == (
        "python -m garak --target_type anthropic "
        "--target_name claude-3-opus-20240229 --probes dan,promptinject"
    )


def test_huggingface_gpt2_free_renders_spec_command_without_export() -> None:
    p = get_provider("LLM Model", "Hugging Face GPT-2")
    assert p is not None
    export, cmd = build_command(p, probe_codes=["dan", "encoding", "promptinject"])
    assert export is None, "free models must not prompt for an API key"
    assert cmd == (
        "python -m garak --target_type huggingface --target_name gpt2 "
        "--probes dan,encoding,promptinject"
    )


def test_rest_endpoint_renders_spec_command_with_duplicate_target_type_flag() -> None:
    p = get_provider("REST API Endpoint", "FastAPI endpoint")
    assert p is not None
    export, cmd = build_command(p, probe_codes=["dan", "promptinject"])
    assert export is None
    # The spec explicitly includes both --target_type flags.
    assert "--target_type rest --target_type rest.RestGenerator" in cmd
    assert "--uri YOUR_ENDPOINT_URL" in cmd
    assert "--probes dan,promptinject" in cmd


def test_chatbot_provider_uses_rest_command() -> None:
    p = get_provider("Chatbot Application", "Slack Bot")
    assert p is not None
    _, cmd = build_command(p, probe_codes=["dan"])
    assert "--target_type rest --target_type rest.RestGenerator" in cmd


def test_function_provider_emits_wrapper_helper_comment_and_function_command() -> None:
    p = get_provider("AI Agent", "LangChain Agent")
    assert p is not None
    _, cmd = build_command(p, probe_codes=["dan"])
    assert "def call(prompt: str) -> str" in cmd
    assert (
        "python -m garak --target_type function --target_name agent_wrap.call --probes dan"
        in cmd
    )


def test_deprecated_model_type_flag_is_never_emitted() -> None:
    """No spec command should leak the deprecated --model_type / --model_name flags."""
    for target, providers in PROVIDERS_BY_TARGET.items():  # noqa: B007
        for provider in providers:
            _, cmd = build_command(
                provider,
                probe_codes=["dan"],
                custom={
                    "model_type": "openai",
                    "model_name": "gpt-4",
                    "endpoint_url": "https://x",
                    "function_path": "m.call",
                },
            )
            assert "--model_type" not in cmd, f"{provider.label} emits deprecated flag"
            assert "--model_name" not in cmd, f"{provider.label} emits deprecated flag"


def test_no_probes_omits_probes_flag_entirely() -> None:
    p = get_provider("LLM Model", "OpenAI GPT-4")
    assert p is not None
    _, cmd = build_command(p, probe_codes=[])
    assert "--probes" not in cmd


# ---------------------------------------------------------------------------
# build_command — Other/Custom branches
# ---------------------------------------------------------------------------


def test_custom_model_uses_user_supplied_type_and_name() -> None:
    p = get_provider("LLM Model", "Other/Custom Model")
    assert p is not None
    export, cmd = build_command(
        p,
        probe_codes=["dan"],
        custom={"model_type": "replicate", "model_name": "meta/llama-2-70b-chat"},
    )
    assert export is None  # no api_key passed
    assert cmd == (
        "python -m garak --target_type replicate "
        "--target_name meta/llama-2-70b-chat --probes dan"
    )


def test_custom_model_with_api_key_emits_export_line() -> None:
    p = get_provider("LLM Model", "Other/Custom Model")
    assert p is not None
    export, _ = build_command(
        p,
        probe_codes=["dan"],
        custom={"model_type": "openai", "model_name": "gpt-4o", "api_key": "sk-abc"},
    )
    # Env var guessed from model_type.
    assert export == 'export OPENAI_API_KEY="sk-abc"'


def test_custom_model_with_unknown_type_falls_back_to_generic_env_var() -> None:
    p = get_provider("LLM Model", "Other/Custom Model")
    assert p is not None
    export, _ = build_command(
        p,
        probe_codes=[],
        custom={"model_type": "exotic", "model_name": "weird", "api_key": "k"},
    )
    assert export == 'export MODEL_API_KEY="k"'


def test_custom_model_empty_inputs_uses_placeholder_tokens() -> None:
    p = get_provider("LLM Model", "Other/Custom Model")
    assert p is not None
    _, cmd = build_command(p, probe_codes=[])
    # Placeholder fallback with the current --target_* flags.
    assert "--target_type [their type]" in cmd
    assert "--target_name [their name]" in cmd


def test_custom_rest_uses_user_supplied_url() -> None:
    p = get_provider("REST API Endpoint", "Other/Custom endpoint")
    assert p is not None
    _, cmd = build_command(
        p,
        probe_codes=["dan"],
        custom={"endpoint_url": "https://api.mycorp.com/chat"},
    )
    assert "--uri https://api.mycorp.com/chat" in cmd
    assert "--target_type rest --target_type rest.RestGenerator" in cmd


def test_custom_rest_with_auth_header_emits_comment_hint() -> None:
    p = get_provider("Chatbot Application", "Other/Custom Chatbot")
    assert p is not None
    _, cmd = build_command(
        p,
        probe_codes=[],
        custom={"endpoint_url": "https://hooks.example/bot", "auth_token": "Bearer X"},
    )
    assert "# Auth header / token: Bearer X" in cmd
    assert "--uri https://hooks.example/bot" in cmd


def test_custom_function_uses_user_supplied_path() -> None:
    p = get_provider("Custom Python Function", "Other/Custom")
    assert p is not None
    _, cmd = build_command(
        p,
        probe_codes=["dan"],
        custom={"function_path": "my_pkg.handlers.scan"},
    )
    assert "--target_name my_pkg.handlers.scan" in cmd
    assert "def call(prompt: str) -> str" in cmd
