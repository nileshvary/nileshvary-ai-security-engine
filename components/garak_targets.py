"""Catalog + command builder for the Garak Scanner wizard.

The Scanner page lets a user pick (1) a target type and (2) a
specific provider inside that target type, then renders ready-to-run
``python -m garak`` commands. The provider list per target — plus
the exact command format for each — lives here, in a pure-Python
module so it can be unit-tested without spinning up Streamlit.

Public surface:
    * ``Provider`` — dataclass describing one radio option.
    * ``PROVIDERS_BY_TARGET`` — mapping ``target_label -> [Provider, ...]``.
    * ``TARGET_TYPES`` — ordered list of target labels (UI radio order).
    * ``get_provider(target, label)`` — lookup helper.
    * ``build_command(provider, *, probe_codes, custom)`` — returns
      ``(export_line_or_None, garak_command_string)``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Literal

# kind = "model"            → python -m garak --model_type X --model_name Y
# kind = "rest"             → python -m garak --model_type rest
#                                  --model_type rest.RestGenerator --uri Z
# kind = "function"         → python -m garak --model_type function
#                                  --model_name module.call
# kind = "custom_model"     → caller supplies model_type + model_name
# kind = "custom_rest"      → caller supplies endpoint URL
# kind = "custom_function"  → caller supplies module.call path
ProviderKind = Literal[
    "model", "rest", "function",
    "custom_model", "custom_rest", "custom_function",
]


@dataclass(frozen=True)
class Provider:
    """One selectable provider inside a target-type wizard step."""

    label: str
    kind: ProviderKind = "model"
    model_type: str = ""        # for kind="model"
    model_name: str = ""        # for kind="model"
    api_key_env: str = ""       # env var to export, e.g. "OPENAI_API_KEY"
    is_free: bool = False       # render the FREE badge
    is_custom: bool = False     # show the "Other/Custom" text inputs
    # Free-form hint shown alongside the radio in the UI.
    note: str = ""


# ---------------------------------------------------------------------------
# Catalog — one list per target type
# ---------------------------------------------------------------------------

_LLM_MODEL_PROVIDERS: tuple[Provider, ...] = (
    Provider(
        label="OpenAI GPT-4",
        kind="model",
        model_type="openai",
        model_name="gpt-4",
        api_key_env="OPENAI_API_KEY",
    ),
    Provider(
        label="OpenAI GPT-3.5",
        kind="model",
        model_type="openai",
        model_name="gpt-3.5-turbo",
        api_key_env="OPENAI_API_KEY",
    ),
    Provider(
        label="Anthropic Claude 3",
        kind="model",
        model_type="anthropic",
        model_name="claude-3-opus-20240229",
        api_key_env="ANTHROPIC_API_KEY",
    ),
    Provider(
        label="Google Gemini Pro",
        kind="model",
        model_type="googleai",
        model_name="gemini-pro",
        api_key_env="GOOGLE_API_KEY",
    ),
    Provider(
        label="Meta Llama 3",
        kind="model",
        model_type="huggingface",
        model_name="meta-llama/Meta-Llama-3-8B-Instruct",
        api_key_env="HUGGINGFACE_API_KEY",
    ),
    Provider(
        label="Mistral 7B",
        kind="model",
        model_type="huggingface",
        model_name="mistralai/Mistral-7B-Instruct-v0.2",
        api_key_env="HUGGINGFACE_API_KEY",
    ),
    Provider(
        label="Hugging Face GPT-2",
        kind="model",
        model_type="huggingface",
        model_name="gpt2",
        is_free=True,
    ),
    Provider(
        label="Hugging Face OPT-125M",
        kind="model",
        model_type="huggingface",
        model_name="facebook/opt-125m",
        is_free=True,
    ),
    Provider(
        label="Hugging Face DialoGPT",
        kind="model",
        model_type="huggingface",
        model_name="microsoft/DialoGPT-medium",
        is_free=True,
    ),
    Provider(
        label="Hugging Face GPT-J",
        kind="model",
        model_type="huggingface",
        model_name="EleutherAI/gpt-j-6B",
        is_free=True,
    ),
    Provider(
        label="Cohere Command",
        kind="model",
        model_type="cohere",
        model_name="command",
        api_key_env="COHERE_API_KEY",
    ),
    Provider(
        label="AWS Bedrock",
        kind="model",
        model_type="bedrock",
        model_name="anthropic.claude-v2",
        api_key_env="AWS_ACCESS_KEY_ID",
    ),
    Provider(
        label="Azure OpenAI",
        kind="model",
        model_type="openai.azure",
        model_name="gpt-4",
        api_key_env="AZURE_OPENAI_API_KEY",
    ),
    Provider(label="Other/Custom Model", kind="custom_model", is_custom=True),
)

_AI_AGENT_PROVIDERS: tuple[Provider, ...] = (
    Provider(label="LangChain Agent", kind="function"),
    Provider(label="AutoGPT", kind="function"),
    Provider(label="CrewAI", kind="function"),
    Provider(label="Microsoft AutoGen", kind="function"),
    Provider(label="LlamaIndex Agent", kind="function"),
    Provider(label="Haystack Agent", kind="function"),
    Provider(label="Semantic Kernel", kind="function"),
    Provider(label="Other/Custom Agent", kind="custom_function", is_custom=True),
)

_REST_API_PROVIDERS: tuple[Provider, ...] = (
    Provider(label="FastAPI endpoint", kind="rest"),
    Provider(label="Flask endpoint", kind="rest"),
    Provider(label="Django REST endpoint", kind="rest"),
    Provider(label="Express.js endpoint", kind="rest"),
    Provider(label="Spring Boot endpoint", kind="rest"),
    Provider(label="Other/Custom endpoint", kind="custom_rest", is_custom=True),
)

_CHATBOT_PROVIDERS: tuple[Provider, ...] = (
    Provider(label="Slack Bot", kind="rest"),
    Provider(label="Discord Bot", kind="rest"),
    Provider(label="Microsoft Teams Bot", kind="rest"),
    Provider(label="WhatsApp Bot", kind="rest"),
    Provider(label="Telegram Bot", kind="rest"),
    Provider(label="Intercom", kind="rest"),
    Provider(label="Zendesk", kind="rest"),
    Provider(label="Salesforce Einstein Bot", kind="rest"),
    Provider(label="HubSpot Chatbot", kind="rest"),
    Provider(label="Drift", kind="rest"),
    Provider(label="Other/Custom Chatbot", kind="custom_rest", is_custom=True),
)

_PYTHON_FUNCTION_PROVIDERS: tuple[Provider, ...] = (
    Provider(label="Standard Python function", kind="function"),
    Provider(label="Async Python function", kind="function"),
    Provider(label="Class method", kind="function"),
    Provider(label="FastAPI route handler", kind="function"),
    Provider(label="Flask route handler", kind="function"),
    Provider(label="Other/Custom", kind="custom_function", is_custom=True),
)


PROVIDERS_BY_TARGET: dict[str, tuple[Provider, ...]] = {
    "LLM Model": _LLM_MODEL_PROVIDERS,
    "AI Agent": _AI_AGENT_PROVIDERS,
    "REST API Endpoint": _REST_API_PROVIDERS,
    "Chatbot Application": _CHATBOT_PROVIDERS,
    "Custom Python Function": _PYTHON_FUNCTION_PROVIDERS,
}

TARGET_TYPES: tuple[str, ...] = tuple(PROVIDERS_BY_TARGET.keys())


def get_provider(target: str, label: str) -> Provider | None:
    """Return the Provider matching ``label`` under ``target``, or ``None``."""
    for p in PROVIDERS_BY_TARGET.get(target, ()):
        if p.label == label:
            return p
    return None


# ---------------------------------------------------------------------------
# Command builder
# ---------------------------------------------------------------------------


def _probe_flag(probe_codes: list[str]) -> str:
    """Return the trailing ``--probes ...`` flag (empty if no probes selected)."""
    if not probe_codes:
        return ""
    return f" --probes {','.join(probe_codes)}"


def build_command(
    provider: Provider,
    *,
    probe_codes: list[str],
    custom: dict[str, str] | None = None,
) -> tuple[str | None, str]:
    """Return ``(export_line_or_None, garak_command_string)`` for a provider.

    Output format uses garak's current ``--target_type`` /
    ``--target_name`` flags (the deprecated ``--model_type`` /
    ``--model_name`` aliases are avoided so users on recent garak
    don't see deprecation warnings):

        For Hugging Face GPT-2 (free):
            python -m garak --target_type huggingface --target_name gpt2 --probes dan,...

        For OpenAI:
            export OPENAI_API_KEY="your-key-here"
            python -m garak --target_type openai --target_name gpt-4 --probes ...

        For REST endpoint:
            python -m garak --target_type rest --target_type rest.RestGenerator
                --uri https://... --probes ...

        For Custom/Other:
            python -m garak --target_type <user_type> --target_name <user_name>
                --probes ...

    Args:
        provider: One of the entries returned by ``PROVIDERS_BY_TARGET``.
        probe_codes: Garak probe identifiers selected in step 3.
        custom: Free-form user-supplied fields for ``is_custom`` providers.
            Recognized keys: ``model_type``, ``model_name``, ``api_key``,
            ``endpoint_url``, ``auth_header``, ``auth_token``,
            ``framework_name``, ``platform_name``, ``function_path``.

    Returns:
        A 2-tuple ``(export_line, command_line)``. ``export_line`` is
        ``None`` when no environment variable is required (free models,
        REST endpoints, function wrappers without an explicit API
        key). ``command_line`` is the full ``python -m garak ...``
        invocation, with newlines for any helper comments.
    """
    custom = custom or {}
    probes = _probe_flag(probe_codes)

    if provider.is_custom:
        return _build_custom_command(provider, custom, probes)

    if provider.kind == "model":
        export = _export_for(provider.api_key_env) if provider.api_key_env else None
        cmd = (
            f"python -m garak --target_type {provider.model_type} "
            f"--target_name {provider.model_name}{probes}"
        )
        return (export, cmd)

    if provider.kind == "rest":
        # The duplicate --target_type is intentional and matches the
        # product spec verbatim ("--target_type rest --target_type
        # rest.RestGenerator"). Garak accepts the second flag as the
        # generator class to load.
        cmd = (
            f"python -m garak --target_type rest "
            f"--target_type rest.RestGenerator "
            f"--uri YOUR_ENDPOINT_URL{probes}"
        )
        return (None, cmd)

    if provider.kind == "function":
        # Agents and Python functions require a thin wrapper file
        # exposing a top-level ``call(prompt: str) -> str``. The
        # comment block above the command documents that contract so
        # the generated snippet is self-explanatory.
        cmd = (
            "# Save the following as agent_wrap.py:\n"
            "# def call(prompt: str) -> str:\n"
            "#     return your_agent_or_function(prompt)\n"
            "\n"
            f"python -m garak --target_type function "
            f"--target_name agent_wrap.call{probes}"
        )
        return (None, cmd)

    # Fallback — should be unreachable given the Literal kind.
    return (None, f"python -m garak{probes}")


def _build_custom_command(
    provider: Provider, custom: dict[str, str], probes: str
) -> tuple[str | None, str]:
    """Build the command for the Other/Custom branches."""
    if provider.kind == "custom_model":
        model_type = (custom.get("model_type") or "[their type]").strip() or "[their type]"
        model_name = (custom.get("model_name") or "[their name]").strip() or "[their name]"
        api_key = (custom.get("api_key") or "").strip()
        export: str | None = None
        if api_key:
            # If the user pasted a key we can't infer the env-var name,
            # so fall back to a sensible default per model type.
            env_guess = _guess_api_key_env(model_type)
            export = f'export {env_guess}="{api_key}"'
        cmd = (
            f"python -m garak --target_type {model_type} "
            f"--target_name {model_name}{probes}"
        )
        return (export, cmd)

    if provider.kind == "custom_rest":
        endpoint = (custom.get("endpoint_url") or "[their URL]").strip() or "[their URL]"
        auth_header = (custom.get("auth_header") or custom.get("auth_token") or "").strip()
        prefix = ""
        if auth_header:
            # Comment-only hint; garak's REST generator reads headers
            # from a config file rather than the CLI, so we surface
            # the value as a TODO instead of a real flag.
            prefix = (
                f"# Auth header / token: {auth_header}\n"
                "# Configure this in your garak rest generator config "
                "(see garak docs for rest.RestGenerator).\n"
            )
        cmd = (
            f"{prefix}python -m garak --target_type rest "
            f"--target_type rest.RestGenerator "
            f"--uri {endpoint}{probes}"
        )
        return (None, cmd)

    if provider.kind == "custom_function":
        path = (
            custom.get("function_path")
            or custom.get("framework_name")
            or "your_module.call"
        ).strip() or "your_module.call"
        cmd = (
            "# Save the following as agent_wrap.py (or use your own module):\n"
            "# def call(prompt: str) -> str:\n"
            "#     return your_agent(prompt)\n"
            "\n"
            f"python -m garak --target_type function "
            f"--target_name {path}{probes}"
        )
        return (None, cmd)

    return (None, f"python -m garak{probes}")


def _export_for(env_var: str) -> str:
    """Return the ``export VAR="your-key-here"`` line for ``env_var``."""
    return f'export {env_var}="your-key-here"'


_API_KEY_ENV_GUESSES: dict[str, str] = {
    "openai": "OPENAI_API_KEY",
    "openai.azure": "AZURE_OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "googleai": "GOOGLE_API_KEY",
    "huggingface": "HUGGINGFACE_API_KEY",
    "cohere": "COHERE_API_KEY",
    "bedrock": "AWS_ACCESS_KEY_ID",
    "replicate": "REPLICATE_API_TOKEN",
}


def _guess_api_key_env(model_type: str) -> str:
    """Best-effort env-var name for a user-supplied model_type."""
    return _API_KEY_ENV_GUESSES.get(model_type.lower(), "MODEL_API_KEY")
