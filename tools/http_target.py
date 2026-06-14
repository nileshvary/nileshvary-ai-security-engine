"""Generic HTTP target adapter for RemediAX PyRIT scanning.

Satisfies the ``_MockTarget`` Protocol in ``tools/pyrit_runner.py``
(any object with ``respond(prompt: str) -> str``) so PyRITRunner can
send real attack probes to any JSON-based LLM HTTP endpoint.

Supported endpoint formats (auto-detected from URL):
  - OpenAI /v1/chat/completions  (GPT-4, Ollama, vLLM, LiteLLM, …)
  - Anthropic /v1/messages
  - Any simple REST API with a plain JSON request/response
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Response field extractors — tried in order, first non-empty value wins.
_EXTRACTORS = [
    # OpenAI-compatible: choices[0].message.content
    lambda d: d.get("choices", [{}])[0].get("message", {}).get("content"),
    # OpenAI legacy: choices[0].text
    lambda d: d.get("choices", [{}])[0].get("text"),
    # Anthropic: content[0].text
    lambda d: d.get("content", [{}])[0].get("text"),
    # Simple REST APIs
    lambda d: (
        d.get("response")
        or d.get("reply")
        or d.get("text")
        or d.get("output")
        or d.get("message")
        or d.get("answer")
        or d.get("result")
    ),
]


class HttpTarget:
    """Generic LLM HTTP target — works against any JSON REST endpoint.

    Auto-detects the request/response format from the URL. Falls back to
    configurable ``prompt_field`` / ``response_field`` for custom APIs.

    Args:
        url: Full URL of the LLM chat endpoint.
        prompt_field: JSON key for the user prompt in simple REST APIs.
                      Ignored when the URL implies OpenAI or Anthropic format.
                      Defaults to ``"message"``.
        response_field: JSON key to extract the reply from simple REST APIs.
                        Ignored when auto-detection succeeds.
        api_key: Bearer token sent in the ``Authorization`` header.
                 Leave empty for unauthenticated endpoints (e.g. local Ollama).
    """

    def __init__(
        self,
        url: str,
        prompt_field: str = "message",
        response_field: str = "",
        api_key: str = "",
    ) -> None:
        self.url = url
        self.prompt_field = prompt_field
        self.response_field = response_field
        self.api_key = api_key

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _default_model(self) -> str:
        """Pick a sensible default model name based on the target URL."""
        url = self.url.lower()
        if "mistral.ai" in url:
            return "mistral-small-latest"
        if "anthropic.com" in url:
            return "claude-3-haiku-20240307"
        if "openai.com" in url:
            return "gpt-3.5-turbo"
        if "googleapis.com" in url or "generativelanguage" in url:
            return "gemini-pro"
        # Local / other OpenAI-compatible (Ollama, vLLM, LiteLLM, etc.)
        return "default"

    def _build_body(self, prompt: str) -> dict[str, Any]:
        if "/chat/completions" in self.url or "/v1/chat" in self.url:
            return {
                "model": self._default_model(),
                "messages": [{"role": "user", "content": prompt}],
            }
        if "/v1/messages" in self.url:
            return {
                "model": self._default_model(),
                "max_tokens": 512,
                "messages": [{"role": "user", "content": prompt}],
            }
        # Simple or custom REST — use configured field name
        return {self.prompt_field: prompt}

    def _extract(self, data: dict[str, Any]) -> str:
        # Custom field override
        if self.response_field and self.response_field in data:
            return str(data[self.response_field])
        # Auto-detect
        for extractor in _EXTRACTORS:
            try:
                val = extractor(data)
                if val:
                    return str(val)
            except (IndexError, KeyError, TypeError):
                continue
        # Last resort — return the raw JSON so the detector still has something
        return str(data)

    # ------------------------------------------------------------------
    # _MockTarget Protocol
    # ------------------------------------------------------------------

    def respond(self, prompt: str) -> str:
        """Send ``prompt`` to the target URL and return the model's reply."""
        import requests  # lazy import — not everyone has requests at import time

        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        try:
            resp = requests.post(
                self.url,
                json=self._build_body(prompt),
                headers=headers,
                timeout=30,
            )
            resp.raise_for_status()
            return self._extract(resp.json())
        except Exception as exc:
            logger.warning("HttpTarget.respond error (%s): %s", self.url, exc)
            return ""
