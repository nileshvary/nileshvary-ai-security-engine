"""Tests for the LOG_ONLY sanitization-gate in components/finding_card.py.

Two kinds of test in here:

1. **Behavioral.** Monkeypatch ``streamlit`` so every render call is
   recorded as a string in a captured-payload list, then run
   ``render_patch_panel`` (the simpler of the two sanitization
   render paths) against LOG_ONLY / HARDEN / SANITIZE remediation
   results and assert the "Sanitization" block is present iff the
   strategy is not LOG_ONLY.

2. **AST guard.** Parse the source of ``render_active_finding`` and
   ``render_patch_panel`` and assert each function references
   ``RemediationStrategy.LOG_ONLY`` somewhere in its body — locks
   the gate in place so a future refactor can't silently regress.
"""

from __future__ import annotations

import ast
import inspect
from unittest.mock import MagicMock

import pytest

from components import finding_card as fc
from components.finding_card import render_patch_panel
from remediation_engine.models import RemediationStrategy

from tests.verifier.fixtures.sample_remediation_results import (
    make_remediation_result,
)


@pytest.fixture
def captured_streamlit(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Replace every render-side ``st.*`` call we touch with a recorder."""
    payloads: list[str] = []

    def record(*args: object, **kw: object) -> None:
        for arg in args:
            payloads.append(str(arg))
        for v in kw.values():
            payloads.append(str(v))

    # st.markdown and st.code both take a body string we want to scan.
    monkeypatch.setattr("streamlit.markdown", record)
    monkeypatch.setattr("streamlit.code", record)
    # The patch panel also calls st.info on the empty path.
    monkeypatch.setattr("streamlit.info", record)
    return payloads


# ---------------------------------------------------------------------------
# Behavioral — sanitization block visibility tracks strategy
# ---------------------------------------------------------------------------


def _logonly_result_with_sanitization():
    """Build an LLM03 LOG_ONLY result whose sanitization carries content.

    LLM03 defaults to LOG_ONLY in the fixtures; we then force the
    ``response_sanitization`` field to look like real remediator
    output ("flagged N occurrence(s)" comes from the remediator at
    runtime — we synthesize the equivalent shape here).
    """
    from remediation_engine.models import ResponseSanitization

    result = make_remediation_result("LLM03")
    # Frozen dataclass — bypass to attach a sanitization payload.
    object.__setattr__(
        result,
        "response_sanitization",
        ResponseSanitization(
            original_response="secret: AKIAIOSFODNN7EXAMPLE",
            sanitized_response="secret: [REDACTED]",
            detected_issues=["AWS key in response"],
            actions_taken=["flagged 1 AWS-key occurrence(s)"],
        ),
    )
    return result


def test_log_only_hides_sanitization_in_patch_panel(
    captured_streamlit: list[str],
) -> None:
    result = _logonly_result_with_sanitization()
    assert result.strategy == RemediationStrategy.LOG_ONLY

    render_patch_panel(result)

    joined = "\n".join(captured_streamlit)
    # Sanitization heading and "flagged ... occurrence(s)" actions must NOT appear.
    assert "Sanitization details" not in joined
    assert "flagged 1 AWS-key occurrence(s)" not in joined
    assert "AWS key in response" not in joined


def test_harden_shows_sanitization_in_patch_panel(
    captured_streamlit: list[str],
) -> None:
    """HARDEN strategy must still surface sanitization details."""
    from remediation_engine.models import ResponseSanitization

    result = make_remediation_result("LLM01")  # HARDEN by default
    object.__setattr__(
        result,
        "response_sanitization",
        ResponseSanitization(
            original_response="raw",
            sanitized_response="clean",
            detected_issues=["one finding"],
            actions_taken=["flagged 1 PII occurrence(s)"],
        ),
    )
    assert result.strategy == RemediationStrategy.HARDEN

    render_patch_panel(result)

    joined = "\n".join(captured_streamlit)
    assert "Sanitization details" in joined
    # And the before/after blocks render too.
    assert "Before:" in joined
    assert "After:" in joined


def test_sanitize_shows_sanitization_in_patch_panel(
    captured_streamlit: list[str],
) -> None:
    """LLM02 defaults to SANITIZE — the block stays visible."""
    result = make_remediation_result("LLM02")  # SANITIZE strategy
    assert result.strategy == RemediationStrategy.SANITIZE
    render_patch_panel(result)
    joined = "\n".join(captured_streamlit)
    # LLM02 sanitization has both detected_issues and actions_taken
    # populated by the fixture, so the block must render.
    assert "Sanitization details" in joined


def test_log_only_still_shows_guardrail_config_when_present(
    captured_streamlit: list[str],
) -> None:
    """The LOG_ONLY gate must not collateral-hide the guardrail config."""
    result = _logonly_result_with_sanitization()
    render_patch_panel(result)
    joined = "\n".join(captured_streamlit)
    # Either the guardrail-config heading shows up (fixture has yaml_export)
    # OR we get the "no additional remediation artifact" stub. Either
    # way, the function doesn't crash and at least some content lands.
    assert (
        "Guardrail config" in joined
        or "No additional remediation artifact" in joined
    )


# ---------------------------------------------------------------------------
# AST guard — regression lock
# ---------------------------------------------------------------------------


def _function_source(func) -> str:  # noqa: ANN001
    return inspect.getsource(func)


def _references_log_only(source: str) -> bool:
    """True when ``RemediationStrategy.LOG_ONLY`` appears in code (not docstrings)."""
    import textwrap

    tree = ast.parse(textwrap.dedent(source))
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and node.attr == "LOG_ONLY":
            # Must be an attribute on something named "RemediationStrategy".
            value = node.value
            if isinstance(value, ast.Name) and value.id == "RemediationStrategy":
                return True
    return False


def test_render_active_finding_gates_on_log_only_strategy() -> None:
    """``render_active_finding`` must check the LOG_ONLY strategy."""
    assert _references_log_only(_function_source(fc.render_active_finding)), (
        "render_active_finding no longer checks "
        "RemediationStrategy.LOG_ONLY — the sanitization block will "
        "leak into LOG_ONLY findings."
    )


def test_render_patch_panel_gates_on_log_only_strategy() -> None:
    """``render_patch_panel`` must check the LOG_ONLY strategy."""
    assert _references_log_only(_function_source(fc.render_patch_panel)), (
        "render_patch_panel no longer checks "
        "RemediationStrategy.LOG_ONLY — Sanitization details will "
        "appear in the View-patch panel for LOG_ONLY findings."
    )
