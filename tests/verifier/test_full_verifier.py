"""Tests for the ``FullVerifier`` v1.0 stub."""

from __future__ import annotations

import pytest

from verifier.full_verifier import FullVerifier

from tests.verifier.fixtures.sample_remediation_results import (
    make_remediation_result,
)


def test_verify_raises_not_implemented_with_exact_message() -> None:
    verifier = FullVerifier()
    with pytest.raises(NotImplementedError) as exc_info:
        verifier.verify(make_remediation_result("LLM01"))
    assert str(exc_info.value) == (
        "FullVerifier requires garak integration via subprocess. "
        "Stub for v1.0 — implement in v1.1."
    )


def test_class_docstring_mentions_v1_1() -> None:
    assert FullVerifier.__doc__ is not None
    assert "v1.1" in FullVerifier.__doc__


def test_garak_runner_path_kwarg_accepted() -> None:
    verifier = FullVerifier()
    with pytest.raises(NotImplementedError):
        verifier.verify(
            make_remediation_result("LLM01"), garak_runner_path="/usr/local/bin/garak"
        )
