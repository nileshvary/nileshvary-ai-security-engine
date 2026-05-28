"""Shared pytest fixtures for integration_bridge tests."""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def sample_hitlog_path() -> Path:
    """Return the path to the sample garak hitlog fixture."""
    return Path(__file__).parent / "fixtures" / "sample_hitlog.jsonl"
