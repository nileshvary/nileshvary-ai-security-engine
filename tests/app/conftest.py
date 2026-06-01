"""Shared fixtures for the RemediAX app tests."""

from __future__ import annotations

from pathlib import Path

import pytest

from auth.rate_limiter import RateLimiter
from auth.token_manager import TokenManager


@pytest.fixture
def token_manager(tmp_path: Path) -> TokenManager:
    """A TokenManager bound to a clean tmp_path tokens file."""
    return TokenManager(tokens_file=tmp_path / "tokens.json")


@pytest.fixture
def rate_limiter(tmp_path: Path) -> RateLimiter:
    """A RateLimiter bound to a clean tmp_path usage file."""
    return RateLimiter(usage_file=tmp_path / ".remediax_usage.json")
