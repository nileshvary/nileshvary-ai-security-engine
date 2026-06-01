"""Tests for the per-token daily scan cap."""

from __future__ import annotations

from auth.rate_limiter import DAILY_CAP, RateLimiter


def test_first_three_calls_allowed(rate_limiter: RateLimiter) -> None:
    for expected_used in range(1, DAILY_CAP + 1):
        allowed, used, cap = rate_limiter.check_and_increment(
            "tok123", has_api_key=False
        )
        assert allowed is True
        assert used == expected_used
        assert cap == DAILY_CAP


def test_fourth_call_blocked(rate_limiter: RateLimiter) -> None:
    for _ in range(DAILY_CAP):
        rate_limiter.check_and_increment("tok123", has_api_key=False)
    allowed, used, cap = rate_limiter.check_and_increment(
        "tok123", has_api_key=False
    )
    assert allowed is False
    assert used == DAILY_CAP
    assert cap == DAILY_CAP


def test_api_mode_bypasses_cap(rate_limiter: RateLimiter) -> None:
    for _ in range(10):
        allowed, _, _ = rate_limiter.check_and_increment(
            "tokAPI", has_api_key=True
        )
        assert allowed is True


def test_different_tokens_counted_independently(rate_limiter: RateLimiter) -> None:
    for _ in range(DAILY_CAP):
        rate_limiter.check_and_increment("tok-a", has_api_key=False)
    # tok-b should still have full quota.
    allowed, used, _ = rate_limiter.check_and_increment(
        "tok-b", has_api_key=False
    )
    assert allowed is True
    assert used == 1


def test_usage_today_observes_increments(rate_limiter: RateLimiter) -> None:
    assert rate_limiter.usage_today("tokX") == 0
    rate_limiter.check_and_increment("tokX", has_api_key=False)
    rate_limiter.check_and_increment("tokX", has_api_key=False)
    assert rate_limiter.usage_today("tokX") == 2
