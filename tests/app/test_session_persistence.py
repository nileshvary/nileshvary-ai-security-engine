"""Tests for the HMAC-signed Firebase remember-me session tokens."""

from __future__ import annotations

import pytest

from auth.session_persistence import (
    SESSION_TTL_SECONDS,
    read_session_secret,
    sign_session,
    verify_session,
)


_SECRET = "test-secret-do-not-use-in-prod"


# ---------------------------------------------------------------------------
# sign_session
# ---------------------------------------------------------------------------


def test_sign_session_returns_four_pipe_delimited_fields() -> None:
    token = sign_session("uid-1", "a@b.com", secret=_SECRET, issued_at=1_000_000)
    parts = token.split("|")
    assert parts[:3] == ["uid-1", "a@b.com", "1000000"]
    assert len(parts) == 4
    assert len(parts[3]) == 64  # SHA-256 hex


def test_sign_session_is_deterministic_for_same_inputs() -> None:
    a = sign_session("uid", "e@x.com", secret=_SECRET, issued_at=42)
    b = sign_session("uid", "e@x.com", secret=_SECRET, issued_at=42)
    assert a == b


def test_sign_session_changes_with_secret() -> None:
    a = sign_session("uid", "e@x.com", secret="A", issued_at=42)
    b = sign_session("uid", "e@x.com", secret="B", issued_at=42)
    assert a != b


def test_sign_session_rejects_empty_secret() -> None:
    with pytest.raises(ValueError):
        sign_session("uid", "e@x.com", secret="")


def test_sign_session_rejects_delimiter_in_fields() -> None:
    with pytest.raises(ValueError):
        sign_session("uid|hack", "e@x.com", secret=_SECRET)
    with pytest.raises(ValueError):
        sign_session("uid", "e|hack@x.com", secret=_SECRET)


# ---------------------------------------------------------------------------
# verify_session — happy path + every rejection branch
# ---------------------------------------------------------------------------


def test_verify_session_roundtrip_returns_payload() -> None:
    token = sign_session("uid-99", "alice@example.com", secret=_SECRET, issued_at=100)
    out = verify_session(token, secret=_SECRET, now=200)
    assert out == {"uid": "uid-99", "email": "alice@example.com", "issued_at": 100}


def test_verify_session_rejects_tampered_signature() -> None:
    token = sign_session("uid", "e@x.com", secret=_SECRET, issued_at=100)
    tampered = token[:-1] + ("0" if token[-1] != "0" else "1")
    assert verify_session(tampered, secret=_SECRET, now=200) is None


def test_verify_session_rejects_tampered_uid() -> None:
    token = sign_session("victim", "e@x.com", secret=_SECRET, issued_at=100)
    parts = token.split("|")
    parts[0] = "attacker"
    forged = "|".join(parts)
    assert verify_session(forged, secret=_SECRET, now=200) is None


def test_verify_session_rejects_wrong_secret() -> None:
    token = sign_session("uid", "e@x.com", secret=_SECRET, issued_at=100)
    assert verify_session(token, secret="different-secret", now=200) is None


def test_verify_session_rejects_expired_token() -> None:
    token = sign_session("uid", "e@x.com", secret=_SECRET, issued_at=100)
    expired_now = 100 + SESSION_TTL_SECONDS + 1
    assert verify_session(token, secret=_SECRET, now=expired_now) is None


def test_verify_session_accepts_token_at_exact_ttl_boundary() -> None:
    token = sign_session("uid", "e@x.com", secret=_SECRET, issued_at=100)
    boundary = 100 + SESSION_TTL_SECONDS
    assert verify_session(token, secret=_SECRET, now=boundary) is not None


def test_verify_session_rejects_token_issued_in_future() -> None:
    token = sign_session("uid", "e@x.com", secret=_SECRET, issued_at=10_000)
    assert verify_session(token, secret=_SECRET, now=100) is None


def test_verify_session_rejects_malformed_inputs() -> None:
    assert verify_session("", secret=_SECRET) is None
    assert verify_session("not-a-token", secret=_SECRET) is None
    assert verify_session("a|b|c", secret=_SECRET) is None  # only 3 parts
    assert verify_session("a|b|notanumber|sig", secret=_SECRET) is None
    assert verify_session("a||100|sig", secret=_SECRET) is None  # empty email


def test_verify_session_rejects_empty_secret() -> None:
    token = sign_session("uid", "e@x.com", secret=_SECRET, issued_at=100)
    assert verify_session(token, secret="") is None


def test_verify_session_custom_ttl() -> None:
    token = sign_session("uid", "e@x.com", secret=_SECRET, issued_at=100)
    # 10-second TTL — token at t=200 is way past.
    assert verify_session(token, secret=_SECRET, now=200, ttl_seconds=10) is None
    assert verify_session(token, secret=_SECRET, now=105, ttl_seconds=10) is not None


# ---------------------------------------------------------------------------
# read_session_secret
# ---------------------------------------------------------------------------


def test_read_session_secret_returns_value() -> None:
    assert read_session_secret({"session": {"secret": "abc"}}) == "abc"


def test_read_session_secret_strips_whitespace() -> None:
    assert read_session_secret({"session": {"secret": "  abc  "}}) == "abc"


def test_read_session_secret_returns_none_when_missing() -> None:
    assert read_session_secret(None) is None
    assert read_session_secret({}) is None
    assert read_session_secret({"session": {}}) is None
    assert read_session_secret({"other": {"secret": "x"}}) is None


def test_read_session_secret_returns_none_when_empty() -> None:
    assert read_session_secret({"session": {"secret": ""}}) is None
    assert read_session_secret({"session": {"secret": "   "}}) is None
