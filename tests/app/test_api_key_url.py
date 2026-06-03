"""Tests for the Fernet codec backing the Claude API key URL persist."""

from __future__ import annotations

import pytest

from components.api_key_url import decrypt_api_key, encrypt_api_key


_SECRET = "test-server-secret-do-not-use-in-prod-12345"
_OTHER_SECRET = "different-server-secret-xyz"


# ---------------------------------------------------------------------------
# Roundtrip — every realistic input must encrypt then decrypt back to itself
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw",
    [
        "sk-ant-api03-abcdef0123456789",
        "sk-ant-very-long-key-with-lots-of-characters-1234567890",
        "k",                                # single char
        "a" * 200,                          # very long
        "with spaces and !@#$%^&*()",       # special chars
        "unicode-µ-é-中-日",                 # non-ascii
    ],
)
def test_encrypt_decrypt_roundtrip(raw: str) -> None:
    ciphertext = encrypt_api_key(raw, secret=_SECRET)
    assert decrypt_api_key(ciphertext, secret=_SECRET) == raw


def test_ciphertext_is_not_the_raw_key() -> None:
    raw = "sk-ant-api03-secret"
    ciphertext = encrypt_api_key(raw, secret=_SECRET)
    assert raw not in ciphertext


def test_ciphertext_is_url_safe() -> None:
    """Fernet tokens are URL-safe by construction — no %-encoding needed."""
    raw = "ABCDxyz??//++123 !@#"
    ciphertext = encrypt_api_key(raw, secret=_SECRET)
    allowed = set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_="
    )
    assert set(ciphertext) <= allowed


def test_two_encryptions_of_same_key_differ() -> None:
    """Fernet embeds a random IV — same input encrypted twice should not match."""
    raw = "sk-ant-determinism-check"
    a = encrypt_api_key(raw, secret=_SECRET)
    b = encrypt_api_key(raw, secret=_SECRET)
    assert a != b
    # But both must decrypt to the same plaintext.
    assert decrypt_api_key(a, secret=_SECRET) == raw
    assert decrypt_api_key(b, secret=_SECRET) == raw


# ---------------------------------------------------------------------------
# Empty / falsy inputs — no work to do, no exception
# ---------------------------------------------------------------------------


def test_encrypt_empty_key_returns_empty_string() -> None:
    assert encrypt_api_key("", secret=_SECRET) == ""


def test_encrypt_missing_secret_returns_empty_string() -> None:
    assert encrypt_api_key("sk-ant-x", secret="") == ""


def test_decrypt_empty_ciphertext_returns_none() -> None:
    assert decrypt_api_key("", secret=_SECRET) is None


def test_decrypt_missing_secret_returns_none() -> None:
    ciphertext = encrypt_api_key("sk-ant-x", secret=_SECRET)
    assert decrypt_api_key(ciphertext, secret="") is None


# ---------------------------------------------------------------------------
# Wrong secret — the whole point of using real encryption
# ---------------------------------------------------------------------------


def test_decrypt_with_wrong_secret_returns_none() -> None:
    """A URL leaked without the server secret cannot recover the key."""
    raw = "sk-ant-api03-very-real-key"
    ciphertext = encrypt_api_key(raw, secret=_SECRET)
    assert decrypt_api_key(ciphertext, secret=_OTHER_SECRET) is None


def test_decrypt_with_almost_right_secret_returns_none() -> None:
    """One character off in the secret must still fail closed."""
    raw = "sk-ant-test"
    ciphertext = encrypt_api_key(raw, secret=_SECRET)
    nudged = _SECRET[:-1] + ("X" if _SECRET[-1] != "X" else "Y")
    assert decrypt_api_key(ciphertext, secret=nudged) is None


# ---------------------------------------------------------------------------
# Tampered ciphertext — Fernet's HMAC must reject this
# ---------------------------------------------------------------------------


def test_decrypt_tampered_ciphertext_returns_none() -> None:
    raw = "sk-ant-tamper-test"
    ciphertext = encrypt_api_key(raw, secret=_SECRET)
    # Flip a single character in the middle of the token.
    midpoint = len(ciphertext) // 2
    flipped_char = "B" if ciphertext[midpoint] != "B" else "C"
    tampered = ciphertext[:midpoint] + flipped_char + ciphertext[midpoint + 1 :]
    assert decrypt_api_key(tampered, secret=_SECRET) is None


def test_decrypt_garbage_input_returns_none() -> None:
    assert decrypt_api_key("not-even-a-token", secret=_SECRET) is None
    assert decrypt_api_key("!!!invalid!!!", secret=_SECRET) is None


def test_decrypt_truncated_token_returns_none() -> None:
    ciphertext = encrypt_api_key("sk-ant-truncate", secret=_SECRET)
    assert decrypt_api_key(ciphertext[:20], secret=_SECRET) is None
