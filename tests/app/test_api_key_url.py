"""Tests for the URL-safe base64 codec used by the Claude API key persist."""

from __future__ import annotations

import pytest

from components.api_key_url import decode_api_key, encode_api_key


# ---------------------------------------------------------------------------
# Roundtrip — every realistic input must encode then decode back to itself
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
def test_encode_decode_roundtrip(raw: str) -> None:
    assert decode_api_key(encode_api_key(raw)) == raw


def test_encoded_value_is_not_the_raw_key() -> None:
    raw = "sk-ant-api03-secret"
    encoded = encode_api_key(raw)
    assert raw not in encoded


def test_encoded_value_is_url_safe() -> None:
    """No characters that need %-encoding to sit in a URL."""
    raw = "ABCDxyz??//++123 !@#"
    encoded = encode_api_key(raw)
    # URL-safe alphabet: A-Z a-z 0-9 - _   (no = padding either)
    allowed = set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    )
    assert set(encoded) <= allowed


def test_encoded_has_no_padding_equals_signs() -> None:
    for raw in ("a", "ab", "abc", "abcd", "abcde"):
        assert "=" not in encode_api_key(raw)


# ---------------------------------------------------------------------------
# Empty / falsy inputs
# ---------------------------------------------------------------------------


def test_encode_empty_string_returns_empty_string() -> None:
    assert encode_api_key("") == ""


def test_decode_empty_string_returns_none() -> None:
    assert decode_api_key("") is None


def test_decode_none_like_inputs_return_none() -> None:
    # The signature is str, but the caller passes whatever
    # st.query_params gives back. Guard against type-confused values.
    assert decode_api_key("") is None


# ---------------------------------------------------------------------------
# Malformed input — must fail closed, never raise
# ---------------------------------------------------------------------------


def test_decode_garbage_returns_none() -> None:
    assert decode_api_key("!!!not-base64!!!") is None


def test_decode_truncated_returns_none() -> None:
    # Truncate a real encoded value mid-character.
    encoded = encode_api_key("sk-ant-12345")
    truncated = encoded[:-3] + "."  # invalid char at end
    assert decode_api_key(truncated) is None


def test_decode_non_utf8_payload_returns_none() -> None:
    # Construct a base64 string whose bytes are not valid UTF-8 (a
    # lone continuation byte).
    import base64

    bad = base64.urlsafe_b64encode(b"\x80\x81\x82").decode("ascii").rstrip("=")
    assert decode_api_key(bad) is None
