"""URL-safe base64 codec for the Claude API key remember-me param.

The Anthropic API key is persisted in ``st.query_params["ak"]`` so it
survives a browser refresh. Base64 (URL-safe variant) is used as a
lightweight obfuscation step — it makes the value un-obvious in the
address bar but is fully reversible. **This is not encryption.** See
the long-form security note in ``app.py`` before extending this.

Kept as a standalone module so the codec is unit-testable without
spinning up the Streamlit runtime.
"""

from __future__ import annotations

import base64


def encode_api_key(key: str) -> str:
    """URL-safe base64 encode ``key``. Empty input returns ``""``.

    ``=`` padding is stripped because Streamlit's query-param parsing
    handles unpadded strings fine and the cleaner address bar is the
    whole point.
    """
    if not key:
        return ""
    return (
        base64.urlsafe_b64encode(key.encode("utf-8"))
        .decode("ascii")
        .rstrip("=")
    )


def decode_api_key(encoded: str) -> str | None:
    """Reverse ``encode_api_key``. Returns ``None`` for malformed input.

    Padding is re-added before decoding so the unpadded form produced
    by ``encode_api_key`` round-trips correctly. Anything that isn't
    valid URL-safe base64, or that decodes to non-UTF-8 bytes, comes
    back as ``None`` so the caller can drop the bad param cleanly
    rather than blowing up the page.
    """
    if not encoded:
        return None
    s = str(encoded).strip()
    # Restore the padding base64 needs (multiple of 4 chars).
    padding = "=" * ((4 - len(s) % 4) % 4)
    try:
        raw = base64.urlsafe_b64decode(s + padding)
        return raw.decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        return None
