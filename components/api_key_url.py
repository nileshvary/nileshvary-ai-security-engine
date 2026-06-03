"""Server-side Fernet encryption for the Claude API key URL persist.

The Anthropic API key is persisted in ``st.query_params["ak"]`` so it
survives a browser refresh. The value stored in the URL is a Fernet
ciphertext (AES-128-CBC + HMAC-SHA256) — opaque to anyone who doesn't
hold the server-side secret, even if they can read the URL. This is
real symmetric encryption, not just base64 obfuscation.

Secret: read from ``st.secrets["session"]["secret"]`` in the caller
and passed through as ``secret``. A SHA-256 digest of that string
becomes the 32-byte Fernet key (URL-safe base64 encoded). The same
secret therefore deterministically yields the same Fernet key —
ciphertexts written before a redeploy decrypt fine after, as long as
the secret hasn't changed.

What URL leakage still costs you:
    * The encrypted blob is meaningless without the secret, so a
      leaked URL alone does not expose the API key.
    * A leaked URL **plus** a leaked secret is the same as a leaked
      plaintext key. Keep the secret out of version control and
      logs.
    * Fernet tokens include a timestamp; if you later add TTL
      enforcement, swap the bare ``decrypt`` call for ``decrypt_at_time``
      or ``decrypt(token, ttl=...)``.
"""

from __future__ import annotations

import base64
import hashlib

from cryptography.fernet import Fernet, InvalidToken


def _derive_fernet_key(secret: str) -> bytes:
    """Derive a Fernet-compatible 32-byte key from an arbitrary secret string.

    SHA-256 + URL-safe base64 is the canonical pattern for turning a
    human-chosen passphrase into a Fernet key. The output is exactly
    44 ASCII characters (the only thing Fernet accepts as a key).
    Deterministic — the same input string always produces the same
    key, so the same secret can decrypt ciphertexts written by an
    earlier process run.
    """
    digest = hashlib.sha256(secret.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


def encrypt_api_key(key: str, *, secret: str) -> str:
    """Encrypt ``key`` with the Fernet key derived from ``secret``.

    Returns the ciphertext as a URL-safe ASCII string (Fernet tokens
    are already URL-safe — no further encoding needed). Returns an
    empty string when either input is empty so the caller can treat
    "no work to do" the same as "encryption disabled".
    """
    if not key or not secret:
        return ""
    fernet = Fernet(_derive_fernet_key(secret))
    return fernet.encrypt(key.encode("utf-8")).decode("ascii")


def decrypt_api_key(ciphertext: str, *, secret: str) -> str | None:
    """Reverse ``encrypt_api_key``. Returns ``None`` on any failure.

    Fails closed for: empty inputs, the wrong secret, a tampered
    ciphertext (Fernet's HMAC catches single-byte flips), a value
    that isn't a Fernet token at all, or a payload that doesn't
    decode as UTF-8. Never raises.
    """
    if not ciphertext or not secret:
        return None
    try:
        fernet = Fernet(_derive_fernet_key(secret))
        plaintext_bytes = fernet.decrypt(ciphertext.encode("ascii"))
        return plaintext_bytes.decode("utf-8")
    except (InvalidToken, ValueError, UnicodeDecodeError, UnicodeEncodeError):
        return None
