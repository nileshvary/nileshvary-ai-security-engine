"""HMAC-signed session tokens for cookie-based Firebase remember-me.

Tokens travel in a browser cookie (not the URL) and contain only
non-secret identity claims (uid, email, issue timestamp) plus an
HMAC-SHA256 signature computed with a server-side secret. The secret
lives in ``st.secrets["session"]["secret"]`` and never leaves the
server.

Tokens are stateless: validation re-derives the HMAC and checks the
fixed 24-hour TTL. There is no server-side revocation list, so a
leaked cookie is valid until its TTL expires. Logout deletes the
cookie on the originating device only.
"""

from __future__ import annotations

import hmac
import logging
import time
from hashlib import sha256
from typing import Any

logger = logging.getLogger(__name__)

# Sessions live for 24 hours from issue time. Matches the choice
# captured during the feature design conversation; shorter TTLs reduce
# the blast radius of a leaked cookie at the cost of more re-logins.
SESSION_TTL_SECONDS = 24 * 60 * 60

# Fixed delimiter between payload fields. The empty-string check during
# verification rejects any payload that contains it inside a field.
_FIELD_SEP = "|"


def sign_session(
    uid: str,
    email: str,
    *,
    secret: str,
    issued_at: int | None = None,
) -> str:
    """Return a signed session token for ``uid`` / ``email``.

    Args:
        uid: Firebase user id (the canonical identity).
        email: Email address claim, included so the verifier can surface
            it without an extra Firestore read.
        secret: Server-side HMAC secret. Must be non-empty; callers are
            expected to gate on ``read_session_secret`` first.
        issued_at: Unix timestamp (seconds) for the token's issue time.
            Defaults to ``time.time()``. Exposed so tests can pin time.

    Returns:
        A token of the form ``"uid|email|issued_at|hex_hmac"``.
    """
    if not secret:
        raise ValueError("session secret is required to sign a session")
    if _FIELD_SEP in uid or _FIELD_SEP in email:
        raise ValueError(
            f"uid and email must not contain the {_FIELD_SEP!r} delimiter"
        )
    ts = int(issued_at if issued_at is not None else time.time())
    payload = f"{uid}{_FIELD_SEP}{email}{_FIELD_SEP}{ts}"
    sig = hmac.new(secret.encode("utf-8"), payload.encode("utf-8"), sha256).hexdigest()
    return f"{payload}{_FIELD_SEP}{sig}"


def verify_session(
    token: str,
    *,
    secret: str,
    now: int | None = None,
    ttl_seconds: int = SESSION_TTL_SECONDS,
) -> dict[str, Any] | None:
    """Validate a token's signature and TTL.

    Returns the decoded payload (``uid``, ``email``, ``issued_at``)
    when the signature matches and the token is within ``ttl_seconds``
    of its issue time, ``None`` otherwise. Never raises on malformed
    input — the goal is to fail closed without leaking detail to the
    caller.
    """
    if not token or not secret:
        return None
    parts = token.split(_FIELD_SEP)
    if len(parts) != 4:
        return None
    uid, email, ts_raw, provided_sig = parts
    if not uid or not email or not ts_raw or not provided_sig:
        return None
    try:
        issued_at = int(ts_raw)
    except ValueError:
        return None
    payload = f"{uid}{_FIELD_SEP}{email}{_FIELD_SEP}{issued_at}"
    expected_sig = hmac.new(
        secret.encode("utf-8"), payload.encode("utf-8"), sha256
    ).hexdigest()
    if not hmac.compare_digest(expected_sig, provided_sig):
        return None
    current = int(now if now is not None else time.time())
    if current < issued_at:
        # Issued in the future — clock skew or tampering. Reject.
        return None
    if current - issued_at > ttl_seconds:
        return None
    return {"uid": uid, "email": email, "issued_at": issued_at}


def read_session_secret(secrets: Any) -> str | None:
    """Read ``secrets["session"]["secret"]`` and return it, or ``None``.

    Returns ``None`` when the section/key is missing or the value is
    empty so the caller can disable cookie persistence gracefully
    rather than crashing the app.
    """
    if secrets is None:
        return None
    try:
        section = secrets["session"]
        value = section["secret"]
    except (KeyError, TypeError):
        return None
    value = str(value).strip()
    if not value:
        return None
    return value
