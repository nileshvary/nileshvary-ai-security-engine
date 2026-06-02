"""Firebase Admin + Firestore wrapper for RemediAX user auth and data.

Two layers:

* **firebase-admin SDK** for everything that has admin privileges:
  user creation, user lookup, custom tier claims, all Firestore reads
  and writes.
* **Firebase Auth REST API** for email/password sign-in. The admin SDK
  cannot verify a password directly — that's intentionally a
  client-side concern. We call ``identitytoolkit.googleapis.com``
  ourselves with one HTTP POST.

The module is **import-safe**: nothing connects to Firebase at import
time. Call ``init_firebase()`` once at app start. If credentials are
missing or invalid the helper records the failure, returns ``False``,
and every subsequent call short-circuits gracefully so the UI can
degrade rather than crash.

Expected ``st.secrets`` shape (TOML):

::

    [firebase]
    # The Web API key from Firebase console → Project settings → General
    web_api_key = "AIza..."

    [firebase.service_account]
    type = "service_account"
    project_id = "your-project"
    private_key_id = "..."
    private_key = "-----BEGIN PRIVATE KEY-----\\n...\\n-----END PRIVATE KEY-----\\n"
    client_email = "firebase-adminsdk-...@your-project.iam.gserviceaccount.com"
    client_id = "..."
    # ... rest of the service-account JSON ...
"""

from __future__ import annotations

import calendar
import datetime as _dt
import logging
from typing import Any

import requests

logger = logging.getLogger(__name__)


_FIREBASE_AUTH_REST = (
    "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword"
)
_USERS_COLLECTION = "users"
_SCANS_SUBCOLLECTION = "scans"
_TOKEN_REQUESTS_COLLECTION = "token_requests"

_DEFAULT_TIER = "basic"
_VALID_TIERS: frozenset[str] = frozenset({"basic", "premium", "developer"})

# Module-level state. Populated by ``init_firebase`` and read by all other
# helpers. We intentionally do not initialize at import time so the
# module is import-safe in environments without credentials (tests,
# local dev without ``.streamlit/secrets.toml``).
_state: dict[str, Any] = {
    "ready": False,
    "web_api_key": None,
    "init_error": None,
}


class FirebaseAuthError(Exception):
    """Raised for any expected Firebase Auth failure (bad password, etc)."""


def init_firebase(secrets: Any) -> bool:
    """Initialize the Firebase Admin SDK from a Streamlit secrets-like mapping.

    Idempotent: safe to call on every Streamlit rerun. Returns ``True``
    when Firebase is ready to use, ``False`` when credentials are
    missing or invalid (the caller should fall back to a "Firebase not
    configured" UI in that case).

    Args:
        secrets: Either ``st.secrets`` or a plain ``dict`` shaped like
            ``{"firebase": {"web_api_key": ..., "service_account": {...}}}``.
    """
    if _state["ready"]:
        return True

    try:
        firebase_section = secrets["firebase"]
        service_account = firebase_section["service_account"]
        web_api_key = firebase_section["web_api_key"]
    except (KeyError, TypeError) as exc:
        _state["init_error"] = f"Missing secret: {exc}"
        logger.info(
            "Firebase secrets not configured (%s); auth disabled until set",
            exc,
        )
        return False

    try:
        # Convert TOML-loaded service-account section to a plain dict.
        cred_dict = dict(service_account)
        # Lazy import — the package is heavy and not always present in
        # contexts where init_firebase is being called defensively.
        import firebase_admin
        from firebase_admin import credentials

        if not firebase_admin._apps:  # noqa: SLF001 - idiomatic check
            firebase_admin.initialize_app(credentials.Certificate(cred_dict))
    except Exception as exc:  # pragma: no cover - exercised only with real creds
        _state["init_error"] = str(exc)
        logger.warning("Firebase admin init failed: %s", exc)
        return False

    _state["ready"] = True
    _state["web_api_key"] = str(web_api_key)
    _state["init_error"] = None
    logger.info("Firebase admin initialized")
    return True


def is_firebase_ready() -> bool:
    """True when ``init_firebase`` has succeeded at least once this process."""
    return bool(_state["ready"])


# ---------------------------------------------------------------------------
# Auth — create / login / lookup
# ---------------------------------------------------------------------------


def create_user(email: str, password: str, name: str) -> dict[str, Any]:
    """Create a Firebase Auth user and seed a Firestore profile.

    Args:
        email: Email address. Firebase validates uniqueness.
        password: Plaintext password (Firebase hashes it server-side).
        name: Display name; stored on both the Auth record and the
            Firestore profile.

    Returns:
        A dict with ``uid``, ``email``, ``name``, ``tier``.

    Raises:
        FirebaseAuthError: When Firebase is not configured, the email is
            already taken, the password is too weak, or any other Auth
            error reported by the SDK.
    """
    if not is_firebase_ready():
        raise FirebaseAuthError("Firebase is not configured.")

    from firebase_admin import auth as fb_auth

    try:
        user = fb_auth.create_user(
            email=email, password=password, display_name=name
        )
    except fb_auth.EmailAlreadyExistsError as exc:
        raise FirebaseAuthError("Email is already registered.") from exc
    except ValueError as exc:
        raise FirebaseAuthError(str(exc)) from exc
    except Exception as exc:  # pragma: no cover - network / unknown
        raise FirebaseAuthError(f"Could not create user: {exc}") from exc

    # Seed the user document so tier and counters exist on first login.
    profile = {
        "email": email,
        "name": name,
        "tier": _DEFAULT_TIER,
        "created_at": _dt.datetime.utcnow().isoformat(),
        "scans_total": 0,
    }
    try:
        _firestore_client().collection(_USERS_COLLECTION).document(
            user.uid
        ).set(profile, merge=True)
    except Exception as exc:  # pragma: no cover - Firestore down
        logger.warning("Failed to seed Firestore profile for %s: %s", user.uid, exc)

    return {
        "uid": user.uid,
        "email": email,
        "name": name,
        "tier": _DEFAULT_TIER,
    }


def login_user(email: str, password: str) -> dict[str, Any]:
    """Verify an email/password pair via the Firebase Auth REST API.

    Args:
        email: Email address registered with Firebase Auth.
        password: Plaintext password.

    Returns:
        A dict with ``uid``, ``email``, ``name``, ``tier``, ``id_token``.

    Raises:
        FirebaseAuthError: For any sign-in failure (bad password,
            unknown email, disabled account, Firebase not configured).
    """
    if not is_firebase_ready():
        raise FirebaseAuthError("Firebase is not configured.")

    api_key = _state["web_api_key"]
    if not api_key:
        raise FirebaseAuthError("Firebase web API key is missing.")

    payload = {"email": email, "password": password, "returnSecureToken": True}
    try:
        response = requests.post(
            f"{_FIREBASE_AUTH_REST}?key={api_key}",
            json=payload,
            timeout=10,
        )
    except requests.RequestException as exc:
        raise FirebaseAuthError(f"Network error: {exc}") from exc

    if response.status_code != 200:
        message = _extract_rest_error(response)
        raise FirebaseAuthError(message)

    data = response.json()
    uid = data.get("localId")
    if not uid:
        raise FirebaseAuthError("Sign-in succeeded but no uid was returned.")

    profile = get_user(uid) or {}
    return {
        "uid": uid,
        "email": data.get("email") or email,
        "name": profile.get("name") or data.get("displayName") or email.split("@")[0],
        "tier": profile.get("tier") or _DEFAULT_TIER,
        "id_token": data.get("idToken"),
    }


def get_user(uid: str) -> dict[str, Any] | None:
    """Return the Firestore profile for ``uid``, or ``None`` if not found."""
    if not is_firebase_ready():
        return None
    try:
        doc = (
            _firestore_client()
            .collection(_USERS_COLLECTION)
            .document(uid)
            .get()
        )
    except Exception as exc:  # pragma: no cover
        logger.warning("Failed to read user %s: %s", uid, exc)
        return None
    if not doc.exists:
        return None
    return dict(doc.to_dict() or {})


# ---------------------------------------------------------------------------
# Tier — basic / premium / developer
# ---------------------------------------------------------------------------


def get_user_tier(uid: str) -> str:
    """Return the user's tier or ``"basic"`` if unset / unknown."""
    profile = get_user(uid) or {}
    tier = str(profile.get("tier") or _DEFAULT_TIER)
    return tier if tier in _VALID_TIERS else _DEFAULT_TIER


def set_user_tier(uid: str, tier: str) -> bool:
    """Update the user's tier. Returns ``True`` on success."""
    if tier not in _VALID_TIERS:
        raise ValueError(
            f"Invalid tier {tier!r}; expected one of {sorted(_VALID_TIERS)}"
        )
    if not is_firebase_ready():
        return False
    try:
        _firestore_client().collection(_USERS_COLLECTION).document(uid).set(
            {"tier": tier}, merge=True
        )
        return True
    except Exception as exc:  # pragma: no cover
        logger.warning("Failed to set tier for %s: %s", uid, exc)
        return False


# ---------------------------------------------------------------------------
# Scans — save and list
# ---------------------------------------------------------------------------


def save_scan(uid: str, scan_data: dict[str, Any]) -> bool:
    """Append a scan record to the user's Firestore history. Returns success."""
    if not is_firebase_ready():
        return False
    payload = dict(scan_data)
    payload.setdefault("created_at", _dt.datetime.utcnow().isoformat())
    payload.setdefault("month_key", _current_month_key())
    try:
        client = _firestore_client()
        client.collection(_USERS_COLLECTION).document(uid).collection(
            _SCANS_SUBCOLLECTION
        ).add(payload)
        client.collection(_USERS_COLLECTION).document(uid).set(
            {"scans_total": _firestore_increment(1)}, merge=True
        )
        return True
    except Exception as exc:  # pragma: no cover
        logger.warning("Failed to save scan for %s: %s", uid, exc)
        return False


def get_user_scans(uid: str, limit: int = 50) -> list[dict[str, Any]]:
    """Return the user's most recent scans, newest first."""
    if not is_firebase_ready():
        return []
    try:
        docs = list(
            _firestore_client()
            .collection(_USERS_COLLECTION)
            .document(uid)
            .collection(_SCANS_SUBCOLLECTION)
            .order_by("created_at", direction=_firestore_descending())
            .limit(limit)
            .stream()
        )
    except Exception as exc:  # pragma: no cover
        logger.warning("Failed to list scans for %s: %s", uid, exc)
        return []
    out: list[dict[str, Any]] = []
    for doc in docs:
        record = dict(doc.to_dict() or {})
        record["id"] = doc.id
        out.append(record)
    return out


def scans_this_month(uid: str) -> int:
    """Count of scans the user has run in the current calendar month."""
    if not is_firebase_ready():
        return 0
    try:
        month_key = _current_month_key()
        docs = list(
            _firestore_client()
            .collection(_USERS_COLLECTION)
            .document(uid)
            .collection(_SCANS_SUBCOLLECTION)
            .where("month_key", "==", month_key)
            .stream()
        )
        return len(docs)
    except Exception as exc:  # pragma: no cover
        logger.warning("Failed to count scans for %s: %s", uid, exc)
        return 0


# ---------------------------------------------------------------------------
# Token requests — premium access requests
# ---------------------------------------------------------------------------


def save_token_request(email: str, name: str, reason: str) -> bool:
    """Persist a premium-access request to Firestore. Returns success."""
    if not is_firebase_ready():
        return False
    try:
        _firestore_client().collection(_TOKEN_REQUESTS_COLLECTION).add(
            {
                "email": email,
                "name": name,
                "reason": reason,
                "requested_at": _dt.datetime.utcnow().isoformat(),
                "status": "pending",
            }
        )
        return True
    except Exception as exc:  # pragma: no cover
        logger.warning("Failed to save token request for %s: %s", email, exc)
        return False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _firestore_client() -> Any:
    """Lazy-import + return the firestore.Client."""
    from firebase_admin import firestore

    return firestore.client()


def _firestore_increment(amount: int) -> Any:
    from firebase_admin import firestore

    return firestore.Increment(amount)


def _firestore_descending() -> Any:
    from firebase_admin import firestore

    return firestore.Query.DESCENDING


def _current_month_key() -> str:
    """ISO-style month key (e.g. ``"2026-06"``) for grouping scans by month."""
    now = _dt.datetime.utcnow()
    return f"{now.year:04d}-{now.month:02d}"


def _days_until_month_end() -> int:  # pragma: no cover - cosmetic
    now = _dt.datetime.utcnow()
    _, last_day = calendar.monthrange(now.year, now.month)
    return max(0, last_day - now.day)


def _extract_rest_error(response: requests.Response) -> str:
    """Convert a Firebase Auth REST error response to a user-friendly message."""
    try:
        body = response.json()
    except ValueError:
        return f"Sign-in failed (HTTP {response.status_code})."
    error_msg = str(body.get("error", {}).get("message", "")).upper()

    mapping = {
        "EMAIL_NOT_FOUND": "No account with that email.",
        "INVALID_PASSWORD": "Incorrect password.",
        "INVALID_LOGIN_CREDENTIALS": "Incorrect email or password.",
        "USER_DISABLED": "This account has been disabled.",
        "TOO_MANY_ATTEMPTS_TRY_LATER": "Too many failed attempts. Try again later.",
        "INVALID_EMAIL": "Email address is not valid.",
    }
    for key, friendly in mapping.items():
        if key in error_msg:
            return friendly
    return error_msg.title() or "Sign-in failed."


def _reset_state_for_tests() -> None:
    """Clear the module-level state — only used by the test suite."""
    _state["ready"] = False
    _state["web_api_key"] = None
    _state["init_error"] = None
