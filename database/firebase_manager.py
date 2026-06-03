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

# NOTE: ``requests`` is imported lazily inside ``login_user`` and the
# test paths so that this module can be imported on environments where
# the dependency chain has not yet pulled it in (e.g. mid-deploy on
# Streamlit Cloud before firebase-admin's transitive deps land). The
# ``requests`` package IS required at runtime for the email/password
# sign-in REST call — it is listed explicitly in requirements.txt.

logger = logging.getLogger(__name__)


_FIREBASE_AUTH_REST = (
    "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword"
)
_USERS_COLLECTION = "users"
_SCANS_SUBCOLLECTION = "scans"
_UPLOADS_SUBCOLLECTION = "uploads"
_TOKEN_REQUESTS_COLLECTION = "token_requests"

_DEFAULT_TIER = "basic"
_VALID_TIERS: frozenset[str] = frozenset({"basic", "premium", "developer"})

# The minimum set of keys a Firebase service-account JSON must have for
# firebase_admin.credentials.Certificate to accept it.
_SERVICE_ACCOUNT_REQUIRED_FIELDS: frozenset[str] = frozenset(
    {"type", "project_id", "private_key", "client_email"}
)

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

    # --- Step 1: locate the firebase section ---
    try:
        firebase_section = secrets["firebase"]
    except (KeyError, TypeError) as exc:
        return _fail(
            f"st.secrets['firebase'] section not found "
            f"({type(exc).__name__}: {exc})."
        )

    fb_keys = _safe_keys(firebase_section)
    logger.info(
        "Firebase init: found firebase section with %d top-level keys: %s",
        len(fb_keys),
        sorted(fb_keys),
    )

    # --- Step 2: web_api_key ---
    try:
        web_api_key = firebase_section["web_api_key"]
    except (KeyError, TypeError) as exc:
        return _fail(
            "st.secrets['firebase']['web_api_key'] is missing. Add the "
            "Web API Key from Firebase console → Project settings "
            f"→ General. ({type(exc).__name__}: {exc})"
        )
    if not str(web_api_key).strip():
        return _fail("st.secrets['firebase']['web_api_key'] is empty.")
    logger.info(
        "Firebase init: web_api_key present (length=%d)",
        len(str(web_api_key)),
    )

    # --- Step 3: service_account (nested), with fallback to flat shape ---
    service_account_obj: Any | None = None
    try:
        service_account_obj = firebase_section["service_account"]
    except (KeyError, TypeError):
        service_account_obj = None

    sa_keys = _safe_keys(service_account_obj) if service_account_obj is not None else set()
    if service_account_obj is not None:
        logger.info(
            "Firebase init: found service_account sub-section with keys: %s",
            sorted(sa_keys),
        )

    if not sa_keys:
        # Fallback: maybe the service-account fields are inlined under
        # ``[firebase]`` (e.g. a stray duplicate ``[firebase]`` header
        # in the TOML collapsed the table back).
        if _SERVICE_ACCOUNT_REQUIRED_FIELDS.issubset(fb_keys):
            logger.warning(
                "Firebase init: service_account section is missing or "
                "empty; falling back to flat firebase.* fields"
            )
            service_account_obj = {
                k: firebase_section[k] for k in fb_keys if k != "web_api_key"
            }
            sa_keys = set(service_account_obj.keys())
        else:
            present = fb_keys & _SERVICE_ACCOUNT_REQUIRED_FIELDS
            missing = _SERVICE_ACCOUNT_REQUIRED_FIELDS - fb_keys
            return _fail(
                f"st.secrets['firebase']['service_account'] is missing or "
                f"empty, and the flat fallback fields are incomplete. "
                f"Required: {sorted(_SERVICE_ACCOUNT_REQUIRED_FIELDS)}; "
                f"present directly in firebase section: {sorted(present)}; "
                f"still missing: {sorted(missing)}."
            )

    # --- Step 4: build plain dict + validate required fields ---
    try:
        cred_dict: dict[str, Any] = {
            str(k): service_account_obj[k] for k in sa_keys
        }
    except Exception as exc:
        return _fail(
            f"Failed to read service_account fields: "
            f"{type(exc).__name__}: {exc}"
        )

    missing_required = _SERVICE_ACCOUNT_REQUIRED_FIELDS - set(cred_dict.keys())
    if missing_required:
        return _fail(
            f"service_account is missing required fields: "
            f"{sorted(missing_required)}. Present: "
            f"{sorted(cred_dict.keys())}."
        )

    # --- Step 5: sanity-check private_key (header + newlines) ---
    private_key_raw = str(cred_dict.get("private_key", ""))
    if "BEGIN PRIVATE KEY" not in private_key_raw:
        return _fail(
            "service_account['private_key'] does not contain "
            "'BEGIN PRIVATE KEY'. Check that the PEM header survived "
            "the paste."
        )
    if "\n" not in private_key_raw:
        logger.warning(
            "Firebase init: private_key has no real newlines; converting "
            "literal '\\n' escapes to newlines"
        )
        cred_dict["private_key"] = private_key_raw.replace("\\n", "\n")

    logger.info(
        "Firebase init: cred dict ready (project_id=%s, client_email=%s, "
        "private_key length=%d)",
        cred_dict.get("project_id"),
        cred_dict.get("client_email"),
        len(str(cred_dict.get("private_key", ""))),
    )

    # --- Step 6: initialize firebase_admin ---
    try:
        import firebase_admin
        from firebase_admin import credentials
    except Exception as exc:
        return _fail(
            f"firebase_admin package is not installed or failed to "
            f"import: {type(exc).__name__}: {exc}"
        )

    try:
        if not firebase_admin._apps:  # noqa: SLF001 - idiomatic check
            firebase_admin.initialize_app(credentials.Certificate(cred_dict))
    except ValueError as exc:
        return _fail(
            f"firebase_admin.credentials.Certificate rejected the "
            f"service_account dict: {exc}"
        )
    except Exception as exc:
        return _fail(
            f"firebase_admin.initialize_app raised "
            f"{type(exc).__name__}: {exc}"
        )

    _state["ready"] = True
    _state["web_api_key"] = str(web_api_key)
    _state["init_error"] = None
    logger.info(
        "Firebase admin initialized successfully (project_id=%s)",
        cred_dict.get("project_id"),
    )
    return True


def is_firebase_ready() -> bool:
    """True when ``init_firebase`` has succeeded at least once this process."""
    return bool(_state["ready"])


def get_init_error() -> str | None:
    """Return the most recent init failure reason, or ``None`` if ready / never tried."""
    return _state.get("init_error")


def _safe_keys(obj: Any) -> set[str]:
    """Best-effort key listing for Streamlit Secrets objects / dicts / None."""
    if obj is None:
        return set()
    try:
        return {str(k) for k in obj.keys()}
    except (AttributeError, TypeError):
        pass
    try:
        return {str(k) for k in dict(obj).keys()}
    except Exception:
        return set()


def _fail(reason: str) -> bool:
    """Record an init failure, log it, and return ``False``."""
    _state["init_error"] = reason
    logger.warning("Firebase init failed: %s", reason)
    return False


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

    # Lazy import — keeps the module import-safe on environments where
    # ``requests`` has not yet landed via firebase-admin's dep tree.
    try:
        import requests as _requests
    except ImportError as exc:  # pragma: no cover - install regression
        raise FirebaseAuthError(
            f"requests package is not installed: {exc}"
        ) from exc

    payload = {"email": email, "password": password, "returnSecureToken": True}
    try:
        response = _requests.post(
            f"{_FIREBASE_AUTH_REST}?key={api_key}",
            json=payload,
            timeout=10,
        )
    except _requests.RequestException as exc:
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


def save_scan(
    uid: str,
    scan_data: dict[str, Any],
    scan_id: str | None = None,
) -> str | None:
    """Persist a scan record for ``uid``.

    Args:
        uid: Firebase user id.
        scan_data: Free-form metadata for this scan. ``created_at`` and
            ``month_key`` are auto-set if absent.
        scan_id: Optional deterministic doc id. When given, the caller
            can later call ``update_scan(uid, scan_id, {...})`` to merge
            completion stats into the same record. When ``None``,
            Firestore auto-generates the id.

    Returns:
        The scan id (string) on success, or ``None`` when Firebase is
        not configured or the write failed.
    """
    if not is_firebase_ready():
        return None
    payload = dict(scan_data)
    payload.setdefault("created_at", _dt.datetime.utcnow().isoformat())
    payload.setdefault("month_key", _current_month_key())
    try:
        client = _firestore_client()
        users_doc = client.collection(_USERS_COLLECTION).document(uid)
        scans = users_doc.collection(_SCANS_SUBCOLLECTION)
        if scan_id is None:
            _, doc_ref = scans.add(payload)
            actual_id = doc_ref.id
        else:
            scans.document(scan_id).set(payload, merge=True)
            actual_id = scan_id
        users_doc.set({"scans_total": _firestore_increment(1)}, merge=True)
        return str(actual_id)
    except Exception as exc:  # pragma: no cover
        logger.warning("Failed to save scan for %s: %s", uid, exc)
        return None


def update_scan(uid: str, scan_id: str, updates: dict[str, Any]) -> bool:
    """Merge ``updates`` into an existing scan document.

    Used to add completion stats (fix rate, security score, approved /
    skipped counts) after the user finishes the interactive review.
    Returns ``True`` on success, ``False`` when Firebase is not
    configured, ``scan_id`` is falsy, or the write failed.
    """
    if not is_firebase_ready():
        return False
    if not scan_id:
        return False
    try:
        _firestore_client().collection(_USERS_COLLECTION).document(uid).collection(
            _SCANS_SUBCOLLECTION
        ).document(scan_id).set(updates, merge=True)
        return True
    except Exception as exc:  # pragma: no cover
        logger.warning(
            "Failed to update scan %s for %s: %s", scan_id, uid, exc
        )
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


def get_all_scans(limit: int = 100) -> list[dict[str, Any]]:
    """Return the most recent scans across every user, newest first.

    Used by the admin analytics dashboard to render platform-wide
    metrics. Issues a single Firestore collection-group query against
    every ``users/*/scans`` subcollection — requires a collection-group
    index on the ``created_at`` field (Firebase prompts for it the first
    time the query runs).

    Each returned record carries the scan document id (``id``) and the
    owning user uid (``user_uid``) so admin views can attribute rows.

    Args:
        limit: Maximum scans to return. Defaults to 100.

    Returns:
        A list of scan dicts ordered by ``created_at`` descending; an
        empty list when Firebase is not configured or the query failed.
    """
    if not is_firebase_ready():
        return []
    try:
        docs = list(
            _firestore_client()
            .collection_group(_SCANS_SUBCOLLECTION)
            .order_by("created_at", direction=_firestore_descending())
            .limit(limit)
            .stream()
        )
    except Exception as exc:  # pragma: no cover
        logger.warning("Failed to list scans across all users: %s", exc)
        return []
    out: list[dict[str, Any]] = []
    for doc in docs:
        record = dict(doc.to_dict() or {})
        record["id"] = doc.id
        # Each scan lives at users/{uid}/scans/{scan_id}; the parent of
        # the scan doc's parent collection is the owning user document.
        try:
            user_doc = doc.reference.parent.parent
            if user_doc is not None:
                record["user_uid"] = user_doc.id
        except AttributeError:  # pragma: no cover - defensive
            pass
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
# Uploads — file-ingest records, separate lifecycle from scans
# ---------------------------------------------------------------------------


def save_upload(uid: str, upload_data: dict[str, Any]) -> str | None:
    """Persist an upload record under ``users/{uid}/uploads/{auto-id}``.

    Uploads are tracked separately from scans because a file can be
    uploaded and parsed without the user ever completing a review.
    Analytics reads both collections to surface "files uploaded" vs
    "scans completed" as distinct metrics.

    Args:
        uid: Owning user id. Pass the literal strings ``"guest"`` or
            ``"admin"`` for unauthenticated / admin-token users so the
            data lands under a stable namespace.
        upload_data: Caller-supplied fields (filename, file_size,
            findings_count, status, etc.). ``timestamp`` and
            ``created_at`` are auto-set if absent.

    Returns:
        The new upload id on success, ``None`` when Firebase is not
        configured or the write failed.
    """
    if not is_firebase_ready():
        logger.info(
            "save_upload SKIPPED (Firebase not ready) uid=%s filename=%s",
            uid,
            upload_data.get("filename"),
        )
        return None
    payload = dict(upload_data)
    payload.setdefault("created_at", _dt.datetime.utcnow().isoformat())
    payload.setdefault("timestamp", payload["created_at"])
    try:
        _, doc_ref = (
            _firestore_client()
            .collection(_USERS_COLLECTION)
            .document(uid)
            .collection(_UPLOADS_SUBCOLLECTION)
            .add(payload)
        )
        upload_id = str(doc_ref.id)
        logger.info(
            "save_upload OK uid=%s id=%s filename=%s size=%s status=%s findings=%s",
            uid,
            upload_id,
            payload.get("filename"),
            payload.get("file_size"),
            payload.get("status"),
            payload.get("findings_count"),
        )
        return upload_id
    except Exception as exc:  # pragma: no cover
        logger.warning("save_upload FAILED uid=%s: %s", uid, exc)
        return None


def get_user_uploads(uid: str, limit: int = 10) -> list[dict[str, Any]]:
    """Return the user's most recent uploads, newest first."""
    if not is_firebase_ready():
        return []
    try:
        docs = list(
            _firestore_client()
            .collection(_USERS_COLLECTION)
            .document(uid)
            .collection(_UPLOADS_SUBCOLLECTION)
            .order_by("created_at", direction=_firestore_descending())
            .limit(limit)
            .stream()
        )
    except Exception as exc:  # pragma: no cover
        logger.warning("Failed to list uploads for %s: %s", uid, exc)
        return []
    out: list[dict[str, Any]] = []
    for doc in docs:
        record = dict(doc.to_dict() or {})
        record["id"] = doc.id
        out.append(record)
    return out


def get_all_uploads(limit: int = 100) -> list[dict[str, Any]]:
    """Return uploads across every user, newest first.

    Powers the platform-wide admin Activity Overview. Mirrors the
    behavior of ``get_all_scans`` — single collection-group query
    against every ``users/*/uploads`` subcollection. Requires a
    collection-group index on ``created_at`` (Firebase prompts for it
    on first use).
    """
    if not is_firebase_ready():
        return []
    try:
        docs = list(
            _firestore_client()
            .collection_group(_UPLOADS_SUBCOLLECTION)
            .order_by("created_at", direction=_firestore_descending())
            .limit(limit)
            .stream()
        )
    except Exception as exc:  # pragma: no cover
        logger.warning("Failed to list uploads across all users: %s", exc)
        return []
    out: list[dict[str, Any]] = []
    for doc in docs:
        record = dict(doc.to_dict() or {})
        record["id"] = doc.id
        try:
            user_doc = doc.reference.parent.parent
            if user_doc is not None:
                record["user_uid"] = user_doc.id
        except AttributeError:  # pragma: no cover - defensive
            pass
        out.append(record)
    return out


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
