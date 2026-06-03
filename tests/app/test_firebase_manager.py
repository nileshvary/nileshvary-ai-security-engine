"""Tests for the Firebase manager — Firebase admin SDK and Auth REST mocked."""

from __future__ import annotations

import sys
from types import ModuleType, SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from database import firebase_manager as fm


_SECRETS = {
    "firebase": {
        "web_api_key": "AIza-test",
        "service_account": {
            "type": "service_account",
            "project_id": "test-project",
            "private_key_id": "abc",
            "private_key": "-----BEGIN PRIVATE KEY-----\nxxx\n-----END PRIVATE KEY-----\n",
            "client_email": "test@test.iam.gserviceaccount.com",
            "client_id": "0",
        },
    }
}


@pytest.fixture(autouse=True)
def reset_firebase_state() -> None:
    """Reset module-level state before each test."""
    fm._reset_state_for_tests()
    yield
    fm._reset_state_for_tests()


@pytest.fixture
def fake_firebase(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """Install fake firebase_admin + firebase_admin.auth + .credentials + .firestore."""
    fake_admin = ModuleType("firebase_admin")
    fake_admin._apps = {}  # populated by initialize_app

    def initialize_app(cred):
        fake_admin._apps["[DEFAULT]"] = SimpleNamespace(cred=cred)

    fake_admin.initialize_app = initialize_app

    # credentials submodule
    fake_credentials = ModuleType("firebase_admin.credentials")
    fake_credentials.Certificate = lambda data: SimpleNamespace(data=data)
    fake_admin.credentials = fake_credentials

    # auth submodule
    fake_auth = ModuleType("firebase_admin.auth")

    class EmailAlreadyExistsError(Exception):
        pass

    fake_auth.EmailAlreadyExistsError = EmailAlreadyExistsError
    fake_auth.create_user = MagicMock(
        return_value=SimpleNamespace(uid="user-1", email="a@b.com")
    )
    fake_auth.get_user = MagicMock(
        return_value=SimpleNamespace(uid="user-1", email="a@b.com", display_name="A")
    )
    fake_admin.auth = fake_auth

    # firestore submodule
    fake_firestore = ModuleType("firebase_admin.firestore")
    fake_firestore.Increment = lambda n: f"inc:{n}"

    class _Query:
        DESCENDING = "DESC"

    fake_firestore.Query = _Query

    client_mock = MagicMock(name="firestore_client")
    fake_firestore.client = MagicMock(return_value=client_mock)
    fake_admin.firestore = fake_firestore

    monkeypatch.setitem(sys.modules, "firebase_admin", fake_admin)
    monkeypatch.setitem(sys.modules, "firebase_admin.credentials", fake_credentials)
    monkeypatch.setitem(sys.modules, "firebase_admin.auth", fake_auth)
    monkeypatch.setitem(sys.modules, "firebase_admin.firestore", fake_firestore)

    return SimpleNamespace(
        admin=fake_admin,
        auth=fake_auth,
        firestore=fake_firestore,
        firestore_client=client_mock,
        credentials=fake_credentials,
    )


# ---------------------------------------------------------------------------
# init / readiness
# ---------------------------------------------------------------------------


def test_init_firebase_without_secrets_returns_false() -> None:
    assert fm.init_firebase({}) is False
    assert fm.is_firebase_ready() is False
    assert "section not found" in (fm.get_init_error() or "")


def test_init_firebase_missing_web_api_key_returns_specific_error() -> None:
    assert fm.init_firebase({"firebase": {"service_account": {"x": 1}}}) is False
    assert "web_api_key" in (fm.get_init_error() or "")


def test_init_firebase_empty_web_api_key_returns_specific_error() -> None:
    assert fm.init_firebase(
        {"firebase": {"web_api_key": "  ", "service_account": {"x": 1}}}
    ) is False
    assert "empty" in (fm.get_init_error() or "")


def test_init_firebase_with_partial_secrets_returns_false() -> None:
    assert fm.init_firebase({"firebase": {"web_api_key": "x"}}) is False
    assert fm.is_firebase_ready() is False
    err = fm.get_init_error() or ""
    assert "service_account" in err
    assert "missing" in err


def test_init_firebase_flat_fallback_when_service_account_empty(
    fake_firebase: SimpleNamespace,
) -> None:
    """Service-account fields inlined directly under [firebase] should still work."""
    flat_secrets = {
        "firebase": {
            "web_api_key": "AIza-test",
            "type": "service_account",
            "project_id": "remediax-flat",
            "private_key_id": "abc",
            "private_key": "-----BEGIN PRIVATE KEY-----\nxxx\n-----END PRIVATE KEY-----\n",
            "client_email": "flat@flat.iam.gserviceaccount.com",
            "client_id": "0",
        }
    }
    assert fm.init_firebase(flat_secrets) is True
    assert fm.is_firebase_ready() is True


def test_init_firebase_private_key_missing_header_returns_specific_error(
    fake_firebase: SimpleNamespace,
) -> None:
    bad = dict(_SECRETS)
    bad = {
        "firebase": {
            "web_api_key": "AIza-test",
            "service_account": {
                "type": "service_account",
                "project_id": "x",
                "private_key": "not a real pem",
                "client_email": "x@x.iam.gserviceaccount.com",
            },
        }
    }
    assert fm.init_firebase(bad) is False
    assert "BEGIN PRIVATE KEY" in (fm.get_init_error() or "")


def test_init_firebase_certificate_value_error_surfaces(
    fake_firebase: SimpleNamespace, monkeypatch: pytest.MonkeyPatch
) -> None:
    def boom(_data):
        raise ValueError("Invalid cert format")

    monkeypatch.setattr(fake_firebase.credentials, "Certificate", boom)
    assert fm.init_firebase(_SECRETS) is False
    err = fm.get_init_error() or ""
    assert "Certificate rejected" in err
    assert "Invalid cert format" in err


def test_get_init_error_clears_on_success(fake_firebase: SimpleNamespace) -> None:
    # First, a failed call sets the error.
    assert fm.init_firebase({"firebase": {}}) is False
    assert fm.get_init_error() is not None
    fm._reset_state_for_tests()
    # Then a successful call clears it.
    assert fm.init_firebase(_SECRETS) is True
    assert fm.get_init_error() is None


def test_init_firebase_succeeds_with_full_secrets(fake_firebase: SimpleNamespace) -> None:
    assert fm.init_firebase(_SECRETS) is True
    assert fm.is_firebase_ready() is True
    # Idempotent — second call no-ops.
    assert fm.init_firebase(_SECRETS) is True


def test_create_user_requires_firebase_init() -> None:
    with pytest.raises(fm.FirebaseAuthError):
        fm.create_user("a@b.com", "pw12345", "Alice")


# ---------------------------------------------------------------------------
# create_user
# ---------------------------------------------------------------------------


def test_create_user_happy_path(fake_firebase: SimpleNamespace) -> None:
    fm.init_firebase(_SECRETS)
    fake_firebase.auth.create_user.return_value = SimpleNamespace(
        uid="new-user", email="new@example.com"
    )
    profile = fm.create_user("new@example.com", "secret123", "Newbie")
    assert profile["uid"] == "new-user"
    assert profile["tier"] == "basic"
    fake_firebase.auth.create_user.assert_called_once_with(
        email="new@example.com", password="secret123", display_name="Newbie"
    )


def test_create_user_email_already_exists(fake_firebase: SimpleNamespace) -> None:
    fm.init_firebase(_SECRETS)
    fake_firebase.auth.create_user.side_effect = (
        fake_firebase.auth.EmailAlreadyExistsError()
    )
    with pytest.raises(fm.FirebaseAuthError, match="already registered"):
        fm.create_user("dup@example.com", "pw", "Dup")


# ---------------------------------------------------------------------------
# login_user (REST API)
# ---------------------------------------------------------------------------


def test_login_user_happy_path(fake_firebase: SimpleNamespace) -> None:
    fm.init_firebase(_SECRETS)
    rest_response = MagicMock(status_code=200)
    rest_response.json.return_value = {
        "localId": "user-42",
        "email": "alice@example.com",
        "idToken": "id-token-xyz",
        "displayName": "Alice",
    }
    with patch("database.firebase_manager.requests.post", return_value=rest_response):
        # get_user fetches Firestore profile; mock to return a tier.
        doc = MagicMock()
        doc.exists = True
        doc.to_dict.return_value = {"tier": "premium", "name": "Alice"}
        fake_firebase.firestore_client.collection.return_value.document.return_value.get.return_value = doc

        profile = fm.login_user("alice@example.com", "secret")

    assert profile["uid"] == "user-42"
    assert profile["tier"] == "premium"
    assert profile["id_token"] == "id-token-xyz"


def test_login_user_bad_password(fake_firebase: SimpleNamespace) -> None:
    fm.init_firebase(_SECRETS)
    rest_response = MagicMock(status_code=400)
    rest_response.json.return_value = {
        "error": {"message": "INVALID_PASSWORD"}
    }
    with patch("database.firebase_manager.requests.post", return_value=rest_response):
        with pytest.raises(fm.FirebaseAuthError, match="Incorrect password"):
            fm.login_user("alice@example.com", "wrong")


def test_login_user_unknown_email(fake_firebase: SimpleNamespace) -> None:
    fm.init_firebase(_SECRETS)
    rest_response = MagicMock(status_code=400)
    rest_response.json.return_value = {
        "error": {"message": "EMAIL_NOT_FOUND"}
    }
    with patch("database.firebase_manager.requests.post", return_value=rest_response):
        with pytest.raises(fm.FirebaseAuthError, match="No account"):
            fm.login_user("nope@example.com", "x")


def test_login_user_network_error(fake_firebase: SimpleNamespace) -> None:
    fm.init_firebase(_SECRETS)
    import requests as real_requests

    with patch(
        "database.firebase_manager.requests.post",
        side_effect=real_requests.ConnectionError("boom"),
    ):
        with pytest.raises(fm.FirebaseAuthError, match="Network error"):
            fm.login_user("alice@example.com", "x")


# ---------------------------------------------------------------------------
# tier
# ---------------------------------------------------------------------------


def test_get_user_tier_defaults_to_basic(fake_firebase: SimpleNamespace) -> None:
    fm.init_firebase(_SECRETS)
    doc = MagicMock()
    doc.exists = True
    doc.to_dict.return_value = {}  # no tier field
    fake_firebase.firestore_client.collection.return_value.document.return_value.get.return_value = doc
    assert fm.get_user_tier("any-uid") == "basic"


def test_get_user_tier_returns_premium(fake_firebase: SimpleNamespace) -> None:
    fm.init_firebase(_SECRETS)
    doc = MagicMock()
    doc.exists = True
    doc.to_dict.return_value = {"tier": "premium"}
    fake_firebase.firestore_client.collection.return_value.document.return_value.get.return_value = doc
    assert fm.get_user_tier("any-uid") == "premium"


def test_get_user_tier_rejects_unknown_value(fake_firebase: SimpleNamespace) -> None:
    fm.init_firebase(_SECRETS)
    doc = MagicMock()
    doc.exists = True
    doc.to_dict.return_value = {"tier": "rogue"}
    fake_firebase.firestore_client.collection.return_value.document.return_value.get.return_value = doc
    assert fm.get_user_tier("any-uid") == "basic"


def test_set_user_tier_validates_value(fake_firebase: SimpleNamespace) -> None:
    fm.init_firebase(_SECRETS)
    with pytest.raises(ValueError):
        fm.set_user_tier("uid-1", "rogue")


def test_set_user_tier_persists_to_firestore(
    fake_firebase: SimpleNamespace,
) -> None:
    fm.init_firebase(_SECRETS)
    assert fm.set_user_tier("uid-1", "premium") is True
    set_call = fake_firebase.firestore_client.collection.return_value.document.return_value.set
    set_call.assert_called_with({"tier": "premium"}, merge=True)


# ---------------------------------------------------------------------------
# save_scan / scans_this_month / save_token_request
# ---------------------------------------------------------------------------


def test_save_scan_writes_to_firestore_and_returns_id(
    fake_firebase: SimpleNamespace,
) -> None:
    fm.init_firebase(_SECRETS)
    doc_ref = MagicMock()
    doc_ref.id = "auto-id-123"
    fake_firebase.firestore_client.collection.return_value.document.return_value.collection.return_value.add.return_value = (
        None,
        doc_ref,
    )
    scan_id = fm.save_scan("uid-1", {"source": "demo"})
    assert scan_id == "auto-id-123"
    fake_firebase.firestore_client.collection.assert_any_call("users")


def test_save_scan_with_explicit_scan_id_uses_set_merge(
    fake_firebase: SimpleNamespace,
) -> None:
    fm.init_firebase(_SECRETS)
    result = fm.save_scan(
        "uid-1", {"source": "demo"}, scan_id="my-scan-id"
    )
    assert result == "my-scan-id"
    chain = (
        fake_firebase.firestore_client.collection.return_value
        .document.return_value.collection.return_value
    )
    chain.document.assert_called_with("my-scan-id")


def test_save_scan_returns_none_when_firebase_disabled() -> None:
    assert fm.save_scan("uid", {"x": 1}) is None


def test_update_scan_merges_into_existing_doc(
    fake_firebase: SimpleNamespace,
) -> None:
    fm.init_firebase(_SECRETS)
    assert fm.update_scan("uid-1", "scan-42", {"status": "completed"}) is True
    chain = (
        fake_firebase.firestore_client.collection.return_value
        .document.return_value.collection.return_value
        .document.return_value
    )
    chain.set.assert_called_with({"status": "completed"}, merge=True)


def test_update_scan_returns_false_when_firebase_disabled() -> None:
    assert fm.update_scan("uid", "scan", {"x": 1}) is False


def test_update_scan_returns_false_when_scan_id_falsy(
    fake_firebase: SimpleNamespace,
) -> None:
    fm.init_firebase(_SECRETS)
    assert fm.update_scan("uid", "", {"x": 1}) is False


def test_scans_this_month_counts_filtered_docs(
    fake_firebase: SimpleNamespace,
) -> None:
    fm.init_firebase(_SECRETS)
    # Build a chain: collection > document > collection > where > stream
    where_chain = MagicMock()
    where_chain.stream.return_value = [MagicMock(), MagicMock(), MagicMock()]
    subcol = MagicMock()
    subcol.where.return_value = where_chain
    doc = MagicMock()
    doc.collection.return_value = subcol
    fake_firebase.firestore_client.collection.return_value.document.return_value = doc
    assert fm.scans_this_month("uid-1") == 3


def test_save_token_request(fake_firebase: SimpleNamespace) -> None:
    fm.init_firebase(_SECRETS)
    assert fm.save_token_request("a@b.com", "Alice", "want premium") is True
    add_call = fake_firebase.firestore_client.collection.return_value.add
    assert add_call.called
    payload = add_call.call_args.args[0]
    assert payload["email"] == "a@b.com"
    assert payload["status"] == "pending"


def test_save_scan_when_firebase_disabled_returns_none() -> None:
    assert fm.save_scan("uid", {"x": 1}) is None


def test_save_token_request_when_firebase_disabled_returns_false() -> None:
    assert fm.save_token_request("a@b.com", "A", "r") is False
