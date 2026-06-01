"""Tests for the SHA-256 token manager + brute-force lockout."""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from auth.token_manager import LOCKOUT_MINUTES, MAX_ATTEMPTS, TokenManager


def test_generate_token_returns_raw_with_prefix(token_manager: TokenManager) -> None:
    token = token_manager.generate_token(duration_hours=2, for_person="Alice")
    assert token.startswith("RMX-")
    assert len(token) > 20


def test_validate_token_happy_path(token_manager: TokenManager) -> None:
    token = token_manager.generate_token(duration_hours=2, for_person="Alice")
    ok, status, record = token_manager.validate_token(token, ip="ip-1")
    assert ok is True
    assert status == "valid"
    assert record["for"] == "Alice"
    assert record["uses"] == 1


def test_validate_token_increments_uses(token_manager: TokenManager) -> None:
    token = token_manager.generate_token(duration_hours=2)
    token_manager.validate_token(token, ip="ip-1")
    _, _, record = token_manager.validate_token(token, ip="ip-2")
    assert record["uses"] == 2


def test_raw_token_never_persisted_in_file(
    token_manager: TokenManager, tmp_path: Path
) -> None:
    token = token_manager.generate_token(duration_hours=2)
    contents = (tmp_path / "tokens.json").read_text(encoding="utf-8")
    assert token not in contents


def test_revoked_token_rejected(token_manager: TokenManager) -> None:
    token = token_manager.generate_token(duration_hours=2)
    tid = next(iter(token_manager.get_all_tokens()))
    assert token_manager.revoke_token(tid) is True
    ok, status, _ = token_manager.validate_token(token, ip="ip-1")
    assert ok is False
    assert status == "revoked"


def test_delete_token(token_manager: TokenManager) -> None:
    token_manager.generate_token(duration_hours=2)
    tid = next(iter(token_manager.get_all_tokens()))
    assert token_manager.delete_token(tid) is True
    assert token_manager.get_all_tokens() == {}


def test_expired_token_rejected(token_manager: TokenManager, tmp_path: Path) -> None:
    token = token_manager.generate_token(duration_hours=1)
    data = json.loads((tmp_path / "tokens.json").read_text(encoding="utf-8"))
    [tid] = data["tokens"].keys()
    data["tokens"][tid]["expires"] = (
        datetime.utcnow() - timedelta(hours=1)
    ).isoformat()
    (tmp_path / "tokens.json").write_text(json.dumps(data), encoding="utf-8")

    ok, status, _ = token_manager.validate_token(token, ip="ip-1")
    assert ok is False
    assert status == "expired"


def test_permanent_token_bypasses_expiry(
    token_manager: TokenManager, tmp_path: Path
) -> None:
    token = token_manager.generate_token(permanent=True, for_person="Admin")
    data = json.loads((tmp_path / "tokens.json").read_text(encoding="utf-8"))
    [tid] = data["tokens"].keys()
    assert data["tokens"][tid]["permanent"] is True
    assert data["tokens"][tid]["expires"] is None

    ok, status, record = token_manager.validate_token(token, ip="ip-1")
    assert ok is True
    assert status == "valid"
    assert record["permanent"] is True


def test_lockout_after_five_wrong(token_manager: TokenManager) -> None:
    ip = "brute"
    for i in range(MAX_ATTEMPTS - 1):
        ok, status, _ = token_manager.validate_token("RMX-wrong-" + str(i), ip=ip)
        assert ok is False
        assert status.startswith("invalid:")
    ok, status, _ = token_manager.validate_token("RMX-also-wrong", ip=ip)
    assert ok is False
    assert status.startswith("locked:")
    locked_minutes = int(status.split(":", 1)[1])
    assert 0 < locked_minutes <= LOCKOUT_MINUTES


def test_successful_validation_resets_attempts(token_manager: TokenManager) -> None:
    ip = "mixed"
    token = token_manager.generate_token(duration_hours=2)
    token_manager.validate_token("RMX-wrong-1", ip=ip)
    token_manager.validate_token("RMX-wrong-2", ip=ip)
    ok, status, _ = token_manager.validate_token(token, ip=ip)
    assert ok is True
    token_manager.validate_token("RMX-wrong-3", ip=ip)
    ok, status, _ = token_manager.validate_token("RMX-wrong-4", ip=ip)
    assert ok is False
    assert status.startswith("invalid:")
    # 5 - 2 = 3 remaining; we just used 2 since reset, so 3 remain.
    remaining = int(status.split(":", 1)[1])
    assert remaining == MAX_ATTEMPTS - 2


def test_hash_is_deterministic(token_manager: TokenManager) -> None:
    h1 = token_manager._hash("hello-world")  # noqa: SLF001 - testing internal
    h2 = token_manager._hash("hello-world")  # noqa: SLF001 - testing internal
    assert h1 == h2
    assert len(h1) == 64  # SHA-256 hex


def test_get_all_tokens_returns_every_record(token_manager: TokenManager) -> None:
    token_manager.generate_token(duration_hours=2, for_person="A")
    token_manager.generate_token(duration_hours=24, for_person="B")
    token_manager.generate_token(permanent=True, for_person="Admin")
    all_tokens = token_manager.get_all_tokens()
    assert len(all_tokens) == 3


def test_revoke_unknown_token_returns_false(token_manager: TokenManager) -> None:
    assert token_manager.revoke_token("doesnotexist") is False


def test_delete_unknown_token_returns_false(token_manager: TokenManager) -> None:
    assert token_manager.delete_token("doesnotexist") is False
