"""SHA-256 hashed, file-backed access tokens with brute-force lockout.

Tokens are generated with a `RMX-` prefix plus a urlsafe-base64 random
suffix, hashed before storage, and never written in plaintext to disk.
"""

from __future__ import annotations

import hashlib
import json
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

TOKENS_FILE = Path("tokens.json")
MAX_ATTEMPTS = 5
LOCKOUT_MINUTES = 60


class TokenManager:
    """Manages RemediAX access tokens stored in ``tokens.json``.

    Each token has a SHA-256 hashed representation, an expiry (or
    permanent flag), an issue date, a per-token use counter, and a
    revocation flag. The raw token is returned exactly once from
    ``generate_token``; only the hash is persisted.
    """

    def __init__(self, tokens_file: Path | None = None) -> None:
        """Construct a manager bound to a tokens file (default: ``tokens.json``)."""
        self.tokens_file = tokens_file or TOKENS_FILE

    def generate_token(
        self,
        duration_hours: int = 48,
        for_person: str = "",
        permanent: bool = False,
    ) -> str:
        """Mint a new token and persist its hash.

        Args:
            duration_hours: Validity period in hours; ignored when
                ``permanent=True``.
            for_person: Free-form note about who the token is for.
            permanent: When True, the token never expires.

        Returns:
            The raw token string. Caller must display it once and let
            the user copy it; the manager only stores the hash.
        """
        raw = "RMX-" + secrets.token_urlsafe(32)
        hashed = self._hash(raw)

        expires = (
            None
            if permanent
            else (datetime.utcnow() + timedelta(hours=duration_hours)).isoformat()
        )

        record = {
            "hash": hashed,
            "created": datetime.utcnow().isoformat(),
            "expires": expires,
            "permanent": permanent,
            "for": for_person,
            "uses": 0,
            "revoked": False,
        }

        data = self._load()
        token_id = hashed[:12]
        data["tokens"][token_id] = record
        self._save(data)
        return raw

    def register_token_hash(
        self,
        raw_token: str,
        *,
        duration_hours: int = 48,
        for_person: str = "",
        permanent: bool = False,
    ) -> str | None:
        """Register an existing raw token's hash without minting a new one.

        Useful for bootstrapping a deploy-time admin token from a secret:
        the operator pastes their permanent admin token into the
        deployment's secret store, and this method registers its hash
        on first boot — so the raw value never has to be committed to
        version control. Idempotent: if a record with this hash already
        exists, the store is left unchanged.

        Args:
            raw_token: The token whose hash should be stored. Caller is
                responsible for sourcing it (e.g. from Streamlit secrets).
            duration_hours: Validity period in hours; ignored when
                ``permanent=True``.
            for_person: Free-form note about who the token is for.
            permanent: When True, the token never expires.

        Returns:
            The newly-created token id (first 12 chars of the SHA-256
            hash) on success, or ``None`` if a record with that hash
            was already present.
        """
        hashed = self._hash(raw_token)
        data = self._load()
        if any(
            rec.get("hash") == hashed
            for rec in data.get("tokens", {}).values()
        ):
            return None

        expires = (
            None
            if permanent
            else (datetime.utcnow() + timedelta(hours=duration_hours)).isoformat()
        )
        record = {
            "hash": hashed,
            "created": datetime.utcnow().isoformat(),
            "expires": expires,
            "permanent": permanent,
            "for": for_person,
            "uses": 0,
            "revoked": False,
        }
        token_id = hashed[:12]
        data.setdefault("tokens", {})[token_id] = record
        self._save(data)
        return token_id

    def validate_token(
        self,
        entered: str,
        ip: str = "unknown",
    ) -> tuple[bool, str, dict[str, Any]]:
        """Validate a user-entered token against the stored hashes.

        Args:
            entered: The raw token typed by the user.
            ip: A per-client identifier (real IP, or a stable proxy
                like a session-id) used for brute-force lockout.

        Returns:
            A 3-tuple ``(ok, status, record)`` where ``status`` is one
            of: ``"valid"``, ``"revoked"``, ``"expired"``,
            ``"invalid:<remaining>"``, ``"locked:<minutes>"``.
        """
        if self._is_locked_out(ip):
            remaining = self._lockout_remaining(ip)
            return False, f"locked:{remaining}", {}

        hashed = self._hash(entered.strip())
        data = self._load()

        for record in data["tokens"].values():
            if record["hash"] != hashed:
                continue
            if record["revoked"]:
                return False, "revoked", {}
            if not record["permanent"]:
                expires = datetime.fromisoformat(record["expires"])
                if datetime.utcnow() > expires:
                    return False, "expired", record
            # Reset attempts on the in-memory data so the save below
            # does not undo the reset.
            if ip in data.get("attempts", {}):
                del data["attempts"][ip]
            record["uses"] += 1
            self._save(data)
            return True, "valid", record

        self._record_attempt(ip)
        attempts = self._get_attempts(ip)
        remaining = MAX_ATTEMPTS - attempts
        if remaining <= 0:
            return False, f"locked:{LOCKOUT_MINUTES}", {}
        return False, f"invalid:{remaining}", {}

    def revoke_token(self, token_id: str) -> bool:
        """Set the ``revoked`` flag on a token by id (first 12 chars of hash)."""
        data = self._load()
        if token_id in data["tokens"]:
            data["tokens"][token_id]["revoked"] = True
            self._save(data)
            return True
        return False

    def delete_token(self, token_id: str) -> bool:
        """Permanently remove a token record (used for expired entries)."""
        data = self._load()
        if token_id in data["tokens"]:
            del data["tokens"][token_id]
            self._save(data)
            return True
        return False

    def get_all_tokens(self) -> dict[str, dict[str, Any]]:
        """Return every stored token record keyed by token id."""
        return self._load()["tokens"]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _hash(self, token: str) -> str:
        return hashlib.sha256(token.encode()).hexdigest()

    def _load(self) -> dict[str, Any]:
        if not self.tokens_file.exists():
            self.tokens_file.write_text(
                '{"tokens": {}, "attempts": {}}', encoding="utf-8"
            )
        return json.loads(self.tokens_file.read_text(encoding="utf-8"))

    def _save(self, data: dict[str, Any]) -> None:
        self.tokens_file.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def _is_locked_out(self, ip: str) -> bool:
        data = self._load()
        attempts = data.get("attempts", {})
        if ip not in attempts:
            return False
        entry = attempts[ip]
        if entry["count"] < MAX_ATTEMPTS:
            return False
        if entry.get("locked_at") is None:
            return False
        locked_at = datetime.fromisoformat(entry["locked_at"])
        return (datetime.utcnow() - locked_at).total_seconds() < LOCKOUT_MINUTES * 60

    def _lockout_remaining(self, ip: str) -> int:
        data = self._load()
        locked_at = datetime.fromisoformat(data["attempts"][ip]["locked_at"])
        elapsed_minutes = int((datetime.utcnow() - locked_at).total_seconds() // 60)
        return max(LOCKOUT_MINUTES - elapsed_minutes, 0)

    def _get_attempts(self, ip: str) -> int:
        data = self._load()
        return data.get("attempts", {}).get(ip, {}).get("count", 0)

    def _record_attempt(self, ip: str) -> None:
        data = self._load()
        attempts = data.setdefault("attempts", {})
        entry = attempts.setdefault(ip, {"count": 0, "locked_at": None})
        entry["count"] += 1
        if entry["count"] >= MAX_ATTEMPTS:
            entry["locked_at"] = datetime.utcnow().isoformat()
        self._save(data)

    def _reset_attempts(self, ip: str) -> None:
        data = self._load()
        if ip in data.get("attempts", {}):
            del data["attempts"][ip]
            self._save(data)
