"""Per-token daily scan limit, bypassed for users who bring their own API key.

State lives in ``.remediax_usage.json`` keyed by ``YYYY-MM-DD`` then token id.
"""

from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from typing import Any

USAGE_FILE = Path(".remediax_usage.json")
DAILY_CAP = 3


class RateLimiter:
    """Tracks daily scan counts per token and enforces the free-tier cap."""

    def __init__(self, usage_file: Path | None = None, daily_cap: int = DAILY_CAP) -> None:
        """Build a limiter bound to a usage file (default: ``.remediax_usage.json``)."""
        self.usage_file = usage_file or USAGE_FILE
        self.daily_cap = daily_cap

    def check_and_increment(
        self,
        token_id: str,
        has_api_key: bool,
    ) -> tuple[bool, int, int]:
        """Atomically read + bump the day's usage for ``token_id``.

        Args:
            token_id: First 12 chars of the token's SHA-256 hash.
            has_api_key: When True the cap is bypassed entirely.

        Returns:
            ``(allowed, used_today, daily_cap)``. ``used_today`` is the
            count after the bump on success, or the count at the time of
            denial when ``allowed`` is False.
        """
        data = self._load()
        today = date.today().isoformat()
        today_bucket = data.setdefault(today, {})
        used = int(today_bucket.get(token_id, 0))

        if has_api_key:
            today_bucket[token_id] = used + 1
            self._save(data)
            return True, used + 1, self.daily_cap

        if used >= self.daily_cap:
            return False, used, self.daily_cap

        today_bucket[token_id] = used + 1
        self._save(data)
        return True, used + 1, self.daily_cap

    def usage_today(self, token_id: str) -> int:
        """Return how many scans the token has done today (no mutation)."""
        data = self._load()
        return int(data.get(date.today().isoformat(), {}).get(token_id, 0))

    def _load(self) -> dict[str, Any]:
        if not self.usage_file.exists():
            return {}
        try:
            return json.loads(self.usage_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}

    def _save(self, data: dict[str, Any]) -> None:
        self.usage_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
