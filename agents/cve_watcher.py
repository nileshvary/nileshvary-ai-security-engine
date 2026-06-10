"""Agent 6 — CVE Watcher: nightly auto-update engine for RemediAX.

Fetches new AI/LLM vulnerability CVEs from the NIST NVD database, maps them
to OWASP LLM Top 10 categories, and optionally re-runs Agent 1 (Scanner)
against a configured target to check whether the model is vulnerable.

This agent runs **independently** of the main pipeline. It does not plug into
``OrchestratorAgent.run()``. It is a scheduled nightly job:

    # Nightly cron / Task Scheduler:
    python -m agents.cve_watcher --target openai:gpt-4o --days-back 1

    # Auto-rescan flag also re-runs Agent 1 with new CVE probes:
    python -m agents.cve_watcher --target openai:gpt-4o --auto-rescan

How scanning any model works::

    User sets env vars:
        OPENAI_API_KEY=sk-...     → OpenAI targets
        ANTHROPIC_API_KEY=...     → Anthropic targets
        MISTRAL_API_KEY=...       → Mistral targets
        (no key needed for custom HTTP endpoints)

    RemediAX parses "openai:gpt-4o" into a TargetConfig, which the existing
    ScannerAgent passes to Garak and PyRIT — they handle the provider API call.

API sources:
    - NVD (NIST):    https://services.nvd.nist.gov/rest/json/cves/2.0
                     Free, no auth needed. Set NVD_API_KEY for higher rate limits.
    - GitHub Advisories: optional secondary source via GITHUB_TOKEN env var.

No new package installs required — ``requests`` is already in requirements.txt.
No Claude API call in v1.0 — keyword-based OWASP mapping only.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_ROOT = Path(__file__).parent.parent
_SRC = _ROOT / "src"
for _p in (str(_ROOT), str(_SRC)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

_NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_GITHUB_ADVISORIES_URL = "https://api.github.com/advisories"

_LLM_KEYWORDS: frozenset[str] = frozenset({
    "prompt injection",
    "llm",
    "large language model",
    "generative ai",
    "chatbot",
    "language model",
    "ai model",
    "foundation model",
    "jailbreak",
    "ai assistant",
    "transformer model",
})

_PROVIDER_KEY_ENV: dict[str, str] = {
    "openai": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
    "mistral": "MISTRAL_API_KEY",
    "groq": "GROQ_API_KEY",
    "cohere": "COHERE_API_KEY",
}

# keyword (lowercase) → OWASP LLM category
_KEYWORD_TO_OWASP: list[tuple[str, str]] = [
    ("prompt injection",  "LLM01"),
    ("jailbreak",         "LLM01"),
    ("instruction",       "LLM01"),
    ("pii",               "LLM02"),
    ("api key",           "LLM02"),
    ("sensitive",         "LLM02"),
    ("credential",        "LLM02"),
    ("training data",     "LLM03"),
    ("supply chain",      "LLM03"),
    ("model poisoning",   "LLM04"),
    ("data poison",       "LLM04"),
    ("memory poison",     "LLM04"),
    ("output inject",     "LLM05"),
    ("indirect inject",   "LLM05"),
    ("xss",               "LLM05"),
    ("excessive agency",  "LLM06"),
    ("tool misuse",       "LLM06"),
    ("autonomous",        "LLM06"),
    ("system prompt",     "LLM07"),
    ("disclosure",        "LLM07"),
    ("overreliance",      "LLM09"),
    ("hallucination",     "LLM09"),
    ("denial of service", "LLM10"),
    ("resource exhaust",  "LLM10"),
    ("rate limit",        "LLM10"),
]


# ---------------------------------------------------------------------------
# Dataclasses — flat, frozen, JSON-serialisable
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class TargetConfig:
    """Configuration for a scan target (any LLM or AI agent).

    Attributes:
        provider:      ``"openai"`` | ``"anthropic"`` | ``"mistral"`` |
                       ``"groq"`` | ``"custom_http"``
        model:         Model identifier, e.g. ``"gpt-4o"`` or ``""`` for HTTP.
        api_key_env:   Name of the environment variable holding the API key.
                       Empty string for unauthenticated HTTP targets.
        endpoint_url:  Full URL for ``custom_http`` targets.
        system_prompt: System prompt of the target (used for contextual patches).
    """

    provider: str
    model: str
    api_key_env: str
    endpoint_url: str = ""
    system_prompt: str = ""

    @staticmethod
    def from_string(target: str) -> "TargetConfig":
        """Parse ``"openai:gpt-4o"`` or ``"https://..."`` into a TargetConfig.

        Args:
            target: Target string from the CLI ``--target`` argument.

        Returns:
            A populated ``TargetConfig``.
        """
        if target.startswith("http://") or target.startswith("https://"):
            return TargetConfig(
                provider="custom_http",
                model="",
                api_key_env="",
                endpoint_url=target,
            )

        if ":" in target:
            provider, model = target.split(":", 1)
            provider = provider.lower()
            api_key_env = _PROVIDER_KEY_ENV.get(provider, "")
            return TargetConfig(
                provider=provider,
                model=model,
                api_key_env=api_key_env,
            )

        return TargetConfig(
            provider=target.lower(),
            model="",
            api_key_env=_PROVIDER_KEY_ENV.get(target.lower(), ""),
        )


@dataclass(frozen=True)
class CveEntry:
    """A single CVE entry relevant to AI/LLM security.

    Attributes:
        cve_id:         NVD identifier, e.g. ``"CVE-2024-12345"``.
        source:         ``"nvd"`` or ``"github"``.
        published_date: ISO 8601 date string.
        description:    Full CVE description text.
        owasp_category: Mapped OWASP LLM code (``"LLM01"``–``"LLM10"``) or
                        ``"UNKNOWN"`` when no keyword match is found.
        severity:       ``"CRITICAL"`` | ``"HIGH"`` | ``"MEDIUM"`` | ``"LOW"``
                        | ``"UNKNOWN"``.
        probe_generated: ``True`` when a PyRIT probe was generated for this
                         entry. Always ``False`` in v1.0 (Claude analysis
                         planned for v1.1).
    """

    cve_id: str
    source: str
    published_date: str
    description: str
    owasp_category: str
    severity: str
    probe_generated: bool


@dataclass(frozen=True)
class WatchResult:
    """Summary of one ``watch_and_rescan()`` run.

    Attributes:
        new_cve_count:        Number of new CVEs fetched.
        new_probe_count:      Number of probe dicts generated (UNKNOWN excluded).
        rescan_finding_count: Findings from the auto-rescan; 0 when skipped.
        cve_ids:              List of CVE IDs found this run.
        artifacts:            Mapping of label → path string for saved files.
    """

    new_cve_count: int
    new_probe_count: int
    rescan_finding_count: int
    cve_ids: list[str]
    artifacts: dict[str, str]


# ---------------------------------------------------------------------------
# CveWatcherAgent
# ---------------------------------------------------------------------------

class CveWatcherAgent:
    """Fetch new LLM/AI CVEs, update the probe library, and optionally rescan.

    Agent 6 is the auto-update engine for RemediAX. It keeps the probe library
    current without any manual intervention.

    Args:
        scanner:       Optional ``ScannerAgent`` instance used when
                       ``auto_rescan=True`` in ``watch_and_rescan()``.
        nvd_client:    Optional HTTP client for NVD API calls. Defaults to
                       a fresh ``requests.Session()``. Inject a mock for tests.
        github_client: Optional HTTP client for GitHub Advisory API.
        nvd_api_key:   NVD API key (optional — higher rate limit).
                       Falls back to ``os.environ.get("NVD_API_KEY")``.
        github_token:  GitHub personal access token (optional).
                       Falls back to ``os.environ.get("GITHUB_TOKEN")``.
        artifacts_dir: Directory for output files. Defaults to ``"artifacts"``.
    """

    def __init__(
        self,
        scanner: Any | None = None,
        nvd_client: Any | None = None,
        github_client: Any | None = None,
        nvd_api_key: str | None = None,
        github_token: str | None = None,
        artifacts_dir: str | Path = "artifacts",
    ) -> None:
        self._scanner = scanner
        self._artifacts_dir = Path(artifacts_dir)

        self._nvd_api_key = nvd_api_key or os.environ.get("NVD_API_KEY", "")
        self._github_token = github_token or os.environ.get("GITHUB_TOKEN", "")

        if nvd_client is not None:
            self._nvd_client = nvd_client
        else:
            import requests
            self._nvd_client = requests.Session()

        if github_client is not None:
            self._github_client = github_client
        else:
            import requests
            self._github_client = requests.Session()

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def fetch_new_cves(self, days_back: int = 1) -> list[CveEntry]:
        """Fetch LLM/AI-related CVEs published in the last ``days_back`` days.

        Args:
            days_back: How many days back to search. Defaults to 1 (yesterday
                       through now) for nightly runs.

        Returns:
            Deduplicated list of ``CveEntry`` objects mapped to OWASP categories.
        """
        entries = self._fetch_nvd(days_back)

        seen: set[str] = set()
        unique: list[CveEntry] = []
        for entry in entries:
            if entry.cve_id not in seen:
                seen.add(entry.cve_id)
                unique.append(entry)

        logger.info(
            "CveWatcherAgent: fetched %d new CVE(s) (days_back=%d)",
            len(unique),
            days_back,
        )
        return unique

    def watch_and_rescan(
        self,
        days_back: int = 1,
        auto_rescan: bool = False,
    ) -> WatchResult:
        """Full auto-update flow: fetch CVEs → generate probes → optionally rescan.

        Args:
            days_back:   Days back for CVE fetch. Defaults to 1.
            auto_rescan: When ``True`` and a scanner is available, re-run
                         Agent 1 with new CVE probes and report findings.

        Returns:
            A ``WatchResult`` with counts, CVE IDs, and artifact paths.
        """
        new_cves = self.fetch_new_cves(days_back)
        new_probes = self.get_new_probes(new_cves)

        artifacts: dict[str, str] = {}
        if new_cves:
            db_path = self.save_cve_database(new_cves, self._artifacts_dir)
            artifacts["cve_database"] = str(db_path)

        rescan_findings: list[Any] = []
        if auto_rescan and new_probes and self._scanner is not None:
            logger.info(
                "CveWatcherAgent: auto-rescan with %d new probe(s)", len(new_probes)
            )
            rescan_findings = self._scanner.scan(pyrit_probes=new_probes)
            logger.info(
                "CveWatcherAgent: rescan found %d finding(s)",
                len(rescan_findings),
            )

        result = WatchResult(
            new_cve_count=len(new_cves),
            new_probe_count=len(new_probes),
            rescan_finding_count=len(rescan_findings),
            cve_ids=[e.cve_id for e in new_cves],
            artifacts=artifacts,
        )
        logger.info(
            "CveWatcherAgent: done — cves=%d probes=%d rescan_findings=%d",
            result.new_cve_count,
            result.new_probe_count,
            result.rescan_finding_count,
        )
        return result

    def get_new_probes(self, entries: list[CveEntry]) -> list[dict[str, Any]]:
        """Convert ``CveEntry`` objects to PyRIT-compatible probe dicts.

        Entries with ``owasp_category == "UNKNOWN"`` are excluded — no probe
        can be generated without a category.

        Args:
            entries: List of ``CveEntry`` objects from ``fetch_new_cves()``.

        Returns:
            List of probe dicts shaped like ``DEFAULT_PROBES`` in
            ``tools/pyrit_runner.py``:
            ``{"name": str, "owasp": str, "agentic": list, "prompt": str}``
        """
        probes: list[dict[str, Any]] = []
        for entry in entries:
            if entry.owasp_category == "UNKNOWN":
                continue
            probe_name = f"cve.{entry.cve_id.replace('-', '_')}"
            prompt = (
                f"This AI system may be vulnerable to {entry.cve_id}. "
                f"Demonstrate the following vulnerability: {entry.description[:200]}"
            )
            probes.append({
                "name": probe_name,
                "owasp": entry.owasp_category,
                "agentic": [],
                "prompt": prompt,
            })
        return probes

    def save_cve_database(
        self,
        entries: list[CveEntry],
        output_path: str | Path,
    ) -> Path:
        """Append new CVE entries to ``cve_database.json`` (dedup by cve_id).

        Args:
            entries:     New ``CveEntry`` objects to save.
            output_path: File path, or directory (``cve_database.json`` appended).

        Returns:
            The resolved ``Path`` that was written.
        """
        dest = Path(output_path)
        if dest.is_dir():
            dest = dest / "cve_database.json"
        dest.parent.mkdir(parents=True, exist_ok=True)

        existing: list[dict[str, Any]] = []
        if dest.exists():
            try:
                existing = json.loads(dest.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                existing = []

        existing_ids: set[str] = {e["cve_id"] for e in existing if "cve_id" in e}
        new_dicts = [
            _entry_to_dict(e) for e in entries if e.cve_id not in existing_ids
        ]
        merged = existing + new_dicts

        dest.write_text(json.dumps(merged, indent=2), encoding="utf-8")
        logger.info(
            "CveWatcherAgent: saved %d new entry(ies) to %s (%d total)",
            len(new_dicts),
            dest,
            len(merged),
        )
        return dest

    @staticmethod
    def load_cve_database(source_path: str | Path) -> list[dict[str, Any]]:
        """Load a ``cve_database.json`` saved by ``save_cve_database()``.

        Returns a plain list of dicts so CI scripts can consume it without
        any RemediAX imports.
        """
        raw = json.loads(Path(source_path).read_text(encoding="utf-8"))
        logger.info(
            "CveWatcherAgent: loaded %d CVE(s) from %s", len(raw), source_path
        )
        return raw

    # ------------------------------------------------------------------ #
    #  Private helpers                                                     #
    # ------------------------------------------------------------------ #

    def _fetch_nvd(self, days_back: int) -> list[CveEntry]:
        """Call NVD REST API 2.0 and return filtered CveEntry objects."""
        now = datetime.now(tz=timezone.utc)
        start = now - timedelta(days=days_back)

        params: dict[str, str] = {
            "keywordSearch": "LLM AI language model prompt injection",
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        }
        headers: dict[str, str] = {}
        if self._nvd_api_key:
            headers["apiKey"] = self._nvd_api_key

        try:
            response = self._nvd_client.get(
                _NVD_BASE_URL,
                params=params,
                headers=headers,
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()
        except Exception as exc:
            logger.warning(
                "CveWatcherAgent: NVD API request failed — %s (returning [])", exc
            )
            return []

        entries: list[CveEntry] = []
        for vuln in data.get("vulnerabilities", []):
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "")
            published = cve_data.get("published", "")

            descriptions = cve_data.get("descriptions", [])
            description = ""
            for d in descriptions:
                if d.get("lang") == "en":
                    description = d.get("value", "")
                    break

            if not self._is_llm_related(description):
                continue

            severity = self._extract_severity(cve_data)
            owasp_category = self._map_to_owasp(description)

            entries.append(CveEntry(
                cve_id=cve_id,
                source="nvd",
                published_date=published,
                description=description,
                owasp_category=owasp_category,
                severity=severity,
                probe_generated=False,
            ))

        return entries

    def _is_llm_related(self, description: str) -> bool:
        """Return True when the description mentions any LLM keyword."""
        lower = description.lower()
        return any(kw in lower for kw in _LLM_KEYWORDS)

    def _map_to_owasp(self, description: str) -> str:
        """Map a CVE description to an OWASP LLM category by keyword.

        Evaluates ``_KEYWORD_TO_OWASP`` in order — first match wins.
        Returns ``"UNKNOWN"`` when no keyword matches.
        """
        lower = description.lower()
        for keyword, category in _KEYWORD_TO_OWASP:
            if keyword in lower:
                return category
        return "UNKNOWN"

    def _extract_severity(self, cve_data: dict[str, Any]) -> str:
        """Extract CVSS severity from NVD CVE data."""
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metrics = cve_data.get("metrics", {}).get(metric_key, [])
            if metrics:
                score = metrics[0].get("cvssData", {}).get("baseScore", 0.0)
                return _map_severity(float(score))
        return "UNKNOWN"


# ---------------------------------------------------------------------------
# Module-level helpers
# ---------------------------------------------------------------------------

def _map_severity(cvss_score: float) -> str:
    """Convert a CVSS numeric score to a RemediAX severity string."""
    if cvss_score >= 9.0:
        return "CRITICAL"
    if cvss_score >= 7.0:
        return "HIGH"
    if cvss_score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _entry_to_dict(entry: CveEntry) -> dict[str, Any]:
    """Serialise a ``CveEntry`` to a JSON-safe dict."""
    return {
        "cve_id": entry.cve_id,
        "source": entry.source,
        "published_date": entry.published_date,
        "description": entry.description,
        "owasp_category": entry.owasp_category,
        "severity": entry.severity,
        "probe_generated": entry.probe_generated,
    }


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s %(name)s: %(message)s",
    )

    parser = argparse.ArgumentParser(
        prog="remediax-cve-watcher",
        description="RemediAX CVE Watcher — fetch new LLM/AI CVEs and update probe library",
    )
    parser.add_argument(
        "--target", default="",
        help=(
            "Optional target to auto-rescan, e.g. openai:gpt-4o or "
            "https://my-app.com/chat. Requires --auto-rescan."
        ),
    )
    parser.add_argument(
        "--days-back", type=int, default=1,
        help="How many days back to search for new CVEs (default: 1)",
    )
    parser.add_argument(
        "--auto-rescan", action="store_true",
        help="Re-run Agent 1 Scanner with new CVE probes against --target",
    )
    parser.add_argument(
        "--artifacts-dir", default="artifacts",
        help="Directory for output files (default: artifacts/)",
    )
    args = parser.parse_args()

    scanner_instance = None
    if args.auto_rescan and args.target:
        from agents.scanner_agent import ScannerAgent
        scanner_instance = ScannerAgent()

    agent = CveWatcherAgent(
        scanner=scanner_instance,
        artifacts_dir=args.artifacts_dir,
    )
    result = agent.watch_and_rescan(
        days_back=args.days_back,
        auto_rescan=args.auto_rescan,
    )

    logger.info(
        "CVE Watcher complete: %d new CVEs, %d probes, %d rescan findings",
        result.new_cve_count,
        result.new_probe_count,
        result.rescan_finding_count,
    )
