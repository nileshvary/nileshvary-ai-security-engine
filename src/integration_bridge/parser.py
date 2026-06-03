"""Parser for garak ``hitlog.jsonl`` AND ``.report.jsonl`` outputs.

Real garak (NVIDIA's official tool) emits a ``.report.jsonl`` file whose
shape differs substantially from the legacy demo ``hitlog.jsonl``:

* Every row carries an ``entry_type`` discriminator
  (``start_run setup`` / ``init`` / ``config`` / ``attempt`` / ``eval`` /
  ``completion`` / ``digest``).
* Probe data lives in ``attempt`` rows under ``probe_classname`` (not
  ``probe``).
* ``prompt`` is a nested Conversation dict (text under ``.text``), not
  a string.
* ``outputs`` is a list of Message dicts, not a single ``output`` string.
* Hit signal is ``detector_results`` — a dict mapping detector name to
  a list of per-generation scores — not a single ``score`` float.
* ``eval`` rows carry authoritative per-probe ``total_evaluated``.

This parser auto-detects the format per row (presence of ``entry_type``)
and walks each kind of row appropriately. Legacy hitlog rows keep working
unchanged for backward compatibility with the demo fixture and tests.

Severity is binned from the per-probe attack success rate
``hits / total_attempts`` using ``_severity_from_rate``. Total attempts
are resolved with a strict precedence (see
``GarakParser._resolve_total_attempts``).
"""

from __future__ import annotations

import json
import logging
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from integration_bridge.models import Finding, Severity
from integration_bridge.owasp_mapper import (
    VALID_LLM_CATEGORIES,
    OwaspMapper,
)

logger = logging.getLogger(__name__)


# probe_classname is the field real garak emits inside attempt rows; the
# older legacy hitlog fixture uses probe / probe_name.
_PROBE_KEYS: tuple[str, ...] = ("probe", "probe_name", "probe_classname")
_DETECTOR_KEYS: tuple[str, ...] = ("detector", "detector_name")
_PROMPT_KEYS: tuple[str, ...] = ("prompt", "attack_prompt")
_RESPONSE_KEYS: tuple[str, ...] = ("output", "response", "model_response")

# Real-garak attempt.status values: 0 = not sent, 1 = response only,
# 2 = response + detector evaluation. Only status=2 carries the
# detector_results dict we need to surface as Findings.
_ATTEMPT_STATUS_EVALUATED: int = 2

_DEFAULT_SEVERITY: str = Severity.MEDIUM.value
_HIT_SCORE_THRESHOLD: float = 0.5


def _first_present(row: dict[str, Any], keys: tuple[str, ...]) -> str:
    """Return ``str(row[k])`` for the first key in ``keys`` present in ``row``.

    Returns an empty string when none of the keys are present or all are
    ``None``. Used to tolerate field-name drift across garak versions.
    """
    for key in keys:
        value = row.get(key)
        if value is not None:
            return str(value)
    return ""


def _extract_text(value: Any) -> str:
    """Pull a text string out of a real-garak prompt/output payload.

    Garak's ``attempt`` row stores prompts and outputs as nested
    Conversation/Message dicts (e.g. ``{"text": "..."}``) rather than
    bare strings. This helper accepts either shape and falls back to a
    JSON serialization for unexpected structures so callers always get
    a non-None string.
    """
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        text = value.get("text")
        if isinstance(text, str):
            return text
        # Some message shapes nest under messages / turns / conversations.
        for nested_key in ("messages", "turns", "conversations"):
            nested = value.get(nested_key)
            if isinstance(nested, list) and nested:
                return _extract_text(nested[-1])
        # Last resort: serialize so the raw shape is at least visible
        # to the operator in downstream UI.
        try:
            return json.dumps(value, ensure_ascii=False)
        except (TypeError, ValueError):
            return str(value)
    return str(value)


def _extract_output_texts(value: Any) -> list[str]:
    """Return a list of output text strings from a real-garak outputs field."""
    if value is None:
        return []
    if isinstance(value, list):
        return [_extract_text(item) for item in value]
    if isinstance(value, (str, dict)):
        return [_extract_text(value)]
    return [str(value)]


def _severity_from_rate(rate: float) -> str:
    """Bin an attack success rate into a severity bucket.

    Buckets are lower-inclusive, upper-exclusive, except the top bucket
    which is closed:

    * ``[0.00, 0.10)`` -> ``LOW``
    * ``[0.10, 0.40)`` -> ``MEDIUM``
    * ``[0.40, 0.70)`` -> ``HIGH``
    * ``[0.70, 1.00]`` -> ``CRITICAL``
    """
    if rate < 0.10:
        return Severity.LOW.value
    if rate < 0.40:
        return Severity.MEDIUM.value
    if rate < 0.70:
        return Severity.HIGH.value
    return Severity.CRITICAL.value


class GarakParser:
    """Parses a garak ``hitlog.jsonl`` file into normalized ``Finding`` records.

    Attributes:
        hitlog_path: Path to the JSONL file produced by garak.
    """

    def __init__(
        self,
        hitlog_path: Path,
        attempts_per_probe: dict[str, int] | None = None,
    ) -> None:
        """Initialize the parser.

        Args:
            hitlog_path: Path to garak's ``hitlog.jsonl`` (legacy demo
                format) or ``.report.jsonl`` (real garak output). The
                format is auto-detected per row based on the presence
                of an ``entry_type`` field.
            attempts_per_probe: Optional mapping of probe name to total
                attempts run for that probe. When supplied, this takes
                precedence over any per-row metadata when computing the
                attack success rate.
        """
        self.hitlog_path = hitlog_path
        self._attempts_per_probe: dict[str, int] = dict(attempts_per_probe or {})
        self._unknown_attempts: set[str] = set()
        # Populated by ``_read_rows`` when the input file contains
        # real-garak ``eval`` rows. Maps probe name to the largest
        # ``total_evaluated`` value seen — there is one eval row per
        # (probe, detector) pair, so a single probe can appear in
        # multiple eval rows.
        self._eval_totals: dict[str, int] = {}

    @property
    def unknown_attempts(self) -> set[str]:
        """Probes for which no total-attempts metadata was resolvable."""
        return set(self._unknown_attempts)

    def parse(self) -> list[Finding]:
        """Parse the configured hitlog into a list of ``Finding`` records.

        Returns:
            One ``Finding`` per valid row in the hitlog. Malformed rows
            (invalid JSON or missing probe name) are skipped with a
            WARNING and do not abort the parse.
        """
        logger.info("Parsing garak hitlog: %s", self.hitlog_path)
        rows = self._read_rows()
        hits_per_probe: Counter[str] = Counter(row["probe_name"] for row in rows)
        total_attempts = self._resolve_total_attempts(rows, hits_per_probe)

        findings: list[Finding] = []
        for row in rows:
            probe = row["probe_name"]
            attempts = total_attempts.get(probe)
            if attempts is None or attempts <= 0:
                severity = _DEFAULT_SEVERITY
            else:
                severity = _severity_from_rate(hits_per_probe[probe] / attempts)

            raw = row["raw_data"]
            llm_code, agentic_codes = self._resolve_owasp_category(raw, probe)
            score = raw.get("score")
            try:
                is_successful = score is None or float(score) >= _HIT_SCORE_THRESHOLD
            except (TypeError, ValueError):
                is_successful = True

            findings.append(
                Finding(
                    probe_name=probe,
                    detector_name=row["detector_name"],
                    attack_prompt=row["attack_prompt"],
                    model_response=row["model_response"],
                    is_successful_attack=is_successful,
                    owasp_llm_category=llm_code,
                    owasp_agentic_categories=agentic_codes,
                    severity=severity,
                    raw_data=raw,
                )
            )
            logger.debug(
                "Parsed row: probe=%s detector=%s severity=%s",
                probe,
                row["detector_name"],
                severity,
            )

        logger.info(
            "Parsed %d findings across %d probes",
            len(findings),
            len(hits_per_probe),
        )
        return findings

    def _read_rows(self) -> list[dict[str, Any]]:
        """Stream the JSONL file and return a list of normalized row dicts.

        Auto-detects the format per row. A row carrying an
        ``entry_type`` field is treated as real-garak output; otherwise
        it falls through to the legacy hitlog code path. The mixed-
        format file (real garak interleaves attempts / eval / config /
        etc.) is handled by skipping non-data entry types.
        """
        # Reset eval totals so re-running parse() on the same instance
        # does not leak state from a previous run.
        self._eval_totals = {}
        rows: list[dict[str, Any]] = []
        with self.hitlog_path.open("r", encoding="utf-8") as fh:
            for line_no, raw_line in enumerate(fh, start=1):
                line = raw_line.strip()
                if not line:
                    continue
                try:
                    raw: dict[str, Any] = json.loads(line)
                except json.JSONDecodeError as exc:
                    logger.warning(
                        "Skipping malformed JSON at line %d: %s", line_no, exc
                    )
                    continue

                # Real-garak format → entry_type-discriminated row.
                if "entry_type" in raw:
                    entry_type = raw.get("entry_type")
                    if entry_type == "attempt":
                        rows.extend(self._expand_attempt_row(raw, line_no))
                    elif entry_type == "eval":
                        self._record_eval_entry(raw)
                    # All other entry_types (start_run setup, init,
                    # config, completion, digest) carry run metadata
                    # we don't surface as Findings — skip silently.
                    continue

                # Legacy hitlog format → every line is a hit.
                probe = _first_present(raw, _PROBE_KEYS)
                if not probe:
                    logger.warning(
                        "Skipping row at line %d: no probe name in %s",
                        line_no,
                        sorted(raw.keys()),
                    )
                    continue
                rows.append(
                    {
                        "probe_name": probe,
                        "detector_name": _first_present(raw, _DETECTOR_KEYS),
                        "attack_prompt": _first_present(raw, _PROMPT_KEYS),
                        "model_response": _first_present(raw, _RESPONSE_KEYS),
                        "raw_data": raw,
                    }
                )
        return rows

    def _expand_attempt_row(
        self, attempt_row: dict[str, Any], line_no: int
    ) -> list[dict[str, Any]]:
        """Convert one real-garak ``attempt`` row into zero or more hit rows.

        For every (detector, generation_index) pair whose score crosses
        ``_HIT_SCORE_THRESHOLD`` we emit a single hit-row dict shaped
        like a legacy hitlog row, so the downstream Finding-construction
        loop in ``parse`` does not need a separate branch. Attempts
        with status != 2 (not evaluated) or with no ``detector_results``
        produce no rows.
        """
        status = attempt_row.get("status")
        try:
            status_int = int(status) if status is not None else None
        except (TypeError, ValueError):
            status_int = None
        if status_int != _ATTEMPT_STATUS_EVALUATED:
            return []

        probe = _first_present(attempt_row, _PROBE_KEYS)
        if not probe:
            logger.warning(
                "Skipping attempt at line %d: no probe_classname in %s",
                line_no,
                sorted(attempt_row.keys()),
            )
            return []

        prompt_text = _extract_text(attempt_row.get("prompt"))
        output_texts = _extract_output_texts(
            attempt_row.get("outputs") or attempt_row.get("output")
        )
        detector_results = attempt_row.get("detector_results")
        if not isinstance(detector_results, dict):
            return []

        hits: list[dict[str, Any]] = []
        for detector_name, scores in detector_results.items():
            if not isinstance(scores, list):
                continue
            for i, score in enumerate(scores):
                try:
                    score_f = float(score)
                except (TypeError, ValueError):
                    continue
                if score_f < _HIT_SCORE_THRESHOLD:
                    continue
                # raw_data preserves the original attempt row plus the
                # specific generation index + score that made it a hit,
                # so the operator can trace back to the exact event.
                hit_raw = dict(attempt_row)
                hit_raw["score"] = score_f
                hit_raw["_generation_index"] = i
                hit_raw["_detector_name"] = str(detector_name)
                hits.append(
                    {
                        "probe_name": probe,
                        "detector_name": str(detector_name),
                        "attack_prompt": prompt_text,
                        "model_response": (
                            output_texts[i] if i < len(output_texts) else ""
                        ),
                        "raw_data": hit_raw,
                    }
                )
        return hits

    def _record_eval_entry(self, eval_row: dict[str, Any]) -> None:
        """Stash the largest ``total_evaluated`` seen for each probe.

        Real garak emits one ``eval`` row per (probe, detector) pair
        with ``total_evaluated`` reflecting the number of attempts
        garak ran against that probe/detector pair. Different
        detectors should agree on the count, but we take ``max`` as a
        defensive choice in case they don't.
        """
        probe = eval_row.get("probe")
        total = eval_row.get("total_evaluated")
        if not probe or total is None:
            return
        try:
            total_int = int(total)
        except (TypeError, ValueError):
            return
        if total_int <= 0:
            return
        self._eval_totals[str(probe)] = max(
            self._eval_totals.get(str(probe), 0), total_int
        )

    def _resolve_owasp_category(
        self, raw: dict[str, Any], probe: str
    ) -> tuple[str, list[str]]:
        """Resolve the OWASP LLM code for a row, honoring inline overrides.

        Priority order (first valid value wins):

        1. ``raw["raw_data"]["owasp_llm_category"]`` — a nested
           ``raw_data`` sub-object's category field (some custom
           ingest pipelines attach this).
        2. ``raw["owasp_llm_category"]`` — a top-level category
           field on the JSON row itself.
        3. ``OwaspMapper.classify(probe)`` — pattern-match the probe
           name against the canonical mapping table.

        Any explicit value that is not in ``VALID_LLM_CATEGORIES`` is
        ignored (logged at WARNING) and we fall through to the next
        source — and ultimately to ``LLM01`` so the parser never
        emits a Finding with a bogus category that downstream stages
        would have to special-case.

        Returns ``(llm_code, agentic_codes)`` for direct use by the
        Finding-construction loop.
        """
        for source_name, value in self._owasp_category_candidates(raw):
            normalized = self._normalize_owasp_value(value)
            if normalized is None:
                continue
            if normalized in VALID_LLM_CATEGORIES:
                logger.debug(
                    "OWASP category resolved from %s: %s (probe=%s)",
                    source_name,
                    normalized,
                    probe,
                )
                return (
                    normalized,
                    OwaspMapper.map_llm_to_agentic(normalized),
                )
            logger.warning(
                "Ignoring invalid OWASP category %r from %s on probe %s",
                value,
                source_name,
                probe,
            )
        # Fallback — pattern-match the probe name.
        return OwaspMapper.classify(probe)

    @staticmethod
    def _owasp_category_candidates(
        raw: dict[str, Any],
    ) -> list[tuple[str, Any]]:
        """Return labeled candidate values to try, in priority order."""
        candidates: list[tuple[str, Any]] = []
        nested = raw.get("raw_data")
        if isinstance(nested, dict):
            candidates.append(
                ("raw_data.owasp_llm_category", nested.get("owasp_llm_category"))
            )
        candidates.append(
            ("top-level owasp_llm_category", raw.get("owasp_llm_category"))
        )
        return candidates

    @staticmethod
    def _normalize_owasp_value(value: Any) -> str | None:
        """Coerce a candidate value into a canonical ``LLMnn`` string.

        Accepts case-variant strings (``"llm01"``, ``"LLM1"``) and
        plain integers (``7`` -> ``"LLM07"``). Returns ``None`` only
        when the value cannot be turned into ``LLM<digits>`` form at
        all. Out-of-range values like ``LLM42`` are returned as
        ``"LLM42"`` so the caller can validate them against
        ``VALID_LLM_CATEGORIES`` and log a warning for invalid input —
        silently filtering here would hide misconfiguration.
        """
        if value is None:
            return None
        if isinstance(value, int):
            if value < 0:
                return None
            return f"LLM{value:02d}"
        if not isinstance(value, str):
            return None
        text = value.strip().upper()
        if not text.startswith("LLM"):
            return None
        digits = text[3:]
        if not digits.isdigit():
            return None
        try:
            n = int(digits)
        except ValueError:
            return None
        return f"LLM{n:02d}"

    def _resolve_total_attempts(
        self,
        rows: list[dict[str, Any]],
        hits_per_probe: Counter[str],
    ) -> dict[str, int]:
        """Resolve total attempts per probe using the documented precedence.

        Precedence (first matching source wins):
            1. ``attempts_per_probe`` argument passed to ``__init__``.
            2. Real-garak ``eval`` rows — authoritative ``total_evaluated``
               captured by ``_record_eval_entry``.
            3. Per-row ``total_attempts`` field on a legacy hitlog row
               (max across rows for the same probe).
            4. Per-row ``generations_per_prompt`` * distinct prompts seen.
            5. None resolved — caller falls back to ``MEDIUM`` and the
               probe is added to ``self._unknown_attempts``.
        """
        per_row_total: dict[str, int] = {}
        gens_by_probe: dict[str, int] = {}
        prompts_by_probe: defaultdict[str, set[str]] = defaultdict(set)

        for row in rows:
            probe = row["probe_name"]
            raw = row["raw_data"]
            if "total_attempts" in raw:
                try:
                    value = int(raw["total_attempts"])
                except (TypeError, ValueError):
                    value = 0
                if value > 0:
                    per_row_total[probe] = max(per_row_total.get(probe, 0), value)
            if "generations_per_prompt" in raw:
                try:
                    gens_by_probe[probe] = int(raw["generations_per_prompt"])
                except (TypeError, ValueError):
                    pass
            if row["attack_prompt"]:
                prompts_by_probe[probe].add(row["attack_prompt"])

        resolved: dict[str, int] = {}
        for probe in hits_per_probe:
            if probe in self._attempts_per_probe:
                resolved[probe] = self._attempts_per_probe[probe]
            elif probe in self._eval_totals:
                resolved[probe] = self._eval_totals[probe]
            elif probe in per_row_total:
                resolved[probe] = per_row_total[probe]
            elif probe in gens_by_probe and prompts_by_probe[probe]:
                resolved[probe] = gens_by_probe[probe] * len(prompts_by_probe[probe])
            else:
                self._unknown_attempts.add(probe)
                logger.warning(
                    "No attempts metadata for probe '%s'; severity will default to %s",
                    probe,
                    _DEFAULT_SEVERITY,
                )
        return resolved
