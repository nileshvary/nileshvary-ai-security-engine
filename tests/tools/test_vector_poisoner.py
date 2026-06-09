"""Tests for tools/vector_poisoner.py — real LLM08 vector embedding attacks."""

from __future__ import annotations

import sys
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from tools.vector_poisoner import DEFAULT_ATTACKS, VectorPoisoner


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _FakeQueryResult:
    """Mimics chromadb collection.query() return value."""

    def __init__(self, docs: list[str]) -> None:
        self._docs = docs

    def get(self, key: str, default: Any = None) -> Any:
        if key == "documents":
            return [self._docs]
        return default

    def __contains__(self, key: str) -> bool:
        return key == "documents"

    def __getitem__(self, key: str) -> Any:
        if key == "documents":
            return [self._docs]
        raise KeyError(key)


def _make_collection(docs_to_return: list[str], doc_count: int = 4) -> Any:
    """Return a mock chromadb Collection that yields the given docs on query."""
    col = MagicMock()
    col.count.return_value = doc_count
    col.query.return_value = {"documents": [docs_to_return]}
    return col


def _poisoner_with_factory(attack: dict[str, Any], docs: list[str]) -> VectorPoisoner:
    """Build a VectorPoisoner whose collection_factory returns a fixed set of docs."""

    def factory(_atk: dict) -> Any:
        return _make_collection(docs)

    return VectorPoisoner(collection_factory=factory)


# ---------------------------------------------------------------------------
# Test: poisoned document is retrieved in top-k
# ---------------------------------------------------------------------------


class TestPoisonedDocumentRetrieved:
    def test_attack_is_successful_when_poison_in_top_k(self) -> None:
        attack = DEFAULT_ATTACKS[0]  # DirectInstructionInjection
        poisoned_doc = attack["poisoned_doc"]
        poisoner = _poisoner_with_factory(attack, [poisoned_doc])

        results = poisoner.run_scan(attacks=[attack])

        assert len(results) == 1
        assert results[0]["is_successful_attack"] is True

    def test_attack_fails_when_poison_not_in_top_k(self) -> None:
        attack = DEFAULT_ATTACKS[0]
        clean_docs = attack["legitimate_docs"][:1]
        poisoner = _poisoner_with_factory(attack, clean_docs)

        results = poisoner.run_scan(attacks=[attack])

        assert results[0]["is_successful_attack"] is False


# ---------------------------------------------------------------------------
# Test: clean store has no successful attacks
# ---------------------------------------------------------------------------


class TestCleanStoreNoHits:
    def test_all_attacks_fail_against_clean_corpus(self) -> None:
        for attack in DEFAULT_ATTACKS:
            clean_docs = attack["legitimate_docs"]
            poisoner = _poisoner_with_factory(attack, clean_docs)
            results = poisoner.run_scan(attacks=[attack])
            assert results[0]["is_successful_attack"] is False, (
                f"Attack {attack['name']} should not succeed against clean docs"
            )


# ---------------------------------------------------------------------------
# Test: all five attack patterns run
# ---------------------------------------------------------------------------


class TestAllFiveAttackPatterns:
    def test_five_results_returned(self) -> None:
        def factory(atk: dict) -> Any:
            return _make_collection(atk["legitimate_docs"])

        poisoner = VectorPoisoner(collection_factory=factory)
        results = poisoner.run_scan()

        assert len(results) == 5

    def test_all_probe_names_are_distinct(self) -> None:
        def factory(atk: dict) -> Any:
            return _make_collection(atk["legitimate_docs"])

        poisoner = VectorPoisoner(collection_factory=factory)
        results = poisoner.run_scan()
        names = [r["probe_name"] for r in results]
        assert len(set(names)) == 5


# ---------------------------------------------------------------------------
# Test: result dict has required keys
# ---------------------------------------------------------------------------


class TestResultSchema:
    REQUIRED_KEYS = {
        "probe_name",
        "owasp",
        "agentic",
        "attack_prompt",
        "model_response",
        "is_successful_attack",
        "source",
    }

    def test_all_required_keys_present(self) -> None:
        attack = DEFAULT_ATTACKS[0]

        def factory(_atk: dict) -> Any:
            return _make_collection([])

        poisoner = VectorPoisoner(collection_factory=factory)
        results = poisoner.run_scan(attacks=[attack])
        assert len(results) == 1
        missing = self.REQUIRED_KEYS - results[0].keys()
        assert not missing, f"Missing keys: {missing}"

    def test_owasp_is_llm08(self) -> None:
        def factory(_atk: dict) -> Any:
            return _make_collection([])

        poisoner = VectorPoisoner(collection_factory=factory)
        for r in poisoner.run_scan():
            assert r["owasp"] == "LLM08"

    def test_agentic_contains_asi06(self) -> None:
        def factory(_atk: dict) -> Any:
            return _make_collection([])

        poisoner = VectorPoisoner(collection_factory=factory)
        for r in poisoner.run_scan():
            assert "ASI06" in r["agentic"]

    def test_source_is_vector(self) -> None:
        def factory(_atk: dict) -> Any:
            return _make_collection([])

        poisoner = VectorPoisoner(collection_factory=factory)
        for r in poisoner.run_scan():
            assert r["source"] == "vector"


# ---------------------------------------------------------------------------
# Test: import guard raises when chromadb missing
# ---------------------------------------------------------------------------


class TestImportGuard:
    def test_raises_import_error_when_chromadb_missing(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        import builtins

        real_import = builtins.__import__

        def patched_import(name: str, *args: Any, **kwargs: Any) -> Any:
            if name == "chromadb":
                raise ImportError("No module named 'chromadb'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", patched_import)

        # Remove cached module so the patched import path is hit
        monkeypatch.delitem(sys.modules, "chromadb", raising=False)

        with pytest.raises(ImportError, match="chromadb is not installed"):
            VectorPoisoner()
