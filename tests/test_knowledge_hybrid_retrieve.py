"""TDD tests for KnowledgeRetrieveTool hybrid FTS5 + vector search.

These tests require SQLite with FTS5 and sqlite-vec extensions.
SQLite is no longer supported as a production database (PostgreSQL only).
The tests are preserved for reference but skipped in CI.
"""
from __future__ import annotations

import os

import pytest

pytestmark = pytest.mark.skip(reason="SQLite-era tests; knowledge tool now uses PostgreSQL")

@pytest.fixture()
def populated_store(tmp_path):
    """Return (store, retrieve, settings) with two entries pre-loaded in 'SecAgent' namespace."""
    db_path = tmp_path / "test_hybrid.db"
    os.environ["AILA_DATABASE_URL"] = f"sqlite:///{db_path}"
    from aila.config import get_settings
    from aila.platform.tools.knowledge import KnowledgeRetrieveTool, KnowledgeStoreTool
    from aila.storage.database import init_db

    init_db()
    settings = get_settings()
    store = KnowledgeStoreTool(namespace="SecAgent", settings=settings)
    retrieve = KnowledgeRetrieveTool(namespace="SecAgent", settings=settings)

    store.forward(
        "CVE-2024-1234 heap overflow in libfoo allows remote code execution",
        {"source": "nvd"},
    )
    store.forward(
        "unrelated document about network topology and routing protocols",
        {"source": "other"},
    )
    yield store, retrieve, settings
    del os.environ["AILA_DATABASE_URL"]


def test_retrieve_returns_hybrid_flag(populated_store):
    """Results dict must include hybrid=True when knowledge_fts is available."""
    _, retrieve, _ = populated_store
    results = retrieve.forward("heap overflow remote code execution", limit=5)
    assert results["status"] == "retrieved"
    assert results["hybrid"] is True, "Expected hybrid=True when knowledge_fts is available"


def test_retrieve_returns_score_fields(populated_store):
    """Each result must have score, vec_score, fts_score, source fields."""
    _, retrieve, _ = populated_store
    results = retrieve.forward("heap overflow remote code execution", limit=5)
    assert results["count"] >= 1, f"Expected at least 1 result, got {results['count']}"
    top = results["results"][0]
    assert "score" in top, f"Missing score key: {top.keys()}"
    assert "vec_score" in top, f"Missing vec_score key: {top.keys()}"
    assert "fts_score" in top, f"Missing fts_score key: {top.keys()}"
    assert "source" in top, f"Missing source key: {top.keys()}"


def test_retrieve_source_values(populated_store):
    """source field must be one of 'hybrid', 'fts_only', 'vec_only'."""
    _, retrieve, _ = populated_store
    results = retrieve.forward("heap overflow remote code execution", limit=5)
    for r in results["results"]:
        assert r["source"] in ("hybrid", "fts_only", "vec_only"), (
            f"Unexpected source value: {r['source']}"
        )


def test_retrieve_score_in_range(populated_store):
    """Combined score must be in [0.0, 1.0]."""
    _, retrieve, _ = populated_store
    results = retrieve.forward("heap overflow remote code execution", limit=5)
    for r in results["results"]:
        assert 0.0 <= r["score"] <= 1.0, f"Score out of range: {r['score']}"


def test_retrieve_sorted_by_score_descending(populated_store):
    """Results must be sorted by score descending."""
    _, retrieve, _ = populated_store
    results = retrieve.forward("heap overflow remote code execution", limit=5)
    scores = [r["score"] for r in results["results"]]
    assert scores == sorted(scores, reverse=True), f"Results not sorted descending: {scores}"


def test_namespace_isolation(populated_store):
    """Retrieve from a different namespace must return 0 results."""
    _, _, settings = populated_store
    from aila.platform.tools.knowledge import KnowledgeRetrieveTool

    other = KnowledgeRetrieveTool(namespace="OtherAgent", settings=settings)
    other_results = other.forward("heap overflow", limit=5)
    assert other_results["count"] == 0, (
        f"Namespace leak: OtherAgent got {other_results['count']} results"
    )


def test_retrieve_no_distance_field(populated_store):
    """The old 'distance' field must be removed from results (replaced by score)."""
    _, retrieve, _ = populated_store
    results = retrieve.forward("heap overflow remote code execution", limit=5)
    for r in results["results"]:
        assert "distance" not in r, f"Old 'distance' field should not appear in results: {r.keys()}"
