"""TDD tests for KnowledgeStoreTool upsert deduplication (12-02 Task 1)."""
from __future__ import annotations

import json
import os

import pytest


@pytest.fixture()
def settings_with_temp_db(tmp_path):
    """Return PlatformSettings pointing at a fresh temp SQLite database.

    Cache isolation: _build_settings is memoized. Clear before setting env var
    so init_db() constructs Settings from the temp path. Clear again in teardown
    so subsequent tests do not inherit the temp database_url.
    """
    from aila.config import _build_settings

    db_path = tmp_path / "test_knowledge.db"
    _build_settings.cache_clear()                              # clear stale cache
    os.environ["AILA_DATABASE_URL"] = f"sqlite:///{db_path}"
    from aila.storage.database import init_db
    from aila.config import get_settings

    init_db()
    yield get_settings()
    del os.environ["AILA_DATABASE_URL"]
    _build_settings.cache_clear()                              # prevent leak to next test


def test_upsert_first_call_inserts(settings_with_temp_db):
    """First store with a dedup_key should return operation='inserted'."""
    from aila.platform.tools.knowledge import KnowledgeStoreTool

    tool = KnowledgeStoreTool(namespace="TestAgent", settings=settings_with_temp_db)
    result = tool.forward(
        "CVE-2024-1234 heap overflow in libfoo",
        {"source": "nvd", "_dedup_key": "CVE-2024-1234:host1:advisory"},
    )
    assert result["operation"] == "inserted", f"Expected inserted, got {result}"
    assert result["status"] == "stored"
    assert result["entry_id"] is not None


def test_upsert_second_call_updates(settings_with_temp_db):
    """Second store with same dedup_key should return operation='updated' with same entry_id."""
    from aila.platform.tools.knowledge import KnowledgeStoreTool

    tool = KnowledgeStoreTool(namespace="TestAgent", settings=settings_with_temp_db)
    r1 = tool.forward(
        "CVE-2024-1234 heap overflow in libfoo",
        {"source": "nvd", "_dedup_key": "CVE-2024-1234:host1:advisory"},
    )
    r2 = tool.forward(
        "CVE-2024-1234 heap overflow updated details",
        {"source": "nvd", "_dedup_key": "CVE-2024-1234:host1:advisory"},
    )
    assert r2["operation"] == "updated", f"Expected updated, got {r2}"
    assert r2["entry_id"] == r1["entry_id"], (
        f"entry_id should be same row, got {r2['entry_id']} vs {r1['entry_id']}"
    )


def test_no_dedup_key_always_inserts(settings_with_temp_db):
    """Calls without _dedup_key always INSERT new rows (no dedup)."""
    from aila.platform.tools.knowledge import KnowledgeStoreTool

    tool = KnowledgeStoreTool(namespace="TestAgent", settings=settings_with_temp_db)
    r3 = tool.forward("some other content", {})
    r4 = tool.forward("some other content", {})
    assert r3["operation"] == "inserted"
    assert r4["operation"] == "inserted"
    assert r3["entry_id"] != r4["entry_id"], "No-dedup_key inserts should produce distinct rows"


def test_dedup_key_not_in_stored_metadata(settings_with_temp_db):
    """_dedup_key must be stripped from stored entry_metadata."""
    from aila.platform.tools.knowledge import KnowledgeStoreTool
    from aila.storage.database import session_scope
    from sqlalchemy import text

    tool = KnowledgeStoreTool(namespace="TestNS", settings=settings_with_temp_db)
    r = tool.forward("test content", {"tag": "advisory", "_dedup_key": "k1"})
    with session_scope(settings_with_temp_db) as s:
        raw = s.execute(
            text("SELECT entry_metadata FROM knowledgeentryrecord WHERE id = :id"),
            {"id": r["entry_id"]},
        ).fetchone()[0]
    meta = json.loads(raw)
    assert "_dedup_key" not in meta, f"_dedup_key leaked into stored metadata: {meta}"
    assert meta.get("tag") == "advisory", f"tag missing from metadata: {meta}"


def test_namespace_isolation_dedup(settings_with_temp_db):
    """Two agents with the same dedup_key produce independent rows."""
    from aila.platform.tools.knowledge import KnowledgeStoreTool

    tool_a = KnowledgeStoreTool(namespace="AgentA", settings=settings_with_temp_db)
    tool_b = KnowledgeStoreTool(namespace="AgentB", settings=settings_with_temp_db)
    r_a = tool_a.forward("CVE-2024-1234", {"_dedup_key": "CVE-2024-1234:advisory"})
    r_b = tool_b.forward("CVE-2024-1234", {"_dedup_key": "CVE-2024-1234:advisory"})
    assert r_a["operation"] == "inserted"
    assert r_b["operation"] == "inserted"
    assert r_a["entry_id"] != r_b["entry_id"], "Different namespaces should not share rows"
