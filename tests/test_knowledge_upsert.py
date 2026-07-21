"""TDD tests for KnowledgeStoreTool upsert deduplication (12-02 Task 1).

Migrated to the shared PostgreSQL test_db fixture: KnowledgeStoreTool.forward()
is async and writes via async_session_scope() (aila_test). SQLite is no longer
supported at fixture setup (D-48/D-49), so the old settings_with_temp_db
fixture is gone -- tests seed against aila_test through the shared test_db
fixture in tests/conftest.py.
"""
from __future__ import annotations

import json


async def test_upsert_first_call_inserts(test_db):
    """First store with a dedup_key should return operation='inserted'."""
    from aila.config import get_settings
    from aila.platform.tools.knowledge import KnowledgeStoreTool

    tool = KnowledgeStoreTool(namespace="TestAgent", settings=get_settings())
    result = await tool.forward(
        "CVE-2024-1234 heap overflow in libfoo",
        {"source": "nvd", "_dedup_key": "CVE-2024-1234:host1:advisory"},
    )
    assert result["operation"] == "inserted", f"Expected inserted, got {result}"
    assert result["status"] == "stored"
    assert result["entry_id"] is not None


async def test_upsert_second_call_updates(test_db):
    """Second store with same dedup_key should return operation='updated' with same entry_id."""
    from aila.config import get_settings
    from aila.platform.tools.knowledge import KnowledgeStoreTool

    tool = KnowledgeStoreTool(namespace="TestAgent", settings=get_settings())
    r1 = await tool.forward(
        "CVE-2024-1234 heap overflow in libfoo",
        {"source": "nvd", "_dedup_key": "CVE-2024-1234:host1:advisory"},
    )
    r2 = await tool.forward(
        "CVE-2024-1234 heap overflow updated details",
        {"source": "nvd", "_dedup_key": "CVE-2024-1234:host1:advisory"},
    )
    assert r2["operation"] == "updated", f"Expected updated, got {r2}"
    assert r2["entry_id"] == r1["entry_id"], (
        f"entry_id should be same row, got {r2['entry_id']} vs {r1['entry_id']}"
    )


async def test_no_dedup_key_always_inserts(test_db):
    """Calls without _dedup_key always INSERT new rows (no dedup)."""
    from aila.config import get_settings
    from aila.platform.tools.knowledge import KnowledgeStoreTool

    tool = KnowledgeStoreTool(namespace="TestAgent", settings=get_settings())
    r3 = await tool.forward("some other content", {})
    r4 = await tool.forward("some other content", {})
    assert r3["operation"] == "inserted"
    assert r4["operation"] == "inserted"
    assert r3["entry_id"] != r4["entry_id"], "No-dedup_key inserts should produce distinct rows"


async def test_dedup_key_not_in_stored_metadata(test_db):
    """_dedup_key must be stripped from stored entry_metadata."""
    from sqlalchemy import text

    from aila.config import get_settings
    from aila.platform.tools.knowledge import KnowledgeStoreTool
    from aila.storage.database import session_scope

    tool = KnowledgeStoreTool(namespace="TestNS", settings=get_settings())
    r = await tool.forward("test content", {"tag": "advisory", "_dedup_key": "k1"})
    with session_scope() as s:
        raw = s.execute(
            text("SELECT entry_metadata FROM knowledgeentryrecord WHERE id = :id"),
            {"id": r["entry_id"]},
        ).fetchone()[0]
    meta = json.loads(raw)
    assert "_dedup_key" not in meta, f"_dedup_key leaked into stored metadata: {meta}"
    assert meta.get("tag") == "advisory", f"tag missing from metadata: {meta}"


async def test_upsert_race_resolves_to_update(test_db, monkeypatch):
    """A losing INSERT race on (namespace, dedup_key) resolves to an update (#37).

    Simulates the TOCTOU window: the pre-insert lookup misses the row a
    concurrent writer already committed, so forward() falls into the INSERT
    branch and the unique constraint rejects it. The tool must catch the
    IntegrityError and overwrite the winner row instead of surfacing a 500.
    """
    from aila.config import get_settings
    from aila.platform.tools.knowledge import KnowledgeStoreTool

    tool = KnowledgeStoreTool(namespace="RaceNS", settings=get_settings())
    winner = await tool.forward("original content", {"_dedup_key": "race-key"})
    assert winner["operation"] == "inserted", f"winner should insert, got {winner}"

    real_find = KnowledgeStoreTool._find_entry_id
    calls = {"n": 0}

    async def stale_then_real(session, namespace, dedup_key):
        calls["n"] += 1
        # First lookup returns None so forward() attempts the INSERT and hits
        # the live constraint; subsequent lookups delegate to the real query.
        if calls["n"] == 1:
            return None
        return await real_find(session, namespace, dedup_key)

    monkeypatch.setattr(
        KnowledgeStoreTool, "_find_entry_id", staticmethod(stale_then_real)
    )

    loser = await tool.forward("loser content", {"_dedup_key": "race-key"})
    assert loser["operation"] == "updated", f"race should resolve to update, got {loser}"
    assert loser["entry_id"] == winner["entry_id"], (
        f"race update must target the winner row, got {loser['entry_id']} vs {winner['entry_id']}"
    )


async def test_namespace_isolation_dedup(test_db):
    """Two agents with the same dedup_key produce independent rows."""
    from aila.config import get_settings
    from aila.platform.tools.knowledge import KnowledgeStoreTool

    tool_a = KnowledgeStoreTool(namespace="AgentA", settings=get_settings())
    tool_b = KnowledgeStoreTool(namespace="AgentB", settings=get_settings())
    r_a = await tool_a.forward("CVE-2024-1234", {"_dedup_key": "CVE-2024-1234:advisory"})
    r_b = await tool_b.forward("CVE-2024-1234", {"_dedup_key": "CVE-2024-1234:advisory"})
    assert r_a["operation"] == "inserted"
    assert r_b["operation"] == "inserted"
    assert r_a["entry_id"] != r_b["entry_id"], "Different namespaces should not share rows"
