"""Tests for kb_insights() and KbInsightsTool (OPS-12 / plan 35-02, Task 2).

Post D-48/D-49: kb_insights is an ``async`` function backed by
``ServiceFactory().storage`` which uses the async engine cached by the
``test_db`` fixture. The legacy per-file SQLite ``Settings`` shim is gone;
seeding runs through the sync ``session_scope()`` helper pointed at
``aila_test`` by the shared fixture.
"""
from __future__ import annotations

import json

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

# KnowledgeEntryRecord.embedding is a pgvector Vector(384) column. A test-only
# zero vector satisfies the schema without pulling in the real embedding model.
_ZERO_EMBEDDING: list[float] = [0.0] * 384


def _insert_knowledge(*, namespace: str, content: str, entry_metadata=None) -> None:
    """Insert one KnowledgeEntryRecord into ``aila_test`` via sync session."""
    from aila.storage.database import session_scope
    from aila.storage.db_models import KnowledgeEntryRecord

    with session_scope() as session:
        record = KnowledgeEntryRecord(
            namespace=namespace,
            content=content,
            embedding=list(_ZERO_EMBEDDING),
            entry_metadata=json.dumps(entry_metadata or {}),
            dedup_key=None,
        )
        session.add(record)
        session.commit()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


async def test_empty_db_returns_empty_insights(test_db):
    """No KnowledgeEntryRecord rows -> total_entries==0, namespaces==[], top_cves==[]."""
    from aila.modules.vulnerability.tools.kb_insights import kb_insights

    result = await kb_insights()

    assert result["total_entries"] == 0
    assert result["namespaces"] == []
    assert result["top_cves"] == []


async def test_counts_by_namespace(test_db):
    """3 entries for 'RiskScoringAgent', 1 for 'SynthesisAgent' -> namespaces sorted by count desc."""
    from aila.modules.vulnerability.tools.kb_insights import kb_insights

    _insert_knowledge(namespace="RiskScoringAgent", content="entry one")
    _insert_knowledge(namespace="RiskScoringAgent", content="entry two")
    _insert_knowledge(namespace="RiskScoringAgent", content="entry three")
    _insert_knowledge(namespace="SynthesisAgent", content="synthesis entry")

    result = await kb_insights()

    assert result["total_entries"] == 4
    assert result["namespace_count"] == 2
    assert result["namespaces"][0] == {"namespace": "RiskScoringAgent", "count": 3}
    assert result["namespaces"][1] == {"namespace": "SynthesisAgent", "count": 1}


async def test_top_cves_extracted_from_content(test_db):
    """Entry with content containing 'CVE-2024-1234' -> CVE-2024-1234 appears in top_cves."""
    from aila.modules.vulnerability.tools.kb_insights import kb_insights

    _insert_knowledge(namespace="RiskScoringAgent", content="CVE-2024-1234 is critical and needs patching")

    result = await kb_insights()

    cve_ids = [c["cve_id"] for c in result["top_cves"]]
    assert "CVE-2024-1234" in cve_ids


async def test_top_cves_from_metadata_tags(test_db):
    """Entry with entry_metadata={'tags':['CVE-2024-5678']} -> CVE-2024-5678 in top_cves."""
    from aila.modules.vulnerability.tools.kb_insights import kb_insights

    _insert_knowledge(
        namespace="SynthesisAgent",
        content="general analysis",
        entry_metadata={"tags": ["CVE-2024-5678"]},
    )

    result = await kb_insights()

    cve_ids = [c["cve_id"] for c in result["top_cves"]]
    assert "CVE-2024-5678" in cve_ids


async def test_top_cves_deduped_and_counted(test_db):
    """Same CVE mentioned in 3 entries -> count==3 in top_cves."""
    from aila.modules.vulnerability.tools.kb_insights import kb_insights

    _insert_knowledge(namespace="RiskScoringAgent", content="CVE-2024-9999 is serious")
    _insert_knowledge(namespace="RiskScoringAgent", content="CVE-2024-9999 still unpatched")
    _insert_knowledge(namespace="SynthesisAgent", content="related to CVE-2024-9999 exploit chain")

    result = await kb_insights()

    cve_map = {c["cve_id"]: c["mention_count"] for c in result["top_cves"]}
    assert cve_map.get("CVE-2024-9999") == 3


async def test_top_cves_limited_to_10(test_db):
    """More than 10 distinct CVEs -> only top 10 by mention_count returned."""
    from aila.modules.vulnerability.tools.kb_insights import kb_insights

    # Insert 15 distinct CVEs, each with different mention counts
    for i in range(15):
        cve_id = f"CVE-2024-{1000 + i:04d}"
        for _ in range(i + 1):  # CVE-2024-1000 has 1 mention, ..., CVE-2024-1014 has 15 mentions
            _insert_knowledge(namespace="Agent", content=f"{cve_id} found on host")

    result = await kb_insights()

    assert len(result["top_cves"]) == 10
    # Verify sorted by mention_count descending
    counts = [c["mention_count"] for c in result["top_cves"]]
    assert counts == sorted(counts, reverse=True)


async def test_tool_rejects_bad_action(test_db):
    """KbInsightsTool().forward(action='bad') raises ValueError.

    ``SingleActionTool.forward`` is async, so the raise happens inside the
    awaited coroutine; wrapping ``await`` in ``pytest.raises`` is required
    (a bare call would only build the coroutine and DID NOT RAISE).
    """
    from aila.modules.vulnerability.tools.kb_insights import KbInsightsTool

    tool = KbInsightsTool()
    with pytest.raises(ValueError):
        await tool.forward(action="bad")
