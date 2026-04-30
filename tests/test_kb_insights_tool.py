"""Tests for kb_insights() and KbInsightsTool (OPS-12 / plan 35-02, Task 2)."""
from __future__ import annotations

import json

import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_settings(tmp_path):
    from aila.config import Settings
    return Settings(database_url=f"sqlite:///{(tmp_path / 'test.db').as_posix()}")


def _setup_db(settings):
    from aila.storage.database import init_db
    init_db(settings)


def _insert_knowledge(settings, *, namespace: str, content: str, entry_metadata=None) -> None:
    from aila.storage.db_models import KnowledgeEntryRecord
    from aila.storage.database import session_scope
    with session_scope(settings) as session:
        record = KnowledgeEntryRecord(
            namespace=namespace,
            content=content,
            embedding=b"",
            entry_metadata=json.dumps(entry_metadata or {}),
            dedup_key=None,
        )
        session.add(record)
        session.commit()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_empty_db_returns_empty_insights(tmp_path):
    """No KnowledgeEntryRecord rows -> total_entries==0, namespaces==[], top_cves==[]."""
    from aila.modules.vulnerability.tools.kb_insights import kb_insights

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    result = kb_insights(settings=settings)

    assert result["total_entries"] == 0
    assert result["namespaces"] == []
    assert result["top_cves"] == []


def test_counts_by_namespace(tmp_path):
    """3 entries for 'RiskScoringAgent', 1 for 'SynthesisAgent' -> namespaces sorted by count desc."""
    from aila.modules.vulnerability.tools.kb_insights import kb_insights

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    _insert_knowledge(settings, namespace="RiskScoringAgent", content="entry one")
    _insert_knowledge(settings, namespace="RiskScoringAgent", content="entry two")
    _insert_knowledge(settings, namespace="RiskScoringAgent", content="entry three")
    _insert_knowledge(settings, namespace="SynthesisAgent", content="synthesis entry")

    result = kb_insights(settings=settings)

    assert result["total_entries"] == 4
    assert result["namespace_count"] == 2
    assert result["namespaces"][0] == {"namespace": "RiskScoringAgent", "count": 3}
    assert result["namespaces"][1] == {"namespace": "SynthesisAgent", "count": 1}


def test_top_cves_extracted_from_content(tmp_path):
    """Entry with content containing 'CVE-2024-1234' -> CVE-2024-1234 appears in top_cves."""
    from aila.modules.vulnerability.tools.kb_insights import kb_insights

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    _insert_knowledge(settings, namespace="RiskScoringAgent", content="CVE-2024-1234 is critical and needs patching")

    result = kb_insights(settings=settings)

    cve_ids = [c["cve_id"] for c in result["top_cves"]]
    assert "CVE-2024-1234" in cve_ids


def test_top_cves_from_metadata_tags(tmp_path):
    """Entry with entry_metadata={'tags':['CVE-2024-5678']} -> CVE-2024-5678 in top_cves."""
    from aila.modules.vulnerability.tools.kb_insights import kb_insights

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    _insert_knowledge(settings, namespace="SynthesisAgent", content="general analysis",
                      entry_metadata={"tags": ["CVE-2024-5678"]})

    result = kb_insights(settings=settings)

    cve_ids = [c["cve_id"] for c in result["top_cves"]]
    assert "CVE-2024-5678" in cve_ids


def test_top_cves_deduped_and_counted(tmp_path):
    """Same CVE mentioned in 3 entries -> count==3 in top_cves."""
    from aila.modules.vulnerability.tools.kb_insights import kb_insights

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    _insert_knowledge(settings, namespace="RiskScoringAgent", content="CVE-2024-9999 is serious")
    _insert_knowledge(settings, namespace="RiskScoringAgent", content="CVE-2024-9999 still unpatched")
    _insert_knowledge(settings, namespace="SynthesisAgent", content="related to CVE-2024-9999 exploit chain")

    result = kb_insights(settings=settings)

    cve_map = {c["cve_id"]: c["mention_count"] for c in result["top_cves"]}
    assert cve_map.get("CVE-2024-9999") == 3


def test_top_cves_limited_to_10(tmp_path):
    """More than 10 distinct CVEs -> only top 10 by mention_count returned."""
    from aila.modules.vulnerability.tools.kb_insights import kb_insights

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    # Insert 15 distinct CVEs, each with different mention counts
    for i in range(15):
        cve_id = f"CVE-2024-{1000 + i:04d}"
        for _ in range(i + 1):  # CVE-2024-1000 has 1 mention, ..., CVE-2024-1014 has 15 mentions
            _insert_knowledge(settings, namespace="Agent", content=f"{cve_id} found on host")

    result = kb_insights(settings=settings)

    assert len(result["top_cves"]) == 10
    # Verify sorted by mention_count descending
    counts = [c["mention_count"] for c in result["top_cves"]]
    assert counts == sorted(counts, reverse=True)


def test_tool_rejects_bad_action(tmp_path):
    """KbInsightsTool().forward(action='bad') raises ValueError."""
    from aila.modules.vulnerability.tools.kb_insights import KbInsightsTool

    settings = _make_settings(tmp_path)
    _setup_db(settings)

    tool = KbInsightsTool(settings=settings)
    with pytest.raises(ValueError):
        tool.forward(action="bad")
