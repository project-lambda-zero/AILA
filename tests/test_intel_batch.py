"""Tests for SCALE-04: cve_cache_get_batch action on CVECacheIntelTool (Phase 41 Plan 01).

Verifies:
1. batch fetch returns populated dict for existing IDs
2. batch fetch returns {} for IDs not in DB
3. batch fetch returns {} for empty list
4. batch fetch returns {} for None input
5. batch fetch issues exactly one SELECT query, not N queries
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import MagicMock, patch

import pytest
from sqlmodel import Session, SQLModel, create_engine

from aila.modules.vulnerability.db_models import CacheRecord
from aila.modules.vulnerability.tools.intel_cache import CVECacheIntelTool, _forward_cve_cache_batch

# ---------------------------------------------------------------------------
# In-memory DB fixture
# ---------------------------------------------------------------------------

@pytest.fixture()
def in_memory_engine():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(engine)
    return engine


@pytest.fixture()
def populated_session(in_memory_engine):
    """Return an engine with two CVE cache rows pre-inserted."""
    with Session(in_memory_engine) as session:
        session.add(CacheRecord(
            namespace="cve_intel",
            cache_key="CVE-2021-1",
            payload_json=json.dumps({"severity": "HIGH", "score": 8.1}),
            last_synced_at=datetime(2024, 1, 1, tzinfo=UTC),
        ))
        session.add(CacheRecord(
            namespace="cve_intel",
            cache_key="CVE-2021-2",
            payload_json=json.dumps({"severity": "MEDIUM", "score": 5.5}),
            last_synced_at=datetime(2024, 1, 2, tzinfo=UTC),
        ))
        session.commit()
    return in_memory_engine


# ---------------------------------------------------------------------------
# _forward_cve_cache_batch unit tests (direct function call)
# ---------------------------------------------------------------------------

def test_batch_returns_dict_for_existing_ids(populated_session):
    """cve_cache_get_batch returns a populated dict for IDs that exist."""
    mock_settings = MagicMock()

    with patch("aila.modules.vulnerability.tools.intel_cache.session_scope") as mock_scope:
        mock_scope.return_value.__enter__ = lambda s, *a, **kw: Session(populated_session)
        mock_scope.return_value.__exit__ = MagicMock(return_value=False)

        # Use context-manager correctly
        session_instance = Session(populated_session)

        class _CM:
            def __enter__(self):
                return session_instance
            def __exit__(self, *args):
                session_instance.close()
                return False

        mock_scope.return_value = _CM()

        result = _forward_cve_cache_batch(mock_settings, cve_ids=["CVE-2021-1", "CVE-2021-2"])

    assert "CVE-2021-1" in result
    assert "CVE-2021-2" in result
    assert result["CVE-2021-1"]["severity"] == "HIGH"
    assert result["CVE-2021-2"]["score"] == 5.5


def test_batch_returns_empty_for_missing_ids(populated_session):
    """cve_cache_get_batch returns {} for IDs not in DB."""
    mock_settings = MagicMock()

    session_instance = Session(populated_session)

    class _CM:
        def __enter__(self):
            return session_instance
        def __exit__(self, *args):
            session_instance.close()
            return False

    with patch("aila.modules.vulnerability.tools.intel_cache.session_scope", return_value=_CM()):
        result = _forward_cve_cache_batch(mock_settings, cve_ids=["CVE-MISSING"])

    assert result == {}


def test_batch_returns_empty_for_empty_list(populated_session):
    """_forward_cve_cache_batch with empty list should return {}."""
    mock_settings = MagicMock()
    # forward() normalizes before calling _forward_cve_cache_batch, but direct call with [] also valid
    # Since the forward() guard returns early for empty, we test direct function
    session_instance = Session(populated_session)

    class _CM:
        def __enter__(self):
            return session_instance
        def __exit__(self, *args):
            session_instance.close()
            return False

    with patch("aila.modules.vulnerability.tools.intel_cache.session_scope", return_value=_CM()):
        # direct call with empty list — no query should be needed but behavior is just {}
        result = _forward_cve_cache_batch(mock_settings, cve_ids=[])

    assert result == {}


# ---------------------------------------------------------------------------
# CVECacheIntelTool.forward integration tests
# ---------------------------------------------------------------------------

def _make_tool_with_engine(engine):
    """Return a CVECacheIntelTool whose session_scope uses the given engine."""
    mock_settings = MagicMock()
    tool = CVECacheIntelTool.__new__(CVECacheIntelTool)
    tool.settings = mock_settings
    return tool


def test_forward_cve_cache_get_batch_returns_populated_dict(populated_session):
    """forward(action='cve_cache_get_batch', ...) returns populated dict for existing IDs."""
    tool = _make_tool_with_engine(populated_session)

    session_instance = Session(populated_session)

    class _CM:
        def __enter__(self):
            return session_instance
        def __exit__(self, *args):
            session_instance.close()
            return False

    with patch("aila.modules.vulnerability.tools.intel_cache.session_scope", return_value=_CM()):
        result = tool.forward(action="cve_cache_get_batch", cve_ids=["CVE-2021-1", "CVE-2021-2"])

    assert "CVE-2021-1" in result
    assert "CVE-2021-2" in result


def test_forward_cve_cache_get_batch_missing_ids_returns_empty(populated_session):
    """forward(action='cve_cache_get_batch', cve_ids=['CVE-MISSING']) returns {}."""
    tool = _make_tool_with_engine(populated_session)

    session_instance = Session(populated_session)

    class _CM:
        def __enter__(self):
            return session_instance
        def __exit__(self, *args):
            session_instance.close()
            return False

    with patch("aila.modules.vulnerability.tools.intel_cache.session_scope", return_value=_CM()):
        result = tool.forward(action="cve_cache_get_batch", cve_ids=["CVE-MISSING"])

    assert result == {}


def test_forward_cve_cache_get_batch_empty_list_returns_empty():
    """forward(action='cve_cache_get_batch', cve_ids=[]) returns {} without hitting DB."""
    tool = CVECacheIntelTool.__new__(CVECacheIntelTool)
    tool.settings = MagicMock()

    result = tool.forward(action="cve_cache_get_batch", cve_ids=[])
    assert result == {}


def test_forward_cve_cache_get_batch_none_returns_empty():
    """forward(action='cve_cache_get_batch', cve_ids=None) returns {} without hitting DB."""
    tool = CVECacheIntelTool.__new__(CVECacheIntelTool)
    tool.settings = MagicMock()

    result = tool.forward(action="cve_cache_get_batch", cve_ids=None)
    assert result == {}


def test_forward_cve_cache_get_batch_issues_single_query(populated_session):
    """forward(action='cve_cache_get_batch', cve_ids=[A, B, C]) issues exactly one SELECT query."""
    tool = _make_tool_with_engine(populated_session)

    query_count = 0
    original_exec = Session.exec

    def counting_exec(self, statement, *args, **kwargs):
        nonlocal query_count
        query_count += 1
        return original_exec(self, statement, *args, **kwargs)

    session_instance = Session(populated_session)

    class _CM:
        def __enter__(self):
            return session_instance
        def __exit__(self, *args):
            session_instance.close()
            return False

    with patch("aila.modules.vulnerability.tools.intel_cache.session_scope", return_value=_CM()):
        with patch.object(type(session_instance), "exec", counting_exec):
            result = tool.forward(
                action="cve_cache_get_batch",
                cve_ids=["CVE-2021-1", "CVE-2021-2", "CVE-MISSING-X"],
            )

    assert query_count == 1, f"Expected 1 SELECT query, got {query_count}"
