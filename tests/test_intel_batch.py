"""Tests for SCALE-04: cve_cache_get_batch action on CVECacheIntelTool (Phase 41 Plan 01).

Verifies:
1. batch fetch returns populated dict for existing IDs
2. batch fetch returns {} for IDs not in DB
3. batch fetch returns {} for empty list
4. batch fetch returns {} for None input
5. batch fetch issues exactly one storage-level query, not N queries

Post D-48/D-49: no in-memory SQLite. All DB work runs against aila_test via
the shared ``test_db`` fixture in ``tests/conftest.py``; seed data is inserted
through the sync ``session_scope()`` helper and the production call sites hit
the async engine via ``ServiceFactory().storage``.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from unittest.mock import MagicMock

from aila.modules.vulnerability.db_models import CacheRecord
from aila.modules.vulnerability.tools.intel_cache import CVECacheIntelTool, _forward_cve_cache_batch

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _seed_cve_intel_rows() -> None:
    """Insert two ``cve_intel`` cache rows into ``aila_test`` via sync session."""
    from aila.storage.database import session_scope

    with session_scope() as session:
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


# ---------------------------------------------------------------------------
# _forward_cve_cache_batch unit tests (direct async function call)
# ---------------------------------------------------------------------------


async def test_batch_returns_dict_for_existing_ids(test_db):
    """cve_cache_get_batch returns a populated dict for IDs that exist."""
    _seed_cve_intel_rows()

    result = await _forward_cve_cache_batch(
        MagicMock(),
        cve_ids=["CVE-2021-1", "CVE-2021-2"],
    )

    assert "CVE-2021-1" in result
    assert "CVE-2021-2" in result
    assert result["CVE-2021-1"]["severity"] == "HIGH"
    assert result["CVE-2021-2"]["score"] == 5.5


async def test_batch_returns_empty_for_missing_ids(test_db):
    """cve_cache_get_batch returns {} for IDs not in DB."""
    _seed_cve_intel_rows()

    result = await _forward_cve_cache_batch(MagicMock(), cve_ids=["CVE-MISSING"])

    assert result == {}


async def test_batch_returns_empty_for_empty_list(test_db):
    """_forward_cve_cache_batch with empty list should return {}."""
    _seed_cve_intel_rows()

    result = await _forward_cve_cache_batch(MagicMock(), cve_ids=[])

    assert result == {}


# ---------------------------------------------------------------------------
# CVECacheIntelTool.forward integration tests
# ---------------------------------------------------------------------------


def _make_tool() -> CVECacheIntelTool:
    """Return a CVECacheIntelTool with a stub settings object.

    The tool's real ``__init__`` calls ``get_settings()`` which requires the
    real config surface; bypass it because production DB access flows through
    ``ServiceFactory`` and the ambient async engine picked up from
    ``AILA_DATABASE_URL`` (already set by the ``test_db`` fixture).
    """
    tool = CVECacheIntelTool.__new__(CVECacheIntelTool)
    tool.settings = MagicMock()
    return tool


async def test_forward_cve_cache_get_batch_returns_populated_dict(test_db):
    """forward(action='cve_cache_get_batch', ...) returns populated dict for existing IDs."""
    _seed_cve_intel_rows()
    tool = _make_tool()

    result = await tool.forward(
        action="cve_cache_get_batch",
        cve_ids=["CVE-2021-1", "CVE-2021-2"],
    )

    assert "CVE-2021-1" in result
    assert "CVE-2021-2" in result


async def test_forward_cve_cache_get_batch_missing_ids_returns_empty(test_db):
    """forward(action='cve_cache_get_batch', cve_ids=['CVE-MISSING']) returns {}."""
    _seed_cve_intel_rows()
    tool = _make_tool()

    result = await tool.forward(action="cve_cache_get_batch", cve_ids=["CVE-MISSING"])

    assert result == {}


async def test_forward_cve_cache_get_batch_empty_list_returns_empty():
    """forward(action='cve_cache_get_batch', cve_ids=[]) returns {} without hitting DB.

    The tool short-circuits on an empty list before any storage call, so no
    ``test_db`` fixture is required here.
    """
    tool = _make_tool()

    result = await tool.forward(action="cve_cache_get_batch", cve_ids=[])
    assert result == {}


async def test_forward_cve_cache_get_batch_none_returns_empty():
    """forward(action='cve_cache_get_batch', cve_ids=None) returns {} without hitting DB."""
    tool = _make_tool()

    result = await tool.forward(action="cve_cache_get_batch", cve_ids=None)
    assert result == {}


async def test_forward_cve_cache_get_batch_issues_single_query(test_db, monkeypatch):
    """forward(action='cve_cache_get_batch', cve_ids=[A, B, C]) issues exactly one storage fetch.

    ``_forward_cve_cache_batch`` is expected to make one ``fetch_all`` call
    that maps to a single ``SELECT ... WHERE cache_key IN (...)`` round trip
    instead of N per-ID lookups. Counting ``StorageService.fetch_all``
    invocations is a faithful proxy for that invariant.
    """
    _seed_cve_intel_rows()
    tool = _make_tool()

    from aila.platform.services import storage as _storage_mod

    call_count = 0
    original_fetch_all = _storage_mod.StorageService.fetch_all

    async def _counting_fetch_all(self, model_class, *filters, session=None):
        nonlocal call_count
        call_count += 1
        return await original_fetch_all(self, model_class, *filters, session=session)

    monkeypatch.setattr(
        _storage_mod.StorageService,
        "fetch_all",
        _counting_fetch_all,
    )

    result = await tool.forward(
        action="cve_cache_get_batch",
        cve_ids=["CVE-2021-1", "CVE-2021-2", "CVE-MISSING-X"],
    )

    assert call_count == 1, f"Expected 1 storage fetch_all, got {call_count}"
    # Sanity: the two seeded rows come back; missing is absent.
    assert "CVE-2021-1" in result
    assert "CVE-2021-2" in result
    assert "CVE-MISSING-X" not in result
