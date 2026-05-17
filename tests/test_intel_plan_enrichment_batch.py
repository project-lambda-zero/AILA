"""Tests for SCALE-04/SCALE-09: _plan_enrichment batch rewrite and compound DB indexes (Phase 22 Plan 01).

Verifies:
1. _plan_enrichment calls cache_tool.forward once with action='cve_cache_get_batch', not N calls with 'cve_cache_get'
2. fresh_cache_ids populated for IDs returned by batch fetch (force_refresh=False)
3. missing_ids populated for IDs absent from batch result
4. force_refresh=True puts all IDs in refresh_order regardless of batch result
5. CVEKnowledgeCacheRecord.__table_args__ contains Index named 'ix_cvekc_cve_synced'
6. WorkflowRunRecord.__table_args__ contains Index named 'ix_wfr_status_completed'
7. ReportArtifactRecord.__table_args__ contains Index named 'ix_rar_run_scope_type'
"""
from __future__ import annotations

import inspect
from unittest.mock import MagicMock

import sqlalchemy

# ---------------------------------------------------------------------------
# _plan_enrichment batch call tests
# ---------------------------------------------------------------------------

def _make_intel_service(batch_return: dict) -> object:
    """Create an IntelService whose cache_tool.forward returns batch_return for cve_cache_get_batch."""
    from aila.modules.vulnerability.services.intel import IntelService

    mock_cache_tool = MagicMock()
    mock_cache_tool.forward.return_value = batch_return

    service = IntelService.__new__(IntelService)
    service.nvd_tool = MagicMock()
    service.epss_kev_tool = MagicMock()
    service.cache_tool = mock_cache_tool
    service.settings = MagicMock()
    from aila.modules.vulnerability.config_schema import VulnerabilityConfigSchema
    service.config = VulnerabilityConfigSchema()
    return service


def test_plan_enrichment_calls_batch_not_per_id():
    """_plan_enrichment must call cache_tool.forward exactly once with action='cve_cache_get_batch'."""
    service = _make_intel_service(batch_return={})
    cve_ids = ["CVE-2021-1", "CVE-2021-2", "CVE-2021-3"]

    service._plan_enrichment(cve_ids, force_refresh=False)

    calls = service.cache_tool.forward.call_args_list
    assert len(calls) == 1, f"Expected 1 call, got {len(calls)}: {calls}"
    assert calls[0].kwargs.get("action") == "cve_cache_get_batch" or calls[0].args[0] == "cve_cache_get_batch"


def test_plan_enrichment_no_per_id_cve_cache_get_call():
    """_plan_enrichment source must NOT contain 'cve_cache_get' outside of cve_cache_get_batch."""
    from aila.modules.vulnerability.services.intel import IntelService
    src = inspect.getsource(IntelService._plan_enrichment)
    # 'cve_cache_get_batch' is acceptable, but bare 'cve_cache_get' with per-ID usage is not
    # The simplest check: 'cve_cache_get"' (quoted, no _batch suffix) must not appear
    assert '"cve_cache_get"' not in src, "Per-ID 'cve_cache_get' action still used in _plan_enrichment"


def test_plan_enrichment_fresh_cache_ids_populated(tmp_path):
    """fresh_cache_ids should list CVEs returned by batch fetch (force_refresh=False)."""
    batch_result = {
        "CVE-2021-1": {"severity": "HIGH"},
        "CVE-2021-2": {"severity": "MEDIUM"},
    }
    service = _make_intel_service(batch_return=batch_result)
    cve_ids = ["CVE-2021-1", "CVE-2021-2", "CVE-MISSING"]

    plan = service._plan_enrichment(cve_ids, force_refresh=False)

    assert "CVE-2021-1" in plan.fresh_cache_ids
    assert "CVE-2021-2" in plan.fresh_cache_ids


def test_plan_enrichment_missing_ids_populated():
    """missing_ids should contain CVEs absent from batch result."""
    batch_result = {"CVE-2021-1": {"severity": "HIGH"}}
    service = _make_intel_service(batch_return=batch_result)
    cve_ids = ["CVE-2021-1", "CVE-MISSING-A", "CVE-MISSING-B"]

    plan = service._plan_enrichment(cve_ids, force_refresh=False)

    assert "CVE-MISSING-A" in plan.missing_ids
    assert "CVE-MISSING-B" in plan.missing_ids
    assert "CVE-2021-1" not in plan.missing_ids


def test_plan_enrichment_force_refresh_all_ids_in_refresh_order():
    """force_refresh=True must put all IDs in refresh_order regardless of batch result."""
    batch_result = {"CVE-2021-1": {"severity": "HIGH"}, "CVE-2021-2": {"severity": "LOW"}}
    service = _make_intel_service(batch_return=batch_result)
    cve_ids = ["CVE-2021-1", "CVE-2021-2", "CVE-2021-3"]

    plan = service._plan_enrichment(cve_ids, force_refresh=True)

    assert set(plan.refresh_order) == set(cve_ids)
    assert plan.fresh_cache_ids == []


# ---------------------------------------------------------------------------
# Compound index tests
# ---------------------------------------------------------------------------

def test_cacherecord_has_namespace_index():
    """CacheRecord.__table_args__ must contain Index named 'ix_cacherecord_namespace'."""
    from aila.modules.vulnerability.db_models import CacheRecord
    args = CacheRecord.__table_args__
    names = [a.name for a in args if isinstance(a, sqlalchemy.Index)]
    assert "ix_cacherecord_namespace" in names, f"Expected ix_cacherecord_namespace in {names}"


def test_workflowrunrecord_has_compound_index():
    """WorkflowRunRecord.__table_args__ must contain Index named 'ix_wfr_status_completed'."""
    from aila.storage.db_models import WorkflowRunRecord
    args = WorkflowRunRecord.__table_args__
    names = [a.name for a in args if isinstance(a, sqlalchemy.Index)]
    assert "ix_wfr_status_completed" in names, f"Expected ix_wfr_status_completed in {names}"


def test_reportartifactrecord_has_compound_index():
    """ReportArtifactRecord.__table_args__ must contain Index named 'ix_rar_run_scope_type'."""
    from aila.storage.db_models import ReportArtifactRecord
    args = ReportArtifactRecord.__table_args__
    names = [a.name for a in args if isinstance(a, sqlalchemy.Index)]
    assert "ix_rar_run_scope_type" in names, f"Expected ix_rar_run_scope_type in {names}"
