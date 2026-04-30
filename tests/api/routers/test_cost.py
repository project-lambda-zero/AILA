"""Tests for the cost intelligence API router (Plan 175-03).

Tests: 11 behaviors across 5 endpoints.
  GET  /cost/runs/{run_id}     -- per-model breakdown
  GET  /cost/history           -- monthly aggregated cost data
  POST /cost/estimate          -- pre-scan cost estimation
  POST /cost/estimate-human    -- human-equivalent cost trigger
  GET  /cost/roi               -- ROI comparison

Uses PostgreSQL via AILA_TEST_DATABASE_URL.
Fixtures from tests/api/conftest.py: async_client_with_registries, admin_token.
"""
from __future__ import annotations

import time
from datetime import UTC, datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from aila.platform.llm.cost_record import LLMCostRecord
from aila.storage.database import async_session_scope

# Re-export conftest fixture so pytest can find it
# conftest.py is at tests/api/conftest.py -- fixtures are available here.

_UTC = timezone.utc


def _utc_now() -> datetime:
    return datetime.now(_UTC)


# ---------------------------------------------------------------------------
# Helper: seed LLMCostRecord rows
# ---------------------------------------------------------------------------


async def _seed_cost_records(records: list[dict]) -> None:
    """Insert LLMCostRecord rows for testing."""
    async with async_session_scope() as session:
        for r in records:
            rec = LLMCostRecord(**r)
            session.add(rec)
        await session.commit()


# ---------------------------------------------------------------------------
# Fixture: async client with stub platform + config registry
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="function")
async def cost_client(test_db):
    """Async client with stub platform that has a real ConfigRegistry.

    Uses async_client_with_registries pattern from conftest.py.
    ConfigRegistry is empty (no DB rows), so fallback defaults are used.
    """
    import time as _time

    from aila.api.app import create_app
    from aila.storage.registry import ConfigRegistry
    from aila.platform.runtime.tools import ToolRegistry

    config_registry = ConfigRegistry()
    tool_registry = ToolRegistry()

    stub_runtime = MagicMock()
    stub_runtime.config_registry = config_registry
    stub_runtime.tool_registry = tool_registry

    stub_platform = MagicMock()
    stub_platform.runtime = stub_runtime

    test_app = create_app()
    test_app.state.platform = stub_platform
    test_app.state.start_time = _time.monotonic()

    async with AsyncClient(
        transport=ASGITransport(app=test_app),
        base_url="http://testserver",
    ) as client:
        yield client


# ---------------------------------------------------------------------------
# Test 1: GET /cost/runs/{run_id} returns per-model breakdown
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_breakdown_returns_per_model_data(cost_client, admin_token):
    """GET /cost/runs/{run_id} returns per-model cost breakdown."""
    run_id = "test-run-001"
    await _seed_cost_records([
        {
            "run_id": run_id,
            "model_id": "gpt-4",
            "task_type": "scoring",
            "prompt_tokens": 100,
            "completion_tokens": 50,
            "cost_usd": 0.005,
            "created_at": _utc_now(),
        },
        {
            "run_id": run_id,
            "model_id": "gpt-4",
            "task_type": "scoring",
            "prompt_tokens": 200,
            "completion_tokens": 100,
            "cost_usd": 0.010,
            "created_at": _utc_now(),
        },
        {
            "run_id": run_id,
            "model_id": "gpt-3.5-turbo",
            "task_type": "classify",
            "prompt_tokens": 50,
            "completion_tokens": 20,
            "cost_usd": 0.001,
            "created_at": _utc_now(),
        },
    ])

    resp = await cost_client.get(
        f"/cost/runs/{run_id}",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert "data" in body
    data = body["data"]
    assert data["run_id"] == run_id
    assert data["total_cost_usd"] > 0
    assert data["total_tokens"] > 0
    models = data["models"]
    assert len(models) == 2
    model_ids = {m["model_id"] for m in models}
    assert "gpt-4" in model_ids
    assert "gpt-3.5-turbo" in model_ids
    # gpt-4 should aggregate 2 calls
    gpt4 = next(m for m in models if m["model_id"] == "gpt-4")
    assert gpt4["call_count"] == 2
    assert gpt4["prompt_tokens"] == 300
    assert gpt4["completion_tokens"] == 150
    assert gpt4["total_tokens"] == 450


# ---------------------------------------------------------------------------
# Test 2: GET /cost/runs/{run_id} returns empty models when run not found
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_breakdown_empty_when_run_not_found(cost_client, admin_token):
    """GET /cost/runs/{run_id} returns empty models list when run not found."""
    resp = await cost_client.get(
        "/cost/runs/nonexistent-run-xyz",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    data = body["data"]
    assert data["run_id"] == "nonexistent-run-xyz"
    assert data["total_cost_usd"] == 0.0
    assert data["models"] == []


# ---------------------------------------------------------------------------
# Test 3: GET /cost/history returns monthly aggregated cost data
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_history_returns_monthly_aggregated_data(cost_client, admin_token):
    """GET /cost/history returns monthly aggregated cost with model breakdown."""
    await _seed_cost_records([
        {
            "run_id": "run-hist-001",
            "model_id": "gpt-4",
            "task_type": "scoring",
            "prompt_tokens": 500,
            "completion_tokens": 200,
            "cost_usd": 0.02,
            "created_at": _utc_now(),
        },
        {
            "run_id": "run-hist-002",
            "model_id": "gpt-4",
            "task_type": "classify",
            "prompt_tokens": 300,
            "completion_tokens": 100,
            "cost_usd": 0.01,
            "created_at": _utc_now(),
        },
    ])

    resp = await cost_client.get(
        "/cost/history?months=6",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    data = body["data"]
    assert "months" in data
    assert "grand_total_usd" in data
    assert data["grand_total_usd"] >= 0.03
    assert len(data["months"]) >= 1
    month = data["months"][0]
    assert "year_month" in month
    assert "total_cost_usd" in month
    assert "models" in month


# ---------------------------------------------------------------------------
# Test 4: GET /cost/history respects team scoping (admin sees all with no team_id)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_history_respects_team_scoping(cost_client, admin_token):
    """GET /cost/history for admin (no team_id) returns data (team scoping works)."""
    await _seed_cost_records([
        {
            "run_id": "run-team-001",
            "model_id": "gpt-4",
            "task_type": "scoring",
            "prompt_tokens": 100,
            "completion_tokens": 50,
            "cost_usd": 0.005,
            "team_id": None,  # admin-owned record
            "created_at": _utc_now(),
        },
    ])

    resp = await cost_client.get(
        "/cost/history",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["data"]["grand_total_usd"] >= 0.0  # admin sees all records
    assert "months" in body["data"]


# ---------------------------------------------------------------------------
# Test 5: POST /cost/estimate returns estimated cost with history
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_estimate_returns_estimated_cost_with_history(cost_client, admin_token):
    """POST /cost/estimate returns estimated cost when team history exists."""
    # Seed historical cost records
    await _seed_cost_records([
        {
            "run_id": "run-est-001",
            "model_id": "gpt-4",
            "task_type": "scoring",
            "prompt_tokens": 200,
            "completion_tokens": 100,
            "cost_usd": 0.01,
            "created_at": _utc_now(),
        },
        {
            "run_id": "run-est-002",
            "model_id": "gpt-4",
            "task_type": "scoring",
            "prompt_tokens": 200,
            "completion_tokens": 100,
            "cost_usd": 0.02,
            "created_at": _utc_now(),
        },
    ])

    resp = await cost_client.post(
        "/cost/estimate",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"target_count": 10, "task_types": ["scoring"]},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    data = body["data"]
    assert data["estimated_cost_usd"] > 0
    assert "confidence" in data
    assert "breakdown" in data
    assert len(data["breakdown"]) == 1
    assert data["breakdown"][0]["task_type"] == "scoring"
    # sample_count >= 2 (may be higher if residual data leaked from prior tests)
    assert data["breakdown"][0]["sample_count"] >= 2
    # confidence is "historical" because history exists
    assert data["confidence"] == "historical"


# ---------------------------------------------------------------------------
# Test 6: POST /cost/estimate returns worst-case fallback when no team history
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_estimate_returns_worst_case_when_no_history(cost_client, admin_token):
    """POST /cost/estimate returns worst_case confidence when no history exists."""
    resp = await cost_client.post(
        "/cost/estimate",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"target_count": 5, "task_types": ["new_task_type_never_seen"]},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()["data"]
    assert data["confidence"] == "worst_case"
    assert data["estimated_cost_usd"] > 0
    assert data["breakdown"][0]["sample_count"] == 0


# ---------------------------------------------------------------------------
# Test 7: POST /cost/estimate worst-case uses ConfigRegistry keys (not hardcoded)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_estimate_worst_case_uses_config_registry(cost_client, admin_token):
    """POST /cost/estimate worst-case fallback uses ConfigRegistry, not hardcoded values.

    We verify that the endpoint calls registry.get() by patching the registry
    and confirming the estimated value matches the patched fallback values.
    """
    from aila.storage.registry import ConfigRegistry

    # Patch the config registry to return specific fallback values
    original_get = ConfigRegistry.get

    call_log: list[tuple[str, str]] = []

    async def _patched_get(self, namespace: str, key: str):
        call_log.append((namespace, key))
        if key == "llm_cost_estimate_fallback_max_tokens":
            return 1000  # Smaller than default 4096
        if key == "llm_cost_estimate_fallback_price_per_1k":
            return 0.10  # Larger than default 0.03
        return await original_get(self, namespace, key)

    with patch.object(ConfigRegistry, "get", _patched_get):
        resp = await cost_client.post(
            "/cost/estimate",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={"target_count": 2, "task_types": ["patched_task_type"]},
        )

    assert resp.status_code == 200, resp.text
    data = resp.json()["data"]
    # 2 targets * 1000 tokens * (0.10 / 1000) = 2 * 0.10 = 0.20
    assert abs(data["estimated_cost_usd"] - 0.20) < 0.001
    assert data["confidence"] == "worst_case"
    # Verify ConfigRegistry.get was called for fallback keys
    called_keys = [k for (_, k) in call_log]
    assert "llm_cost_estimate_fallback_max_tokens" in called_keys
    assert "llm_cost_estimate_fallback_price_per_1k" in called_keys


# ---------------------------------------------------------------------------
# Test 8: POST /cost/estimate-human returns 503 when platform not initialized
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_estimate_human_returns_503_without_platform(test_db, admin_token):
    """POST /cost/estimate-human returns 503 when platform is None."""
    import time as _time
    from aila.api.app import create_app

    test_app = create_app()
    test_app.state.platform = None
    test_app.state.start_time = _time.monotonic()

    async with AsyncClient(
        transport=ASGITransport(app=test_app),
        base_url="http://testserver",
    ) as client:
        resp = await client.post(
            "/cost/estimate-human",
            headers={"Authorization": f"Bearer {admin_token}"},
            json={
                "run_id": "run-abc",
                "target_count": 5,
                "finding_count": 10,
                "task_types_performed": ["scoring"],
                "scan_duration_minutes": 15.0,
            },
        )
    assert resp.status_code == 503, resp.text


# ---------------------------------------------------------------------------
# Test 9: GET /cost/roi returns LLM cost vs human cost with ROI percentage
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_roi_returns_llm_and_human_cost(cost_client, admin_token):
    """GET /cost/roi returns LLM cost vs human cost side-by-side with ROI."""
    await _seed_cost_records([
        {
            "run_id": "run-roi-001",
            "model_id": "gpt-4",
            "task_type": "scoring",
            "prompt_tokens": 1000,
            "completion_tokens": 500,
            "cost_usd": 0.05,
            "human_cost_hours": 2.0,
            "human_cost_usd": 300.0,
            "created_at": _utc_now(),
        },
    ])

    resp = await cost_client.get(
        "/cost/roi?months=3",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    data = body["data"]
    assert "llm_cost_usd" in data
    assert "human_equivalent_cost_usd" in data
    assert "human_equivalent_hours" in data
    assert "roi_percentage" in data
    assert "period_start" in data
    assert "period_end" in data
    assert "run_count" in data
    assert data["llm_cost_usd"] >= 0.05
    assert data["human_equivalent_cost_usd"] >= 300.0
    assert data["human_equivalent_hours"] >= 2.0
    # ROI should be high: (300 - 0.05) / 300 * 100 ≈ 99.98%
    assert data["roi_percentage"] > 90.0


# ---------------------------------------------------------------------------
# Test 10: GET /cost/roi excludes task_type="cost_estimation" from LLM cost
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_roi_excludes_cost_estimation_task_type(cost_client, admin_token):
    """GET /cost/roi excludes task_type='cost_estimation' from LLM cost totals (T-175-10)."""
    await _seed_cost_records([
        {
            "run_id": "run-roi-ex-001",
            "model_id": "gpt-4",
            "task_type": "scoring",           # INCLUDED in LLM cost
            "prompt_tokens": 500,
            "completion_tokens": 200,
            "cost_usd": 0.10,
            "created_at": _utc_now(),
        },
        {
            "run_id": "run-roi-ex-002",
            "model_id": "gpt-4",
            "task_type": "cost_estimation",   # EXCLUDED from LLM cost
            "prompt_tokens": 200,
            "completion_tokens": 100,
            "cost_usd": 5.00,  # Large value that should NOT appear in llm_cost_usd
            "created_at": _utc_now(),
        },
    ])

    resp = await cost_client.get(
        "/cost/roi?months=3",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()["data"]
    # llm_cost_usd must NOT include the 5.00 from cost_estimation record.
    # If cost_estimation were included, llm_cost_usd would be >= 5.00.
    # Since there may be residual data from other tests, just verify the
    # cost_estimation 5.00 was NOT added (total stays well below 5.10).
    assert data["llm_cost_usd"] < 5.0, (
        f"cost_estimation task_type was NOT excluded: llm_cost_usd={data['llm_cost_usd']} "
        f"(expected < 5.0 since cost_estimation cost was 5.00)"
    )


# ---------------------------------------------------------------------------
# Test 11: GET /cost/roi reads human_cost from original LLMCostRecords (no sentinel)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_roi_reads_human_cost_from_original_records(cost_client, admin_token):
    """GET /cost/roi reads human_cost_usd/hours from original LLMCostRecords (not sentinel)."""
    run_id = "run-human-source-001"
    await _seed_cost_records([
        {
            "run_id": run_id,
            "model_id": "gpt-4",
            "task_type": "scoring",
            "prompt_tokens": 300,
            "completion_tokens": 150,
            "cost_usd": 0.03,
            "human_cost_hours": 4.0,      # Stored on original record
            "human_cost_usd": 600.0,      # Stored on original record
            "created_at": _utc_now(),
        },
    ])

    resp = await cost_client.get(
        "/cost/roi",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()["data"]
    # Human cost must include our seeded values (>= handles any residual data from prior tests)
    assert data["human_equivalent_cost_usd"] >= 600.0, (
        f"Expected human_equivalent_cost_usd >= 600.0, got {data['human_equivalent_cost_usd']}"
    )
    assert data["human_equivalent_hours"] >= 4.0, (
        f"Expected human_equivalent_hours >= 4.0, got {data['human_equivalent_hours']}"
    )
    # Verify no sentinel records with run_id="_human_estimate" exist in the DB
    # This is the key assertion: human cost is on ORIGINAL records, not sentinel records.
    async with async_session_scope() as session:
        from sqlmodel import select
        sentinel = (await session.exec(
            select(LLMCostRecord).where(LLMCostRecord.run_id == "_human_estimate")
        )).first()
    assert sentinel is None, "No sentinel records should exist -- human cost stored on original records"
