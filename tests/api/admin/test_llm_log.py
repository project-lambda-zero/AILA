"""Tests for the admin LLM interaction log router (Plan 176e).

Covers:
    - happy-path pagination and total_cost aggregate
    - filter params (model, task_type, status, cost, search, date range)
    - admin-only auth enforcement -- non-admin tokens hit 403
    - cost aggregation matches sum of all matching rows, not just the page

Data fixture creates five LLMCostRecord rows with varied model_id, task_type,
status, cost, and prompt_preview so each filter can assert a distinct row set.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
import pytest_asyncio
from httpx import AsyncClient


def _utc_now() -> datetime:
    return datetime.now(UTC)


@pytest_asyncio.fixture(scope="function")
async def seeded_llm_log(test_db):
    """Seed 5 LLMCostRecord rows spanning different models, tasks, and costs."""
    from aila.platform.llm.cost_record import LLMCostRecord
    from aila.storage.database import async_session_scope

    now = _utc_now()
    records = [
        LLMCostRecord(
            id="rec-1",
            run_id="run-A",
            model_id="gpt-4o",
            task_type="scoring",
            team_id=None,
            prompt_tokens=100,
            completion_tokens=50,
            cost_usd=0.05,
            prompt_preview="scan web01 for vulnerabilities",
            response_preview="found 3 CVEs",
            duration_ms=420,
            status="ok",
            created_at=now - timedelta(minutes=5),
        ),
        LLMCostRecord(
            id="rec-2",
            run_id="run-A",
            model_id="gpt-4o-mini",
            task_type="scoring",
            team_id=None,
            prompt_tokens=200,
            completion_tokens=30,
            cost_usd=0.01,
            prompt_preview="rescore top findings",
            response_preview="re-ranked",
            duration_ms=180,
            status="ok",
            created_at=now - timedelta(minutes=4),
        ),
        LLMCostRecord(
            id="rec-3",
            run_id="run-B",
            model_id="gpt-4o",
            task_type="summary",
            team_id=None,
            prompt_tokens=800,
            completion_tokens=400,
            cost_usd=0.75,
            prompt_preview="write exec summary for fleet",
            response_preview="summary: …",
            duration_ms=2100,
            status="ok",
            created_at=now - timedelta(minutes=3),
        ),
        LLMCostRecord(
            id="rec-4",
            run_id="run-B",
            model_id="gpt-4o",
            task_type="routing",
            team_id=None,
            prompt_tokens=40,
            completion_tokens=5,
            cost_usd=0.002,
            prompt_preview="classify intent: list machines",
            response_preview="inventory",
            duration_ms=90,
            status="error",
            created_at=now - timedelta(minutes=2),
        ),
        LLMCostRecord(
            id="rec-5",
            run_id="_no_run",
            model_id="gpt-4o",
            task_type="cost_estimation",
            team_id=None,
            prompt_tokens=50,
            completion_tokens=10,
            cost_usd=0.003,
            prompt_preview="estimate human-hours for run",
            response_preview="4 hours",
            duration_ms=260,
            status="ok",
            created_at=now - timedelta(minutes=1),
        ),
    ]

    async with async_session_scope() as session:
        for r in records:
            session.add(r)
        await session.commit()

    return records


@pytest.mark.asyncio
async def test_requires_admin(
    async_client: AsyncClient, reader_token: str, seeded_llm_log
) -> None:
    """Reader tokens cannot access /admin/llm-log."""
    resp = await async_client.get(
        "/admin/llm-log",
        headers={"Authorization": f"Bearer {reader_token}"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_requires_auth(async_client: AsyncClient, seeded_llm_log) -> None:
    """No token -> 401."""
    resp = await async_client.get("/admin/llm-log")
    assert resp.status_code == 401


@pytest.mark.asyncio
async def test_happy_path_returns_all_with_total_cost(
    async_client: AsyncClient, admin_token: str, seeded_llm_log
) -> None:
    """Admin pull with no filters returns all 5 rows and the cost sum."""
    resp = await async_client.get(
        "/admin/llm-log",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["data"]["total"] == 5
    # Pagination defaults: limit=50, offset=0 -> all rows in one page
    assert len(body["data"]["items"]) == 5
    expected_total = round(0.05 + 0.01 + 0.75 + 0.002 + 0.003, 6)
    assert body["data"]["total_cost_usd"] == expected_total


@pytest.mark.asyncio
async def test_filter_by_model(
    async_client: AsyncClient, admin_token: str, seeded_llm_log
) -> None:
    resp = await async_client.get(
        "/admin/llm-log",
        params={"model": "gpt-4o-mini"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["data"]["total"] == 1
    assert body["data"]["items"][0]["model"] == "gpt-4o-mini"


@pytest.mark.asyncio
async def test_filter_by_task_type_comma_or(
    async_client: AsyncClient, admin_token: str, seeded_llm_log
) -> None:
    """Comma-separated task_type should OR-match all listed task types."""
    resp = await async_client.get(
        "/admin/llm-log",
        params={"task_type": "summary,routing"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["data"]["total"] == 2
    task_types = {item["task_type"] for item in body["data"]["items"]}
    assert task_types == {"summary", "routing"}


@pytest.mark.asyncio
async def test_filter_by_status(
    async_client: AsyncClient, admin_token: str, seeded_llm_log
) -> None:
    resp = await async_client.get(
        "/admin/llm-log",
        params={"status": "error"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["data"]["total"] == 1
    assert body["data"]["items"][0]["status"] == "error"


@pytest.mark.asyncio
async def test_filter_by_min_cost(
    async_client: AsyncClient, admin_token: str, seeded_llm_log
) -> None:
    """min_cost=0.05 returns only rows with cost >= 0.05."""
    resp = await async_client.get(
        "/admin/llm-log",
        params={"min_cost": 0.05},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    # rec-1 (0.05) and rec-3 (0.75) match
    assert body["data"]["total"] == 2


@pytest.mark.asyncio
async def test_filter_by_max_cost(
    async_client: AsyncClient, admin_token: str, seeded_llm_log
) -> None:
    resp = await async_client.get(
        "/admin/llm-log",
        params={"max_cost": 0.005},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    # rec-4 (0.002) and rec-5 (0.003) match
    assert body["data"]["total"] == 2


@pytest.mark.asyncio
async def test_search_hits_prompt_preview(
    async_client: AsyncClient, admin_token: str, seeded_llm_log
) -> None:
    """Search is a case-insensitive substring match on prompt_preview."""
    resp = await async_client.get(
        "/admin/llm-log",
        params={"search": "rescore"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["data"]["total"] == 1
    assert body["data"]["items"][0]["id"] == "rec-2"


@pytest.mark.asyncio
async def test_pagination_respects_limit_and_offset(
    async_client: AsyncClient, admin_token: str, seeded_llm_log
) -> None:
    """limit=2 + offset=2 should produce the third/fourth newest rows."""
    resp = await async_client.get(
        "/admin/llm-log",
        params={"limit": 2, "offset": 2},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    # total reflects all matching rows, not just page
    assert body["data"]["total"] == 5
    assert len(body["data"]["items"]) == 2


@pytest.mark.asyncio
async def test_total_cost_matches_all_rows_not_page(
    async_client: AsyncClient, admin_token: str, seeded_llm_log
) -> None:
    """total_cost_usd must reflect all matching rows even with a small limit."""
    resp = await async_client.get(
        "/admin/llm-log",
        params={"limit": 1, "offset": 0},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert len(body["data"]["items"]) == 1
    expected_total = round(0.05 + 0.01 + 0.75 + 0.002 + 0.003, 6)
    assert body["data"]["total_cost_usd"] == expected_total


@pytest.mark.asyncio
async def test_date_range_filter(
    async_client: AsyncClient, admin_token: str, seeded_llm_log
) -> None:
    """from_date cuts older records."""
    cutoff = (_utc_now() - timedelta(minutes=2, seconds=30)).isoformat()
    resp = await async_client.get(
        "/admin/llm-log",
        params={"from_date": cutoff},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    # rec-4 (-2m) and rec-5 (-1m) are newer than cutoff
    assert body["data"]["total"] == 2
