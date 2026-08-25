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

from aila.platform.llm.cost_record import LLMCostRecord
from aila.storage.database import async_session_scope


def _utc_now() -> datetime:
    return datetime.now(UTC)


@pytest_asyncio.fixture(scope="function")
async def seeded_llm_log(test_db):
    """Seed 5 LLMCostRecord rows spanning different models, tasks, and costs."""
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
    """cost_usd_min=0.05 returns only rows with cost >= 0.05."""
    resp = await async_client.get(
        "/admin/llm-log",
        params={"cost_usd_min": 0.05},
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
        params={"cost_usd_max": 0.005},
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
    """timestamp_since cuts older records."""
    cutoff = (_utc_now() - timedelta(minutes=2, seconds=30)).isoformat()
    resp = await async_client.get(
        "/admin/llm-log",
        params={"timestamp_since": cutoff},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200
    body = resp.json()
    # rec-4 (-2m) and rec-5 (-1m) are newer than cutoff
    assert body["data"]["total"] == 2


@pytest_asyncio.fixture(scope="function")
async def seeded_llm_log_two_users(test_db):
    """Seed cost rows attributed to two distinct users for the #124 filter.

    Written after #124 flipped ``LLMCostRecord.user_id`` from unset to a
    real, indexed attribution column populated at write time. Prior code
    filtered the ``user=`` query param against ``WorkflowRunRecord.team_id``
    -- always wrong or empty. This fixture proves the new filter returns
    exactly one user's rows and never leaks another's.
    """
    now = _utc_now()
    records = [
        LLMCostRecord(
            id="user-a-1",
            run_id="run-A",
            user_id="user-alice",
            model_id="gpt-4o",
            task_type="scoring",
            team_id=None,
            prompt_tokens=10,
            completion_tokens=5,
            cost_usd=0.01,
            status="ok",
            created_at=now - timedelta(minutes=3),
        ),
        LLMCostRecord(
            id="user-a-2",
            run_id="run-A",
            user_id="user-alice",
            model_id="gpt-4o",
            task_type="summary",
            team_id=None,
            prompt_tokens=20,
            completion_tokens=10,
            cost_usd=0.02,
            status="ok",
            created_at=now - timedelta(minutes=2),
        ),
        LLMCostRecord(
            id="user-b-1",
            run_id="run-B",
            user_id="user-bob",
            model_id="gpt-4o",
            task_type="scoring",
            team_id=None,
            prompt_tokens=30,
            completion_tokens=15,
            cost_usd=0.03,
            status="ok",
            created_at=now - timedelta(minutes=1),
        ),
        # No-attribution row (worker path). Must not match either user filter.
        LLMCostRecord(
            id="worker-1",
            run_id="_no_run",
            user_id=None,
            model_id="gpt-4o",
            task_type="cost_estimation",
            team_id=None,
            prompt_tokens=5,
            completion_tokens=1,
            cost_usd=0.001,
            status="ok",
            created_at=now,
        ),
    ]

    async with async_session_scope() as session:
        for r in records:
            session.add(r)
        await session.commit()

    return records


@pytest.mark.asyncio
async def test_user_filter_isolates_caller_rows(
    async_client: AsyncClient, admin_token: str, seeded_llm_log_two_users,
) -> None:
    """#124: ``user_id=`` must filter on LLMCostRecord.user_id, not team_id.

    Before the fix, ``user_id=user-alice`` was compared against
    ``WorkflowRunRecord.team_id`` and always returned zero rows (or
    wrong rows when a team_id coincidentally matched). After the fix,
    it must return exactly alice's two rows and never bob's row or the
    worker-emitted no-attribution row.
    """
    resp = await async_client.get(
        "/admin/llm-log",
        params={"user_id": "user-alice"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    ids = {row["id"] for row in body["data"]["items"]}
    assert ids == {"user-a-1", "user-a-2"}
    assert body["data"]["total"] == 2
    # Every returned row's user_id must equal the requested filter.
    assert all(row["user_id"] == "user-alice" for row in body["data"]["items"])
    # A non-existent user id must produce zero rows, not fall back to team_id.
    zero = await async_client.get(
        "/admin/llm-log",
        params={"user_id": "no-such-user"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert zero.status_code == 200
    assert zero.json()["data"]["total"] == 0


@pytest.mark.asyncio
async def test_model_repeated_param_or_matches_both(
    async_client: AsyncClient, admin_token: str, seeded_llm_log
) -> None:
    """Repeated ``?model=X&model=Y`` OR-matches both models (req 28 wire)."""
    resp = await async_client.get(
        "/admin/llm-log",
        params=[("model", "gpt-4o"), ("model", "gpt-4o-mini")],
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    # rec-1, rec-3, rec-4, rec-5 are gpt-4o; rec-2 is gpt-4o-mini -> all 5
    assert body["data"]["total"] == 5
    models = {row["model"] for row in body["data"]["items"]}
    assert models == {"gpt-4o", "gpt-4o-mini"}


# ---------------------------------------------------------------------------
# GET /admin/llm-log/{id}/content -- req 52 rich viewer endpoint
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="function")
async def seeded_llm_log_content(test_db):
    """Seed three cost rows + one AuditSealRecord for the content endpoint.

    * ``content-seal``  -- paired seal captures both bodies -> source=audit_seal
    * ``content-prev``  -- previews only, no seal            -> source=preview
    * ``content-none``  -- previews null, no seal            -> source=missing
    """
    from aila.storage.db_models import AuditSealRecord

    now = _utc_now()
    cost_rows = [
        LLMCostRecord(
            id="content-seal",
            run_id="run-seal",
            model_id="gpt-4o",
            task_type="scoring",
            team_id=None,
            prompt_tokens=100,
            completion_tokens=50,
            cost_usd=0.10,
            prompt_preview="preview should be ignored when seal has content",
            response_preview="preview response",
            duration_ms=200,
            status="ok",
            created_at=now,
        ),
        LLMCostRecord(
            id="content-prev",
            run_id="run-prev",
            model_id="gpt-4o",
            task_type="summary",
            team_id=None,
            prompt_tokens=10,
            completion_tokens=5,
            cost_usd=0.01,
            prompt_preview="preview prompt body",
            response_preview="preview response body",
            duration_ms=90,
            status="ok",
            created_at=now,
        ),
        LLMCostRecord(
            id="content-none",
            run_id="run-none",
            model_id="gpt-4o",
            task_type="routing",
            team_id=None,
            prompt_tokens=5,
            completion_tokens=1,
            cost_usd=0.001,
            prompt_preview=None,
            response_preview=None,
            duration_ms=40,
            status="ok",
            created_at=now,
        ),
    ]
    seal = AuditSealRecord(
        run_id="run-seal",
        seal_hash="hash-seal",
        input_hash="hash-in",
        output_hash="hash-out",
        model_id="gpt-4o",
        task_type="scoring",
        timestamp=now,
        content_stored=True,
        prompt_content="FULL PROMPT BODY captured by the seal",
        response_content="FULL RESPONSE BODY captured by the seal",
    )

    async with async_session_scope() as session:
        for r in cost_rows:
            session.add(r)
        session.add(seal)
        await session.commit()

    return cost_rows


@pytest.mark.asyncio
async def test_content_returns_audit_seal_bodies_when_available(
    async_client: AsyncClient, admin_token: str, seeded_llm_log_content
) -> None:
    resp = await async_client.get(
        "/admin/llm-log/content-seal/content",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()["data"]
    assert data["source"] == "audit_seal"
    assert data["prompt_content"] == "FULL PROMPT BODY captured by the seal"
    assert data["response_content"] == "FULL RESPONSE BODY captured by the seal"
    assert data["task_type"] == "scoring"
    assert data["config_flag"] is None


@pytest.mark.asyncio
async def test_content_falls_back_to_preview_when_no_seal(
    async_client: AsyncClient, admin_token: str, seeded_llm_log_content
) -> None:
    resp = await async_client.get(
        "/admin/llm-log/content-prev/content",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()["data"]
    assert data["source"] == "preview"
    assert data["prompt_content"] == "preview prompt body"
    assert data["response_content"] == "preview response body"
    assert data["task_type"] == "summary"
    assert data["config_flag"] == "llm_seal_store_content_summary"


@pytest.mark.asyncio
async def test_content_reports_missing_when_no_seal_and_no_preview(
    async_client: AsyncClient, admin_token: str, seeded_llm_log_content
) -> None:
    resp = await async_client.get(
        "/admin/llm-log/content-none/content",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()["data"]
    assert data["source"] == "missing"
    assert data["prompt_content"] is None
    assert data["response_content"] is None
    assert data["task_type"] == "routing"
    assert data["config_flag"] == "llm_seal_store_content_routing"


@pytest.mark.asyncio
async def test_content_unknown_id_returns_404(
    async_client: AsyncClient, admin_token: str, seeded_llm_log_content
) -> None:
    resp = await async_client.get(
        "/admin/llm-log/no-such-id/content",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 404


@pytest_asyncio.fixture(scope="function")
async def team_scoped_admin_token(test_db):
    """Admin ApiKeyRecord scoped to a specific team_id -> its JWT."""
    from aila.api.auth import generate_api_key, hash_api_key, issue_jwt_token
    from aila.storage.db_models import ApiKeyRecord

    raw_key = generate_api_key()
    record = ApiKeyRecord(
        hashed_key=hash_api_key(raw_key),
        key_prefix=raw_key[:12],
        role="admin",
        label="test-admin-team-alpha",
        created_by="test-fixture",
        team_id="team-alpha",
        created_at=_utc_now(),
    )
    async with async_session_scope() as session:
        session.add(record)
        await session.commit()
        await session.refresh(record)
    token, _ = issue_jwt_token(record)
    return token


@pytest_asyncio.fixture(scope="function")
async def seeded_foreign_team_llm_row(test_db):
    now = _utc_now()
    row = LLMCostRecord(
        id="foreign-team-row",
        run_id="run-foreign",
        model_id="gpt-4o",
        task_type="scoring",
        team_id="team-beta",
        prompt_tokens=10,
        completion_tokens=5,
        cost_usd=0.01,
        prompt_preview="foreign team prompt",
        response_preview="foreign team response",
        duration_ms=100,
        status="ok",
        created_at=now,
    )
    async with async_session_scope() as session:
        session.add(row)
        await session.commit()
    return row


@pytest.mark.asyncio
async def test_content_team_scoped_admin_gets_404_on_foreign_row(
    async_client: AsyncClient,
    team_scoped_admin_token: str,
    seeded_foreign_team_llm_row,
) -> None:
    """A team-scoped admin cannot read another team's llm-log content."""
    resp = await async_client.get(
        "/admin/llm-log/foreign-team-row/content",
        headers={"Authorization": f"Bearer {team_scoped_admin_token}"},
    )
    assert resp.status_code == 404
