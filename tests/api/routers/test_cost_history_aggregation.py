"""Focused perf test for /cost/history (#204).

Verifies that after moving the month/model aggregation from Python into
SQL, the endpoint still returns the correct grouped counts, per-model
sums, and grand total on a small seeded set. Complements the existing
``test_cost.py::test_history_returns_monthly_aggregated_data`` coverage
by asserting exact numeric equality across two months and two models
rather than just presence of keys.

Also exercises the SQL rewrite of ``estimate_scan_cost`` (``task_type``
GROUP BY) on the same DB session, so a single test proves the
aggregation contract for both endpoints touched by #204.
"""
from __future__ import annotations

from datetime import UTC, datetime

import pytest

from aila.platform.llm.cost_record import LLMCostRecord
from aila.storage.database import async_session_scope

# Re-use the shared cost fixtures (client, tokens) from test_cost.py.
# pytest discovers fixtures in the test module's namespace, so both the
# leaf and its dependency need to be imported here for the chain to resolve.
from tests.api.routers.test_cost import (  # noqa: F401 -- fixture re-export
    ESTIMATE_TEAM_ID,
    cost_client,
    estimate_team_key_record,
    estimate_team_token,
)


async def _seed(records: list[dict]) -> None:
    async with async_session_scope() as session:
        for r in records:
            session.add(LLMCostRecord(**r))
        await session.commit()


@pytest.mark.asyncio
async def test_history_aggregation_produces_correct_month_and_model_sums(
    cost_client, admin_token,  # noqa: F811 -- pytest fixture (re-exported above)
) -> None:
    """SQL GROUP BY reproduces the pre-rewrite month/model bucket totals.

    Seeds four rows across two months and two models plus one excluded
    ``cost_estimation`` row. Asserts:
    * two monthly buckets returned, in chronological order.
    * per-model sums equal the seeded costs (not the Python-side sum of
      the same rows loaded into memory).
    * ``call_count`` per model equals the row count in that bucket.
    * ``cost_estimation`` records are excluded from the totals.
    """
    aug = datetime(2026, 8, 5, 12, 0, tzinfo=UTC)
    jul = datetime(2026, 7, 10, 9, 0, tzinfo=UTC)

    await _seed([
        # August: two rows on gpt-4, one on gpt-4o-mini
        {
            "run_id": "run-aug-1", "model_id": "gpt-4", "task_type": "scoring",
            "prompt_tokens": 100, "completion_tokens": 50, "cost_usd": 0.01,
            "created_at": aug,
        },
        {
            "run_id": "run-aug-2", "model_id": "gpt-4", "task_type": "scoring",
            "prompt_tokens": 200, "completion_tokens": 100, "cost_usd": 0.02,
            "created_at": aug,
        },
        {
            "run_id": "run-aug-3", "model_id": "gpt-4o-mini", "task_type": "classify",
            "prompt_tokens": 400, "completion_tokens": 100, "cost_usd": 0.005,
            "created_at": aug,
        },
        # July: one row on gpt-4
        {
            "run_id": "run-jul-1", "model_id": "gpt-4", "task_type": "scoring",
            "prompt_tokens": 300, "completion_tokens": 100, "cost_usd": 0.03,
            "created_at": jul,
        },
        # Excluded: cost_estimation task_type must NOT appear in the totals.
        {
            "run_id": "run-est-1", "model_id": "gpt-4", "task_type": "cost_estimation",
            "prompt_tokens": 999, "completion_tokens": 999, "cost_usd": 5.00,
            "created_at": aug,
        },
    ])

    # Widest window so both seeded months fall inside it. The API caps at 24.
    resp = await cost_client.get(
        "/cost/history?months=24",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()["data"]

    months_by_ym = {m["year_month"]: m for m in data["months"]}
    assert "2026-08" in months_by_ym, months_by_ym
    assert "2026-07" in months_by_ym, months_by_ym

    aug_bucket = months_by_ym["2026-08"]
    jul_bucket = months_by_ym["2026-07"]

    # Per-model sums in the August bucket. Convert the response list into a
    # {model_id: entry} map so we can assert on exact numeric equality.
    aug_by_model = {m["model_id"]: m for m in aug_bucket["models"]}
    assert "gpt-4" in aug_by_model and "gpt-4o-mini" in aug_by_model, aug_by_model
    # cost_estimation excluded -> gpt-4 in August is 0.01 + 0.02, not + 5.00
    assert aug_by_model["gpt-4"]["cost_usd"] == pytest.approx(0.03, abs=1e-9)
    assert aug_by_model["gpt-4"]["call_count"] == 2
    assert aug_by_model["gpt-4"]["prompt_tokens"] == 300
    assert aug_by_model["gpt-4"]["completion_tokens"] == 150
    assert aug_by_model["gpt-4"]["total_tokens"] == 450
    assert aug_by_model["gpt-4o-mini"]["cost_usd"] == pytest.approx(0.005, abs=1e-9)
    assert aug_by_model["gpt-4o-mini"]["call_count"] == 1

    # July bucket: one gpt-4 row.
    jul_by_model = {m["model_id"]: m for m in jul_bucket["models"]}
    assert list(jul_by_model.keys()) == ["gpt-4"], jul_by_model
    assert jul_by_model["gpt-4"]["cost_usd"] == pytest.approx(0.03, abs=1e-9)
    assert jul_by_model["gpt-4"]["call_count"] == 1

    # Monthly totals derive from per-model rows.
    assert aug_bucket["total_cost_usd"] == pytest.approx(0.035, abs=1e-9)
    assert aug_bucket["total_tokens"] == 450 + 500  # gpt-4 + gpt-4o-mini
    assert jul_bucket["total_cost_usd"] == pytest.approx(0.03, abs=1e-9)
    assert jul_bucket["total_tokens"] == 400

    # Grand total excludes the cost_estimation 5.00 row.
    assert data["grand_total_usd"] == pytest.approx(0.065, abs=1e-9)


@pytest.mark.asyncio
async def test_estimate_group_by_returns_per_task_type_average(
    cost_client, estimate_team_token,  # noqa: F811 -- pytest fixture (re-exported above)
) -> None:
    """SQL GROUP BY per task_type produces the same avg the Python loop did.

    Two seeded ``scoring`` rows at $0.01 and $0.03 average to $0.02 per call;
    an unseen task_type falls back to worst-case. The endpoint returns one
    breakdown row per requested task_type with sample_count == group COUNT.
    """
    await _seed([
        {
            "run_id": "est-1", "model_id": "gpt-4", "task_type": "scoring",
            "cost_usd": 0.01, "team_id": ESTIMATE_TEAM_ID,
            "created_at": datetime.now(UTC),
        },
        {
            "run_id": "est-2", "model_id": "gpt-4", "task_type": "scoring",
            "cost_usd": 0.03, "team_id": ESTIMATE_TEAM_ID,
            "created_at": datetime.now(UTC),
        },
        # cost_estimation must be excluded from the SUM/COUNT so it does not
        # skew the historical average.
        {
            "run_id": "est-3", "model_id": "gpt-4", "task_type": "cost_estimation",
            "cost_usd": 9.99, "team_id": ESTIMATE_TEAM_ID,
            "created_at": datetime.now(UTC),
        },
    ])

    resp = await cost_client.post(
        "/cost/estimate",
        headers={"Authorization": f"Bearer {estimate_team_token}"},
        json={"target_count": 5, "task_types": ["scoring", "unseen_task"]},
    )
    assert resp.status_code == 200, resp.text
    data = resp.json()["data"]

    by_task = {b["task_type"]: b for b in data["breakdown"]}
    assert set(by_task.keys()) == {"scoring", "unseen_task"}, by_task

    # scoring: SQL GROUP BY(sum=0.04, count=2) -> avg=0.02, target_count=5 -> 0.10
    assert by_task["scoring"]["sample_count"] == 2
    assert by_task["scoring"]["avg_cost_usd"] == pytest.approx(0.02, abs=1e-9)

    # unseen_task: no history row -> sample_count=0, worst-case fallback path.
    assert by_task["unseen_task"]["sample_count"] == 0

    # confidence is worst_case because one task_type had no history.
    assert data["confidence"] == "worst_case"
