"""Tests for human-equivalent cost estimation module (Plan 175-03 Task 2).

Tests 8 behaviors:
  1. estimate_human_cost sends structured LLM call with task_type="cost_estimation"
  2. estimate_human_cost UPDATES existing LLMCostRecords for the run_id
  3. Human cost USD = estimated_hours * configured hourly rate
  4. Default hourly rate is 150.0 when config key missing
  5. The LLM call uses run_id=None (not attributed to scan run)
  6. The estimation LLM call uses task_type="cost_estimation"
  7. LLM call failure is logged and returns None
  8. When no LLMCostRecords exist for run_id, logs warning and returns None

Uses PostgreSQL via AILA_TEST_DATABASE_URL. Mocks AilaLLMClient.chat_structured
to avoid real LLM calls. Mocks ConfigRegistry.get for hourly rate lookup.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import create_async_engine
from sqlmodel import SQLModel

from aila.platform.llm.cost_record import LLMCostRecord
from aila.platform.llm.human_cost import HumanCostEstimate, estimate_human_cost, _DEFAULT_HOURLY_RATE
from aila.storage.database import async_session_scope

_UTC = timezone.utc

TEST_DB_URL: str = os.environ.get(
    "AILA_TEST_DATABASE_URL",
    "postgresql+asyncpg://postgres:admin@localhost:5432/aila_test",
)


def _utc_now() -> datetime:
    return datetime.now(_UTC)


# ---------------------------------------------------------------------------
# Session-scoped engine setup (mirrors tests/api/conftest.py pattern)
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="session")
async def _hc_session_engine():
    """Session-scoped async engine for human_cost tests."""
    import aila.storage.db_models  # noqa: F401
    import aila.storage.database as _db_module

    engine = create_async_engine(TEST_DB_URL, echo=False, pool_pre_ping=True)
    async with engine.begin() as conn:
        await conn.run_sync(SQLModel.metadata.create_all)

    with _db_module._ENGINE_LOCK:
        _db_module._ASYNC_ENGINES[TEST_DB_URL] = engine
        _db_module._INITIALIZED_URLS.add(TEST_DB_URL)

    yield engine

    with _db_module._ENGINE_LOCK:
        _db_module._ASYNC_ENGINES.pop(TEST_DB_URL, None)
        _db_module._INITIALIZED_URLS.discard(TEST_DB_URL)
        _db_module._SESSION_FACTORIES.pop(TEST_DB_URL, None)
    await engine.dispose()


@pytest_asyncio.fixture(scope="function")
async def hc_test_db(_hc_session_engine):
    """Function-scoped test DB with table truncation on teardown."""
    import aila.storage.database as _db_module
    from aila.config import _build_settings

    old_db_url = os.environ.get("AILA_DATABASE_URL")
    os.environ["AILA_DATABASE_URL"] = TEST_DB_URL
    _build_settings.cache_clear()

    engine = _hc_session_engine
    with _db_module._ENGINE_LOCK:
        _db_module._ASYNC_ENGINES[TEST_DB_URL] = engine
        _db_module._INITIALIZED_URLS.add(TEST_DB_URL)

    yield

    async with engine.begin() as conn:
        for table in reversed(SQLModel.metadata.sorted_tables):
            try:
                await conn.execute(table.delete())
            except Exception:  # noqa: BLE001
                pass

    if old_db_url is None:
        os.environ.pop("AILA_DATABASE_URL", None)
    else:
        os.environ["AILA_DATABASE_URL"] = old_db_url
    _build_settings.cache_clear()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_stub_llm_client(
    estimated_hours: float = 3.0,
    reasoning: str = "Test reasoning",
    confidence: str = "high",
) -> MagicMock:
    """Build a stub AilaLLMClient that returns a canned HumanCostEstimate."""
    from aila.platform.llm.client import LLMResponse

    estimate = HumanCostEstimate(
        estimated_hours=estimated_hours,
        reasoning=reasoning,
        confidence=confidence,
    )
    mock_response = LLMResponse(
        content=estimate.model_dump_json(),
        model="gpt-4",
        usage={"prompt_tokens": 200, "completion_tokens": 100},
        disabled=False,
        finish_reason="stop",
    )

    client = MagicMock()
    client.chat_structured = AsyncMock(return_value=mock_response)
    return client


def _make_stub_registry(hourly_rate: float | None = 150.0) -> MagicMock:
    """Build a stub ConfigRegistry with a configurable hourly rate."""
    registry = MagicMock()

    async def _get(namespace: str, key: str):
        if key == "llm_human_consultant_hourly_rate":
            return hourly_rate
        return None

    registry.get = _get
    return registry


async def _seed_cost_records_for_run(run_id: str, count: int = 2) -> list[LLMCostRecord]:
    """Insert `count` LLMCostRecord rows for the given run_id."""
    records = []
    async with async_session_scope() as session:
        for i in range(count):
            rec = LLMCostRecord(
                run_id=run_id,
                model_id="gpt-4",
                task_type="scoring",
                prompt_tokens=100 * (i + 1),
                completion_tokens=50 * (i + 1),
                cost_usd=0.01 * (i + 1),
                created_at=_utc_now(),
            )
            session.add(rec)
            records.append(rec)
        await session.commit()
        for r in records:
            await session.refresh(r)
    return records


# ---------------------------------------------------------------------------
# Test 1: estimate_human_cost sends structured LLM call with task_type="cost_estimation"
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_sends_structured_llm_call_with_cost_estimation_task_type(hc_test_db):
    """estimate_human_cost sends chat_structured with task_type='cost_estimation'."""
    run_id = "run-hc-01"
    await _seed_cost_records_for_run(run_id, count=1)

    client = _make_stub_llm_client()
    registry = _make_stub_registry()

    result = await estimate_human_cost(
        llm_client=client,
        registry=registry,
        team_id=None,
        run_id=run_id,
        target_count=5,
        finding_count=10,
        task_types_performed=["scoring"],
        scan_duration_minutes=15.0,
    )

    assert result is not None
    # Verify chat_structured was called with task_type="cost_estimation"
    call_args = client.chat_structured.call_args
    assert call_args is not None
    positional_args = call_args[0]
    assert positional_args[0] == "cost_estimation", (
        f"Expected task_type='cost_estimation', got '{positional_args[0]}'"
    )


# ---------------------------------------------------------------------------
# Test 2: estimate_human_cost UPDATES existing LLMCostRecords (not new records)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_updates_existing_cost_records_not_new_ones(hc_test_db):
    """estimate_human_cost UPDATES human_cost_hours/usd on original run records."""
    from sqlmodel import select

    run_id = "run-hc-02"
    seeded = await _seed_cost_records_for_run(run_id, count=3)
    initial_count = len(seeded)

    client = _make_stub_llm_client(estimated_hours=6.0)
    registry = _make_stub_registry(hourly_rate=100.0)

    result = await estimate_human_cost(
        llm_client=client,
        registry=registry,
        team_id=None,
        run_id=run_id,
        target_count=10,
        finding_count=20,
        task_types_performed=["scoring", "classify"],
        scan_duration_minutes=30.0,
    )

    assert result is not None
    assert result.estimated_hours == 6.0

    # Verify records were UPDATED (not new records created)
    async with async_session_scope() as session:
        stmt = select(LLMCostRecord).where(LLMCostRecord.run_id == run_id)
        updated = (await session.exec(stmt)).all()

    assert len(updated) == initial_count, (
        f"Expected {initial_count} records, got {len(updated)} (should NOT create new records)"
    )
    # All records should now have human_cost_hours and human_cost_usd populated
    for rec in updated:
        assert rec.human_cost_hours is not None and rec.human_cost_hours > 0
        assert rec.human_cost_usd is not None and rec.human_cost_usd > 0

    # Total should sum to estimated values
    total_hours = sum(r.human_cost_hours for r in updated)
    total_usd = sum(r.human_cost_usd for r in updated)
    assert abs(total_hours - 6.0) < 0.001
    assert abs(total_usd - 600.0) < 0.001  # 6.0 * 100.0


# ---------------------------------------------------------------------------
# Test 3: Human cost USD = estimated_hours * configured hourly rate
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_human_cost_usd_equals_hours_times_rate(hc_test_db):
    """Human cost USD = estimated_hours * configured hourly rate from ConfigRegistry."""
    run_id = "run-hc-03"
    await _seed_cost_records_for_run(run_id, count=1)

    client = _make_stub_llm_client(estimated_hours=4.0)
    registry = _make_stub_registry(hourly_rate=200.0)

    result = await estimate_human_cost(
        llm_client=client,
        registry=registry,
        team_id=None,
        run_id=run_id,
        target_count=5,
        finding_count=8,
        task_types_performed=["scoring"],
        scan_duration_minutes=20.0,
    )

    assert result is not None

    # Verify the stored human_cost_usd = hours * rate = 4.0 * 200.0 = 800.0
    from sqlmodel import select
    async with async_session_scope() as session:
        stmt = select(LLMCostRecord).where(LLMCostRecord.run_id == run_id)
        records = (await session.exec(stmt)).all()

    total_usd = sum(r.human_cost_usd for r in records if r.human_cost_usd is not None)
    assert abs(total_usd - 800.0) < 0.001, f"Expected 800.0, got {total_usd}"


# ---------------------------------------------------------------------------
# Test 4: Default hourly rate is _DEFAULT_HOURLY_RATE when config key missing
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_default_hourly_rate_when_config_missing(hc_test_db):
    """estimate_human_cost uses _DEFAULT_HOURLY_RATE (150.0) when config key returns None."""
    run_id = "run-hc-04"
    await _seed_cost_records_for_run(run_id, count=1)

    client = _make_stub_llm_client(estimated_hours=2.0)
    registry = _make_stub_registry(hourly_rate=None)  # No config -> None

    result = await estimate_human_cost(
        llm_client=client,
        registry=registry,
        team_id=None,
        run_id=run_id,
        target_count=3,
        finding_count=5,
        task_types_performed=["classify"],
        scan_duration_minutes=10.0,
    )

    assert result is not None

    # Verify USD = 2.0 * 150.0 = 300.0 (default rate)
    from sqlmodel import select
    async with async_session_scope() as session:
        stmt = select(LLMCostRecord).where(LLMCostRecord.run_id == run_id)
        records = (await session.exec(stmt)).all()

    total_usd = sum(r.human_cost_usd for r in records if r.human_cost_usd is not None)
    expected_usd = 2.0 * _DEFAULT_HOURLY_RATE
    assert abs(total_usd - expected_usd) < 0.001, (
        f"Expected {expected_usd} (default rate), got {total_usd}"
    )


# ---------------------------------------------------------------------------
# Test 5: LLM call uses run_id=None (not attributed to the scan run)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_llm_call_uses_run_id_none(hc_test_db):
    """estimate_human_cost passes run_id=None to chat_structured (D-06b)."""
    run_id = "run-hc-05"
    await _seed_cost_records_for_run(run_id, count=1)

    client = _make_stub_llm_client()
    registry = _make_stub_registry()

    await estimate_human_cost(
        llm_client=client,
        registry=registry,
        team_id="team-abc",
        run_id=run_id,
        target_count=5,
        finding_count=10,
        task_types_performed=["scoring"],
        scan_duration_minutes=15.0,
    )

    call_kwargs = client.chat_structured.call_args[1]  # keyword args
    assert call_kwargs.get("run_id") is None, (
        f"Expected run_id=None in chat_structured call, got run_id={call_kwargs.get('run_id')}"
    )


# ---------------------------------------------------------------------------
# Test 6: The estimation LLM call uses task_type="cost_estimation" (string literal)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_estimation_call_uses_cost_estimation_task_type_literal(hc_test_db):
    """Verify task_type='cost_estimation' is passed as a string literal."""
    run_id = "run-hc-06"
    await _seed_cost_records_for_run(run_id, count=1)

    client = _make_stub_llm_client()
    registry = _make_stub_registry()

    await estimate_human_cost(
        llm_client=client,
        registry=registry,
        team_id=None,
        run_id=run_id,
        target_count=5,
        finding_count=10,
        task_types_performed=["scoring"],
        scan_duration_minutes=15.0,
    )

    args = client.chat_structured.call_args[0]
    assert args[0] == "cost_estimation"
    # Also verify the model class passed is HumanCostEstimate
    assert args[2] is HumanCostEstimate


# ---------------------------------------------------------------------------
# Test 7: LLM call failure is logged and returns None
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_llm_call_failure_returns_none(hc_test_db):
    """estimate_human_cost returns None when chat_structured raises an exception."""
    run_id = "run-hc-07"
    await _seed_cost_records_for_run(run_id, count=1)

    from aila.platform.llm.errors import LLMError

    client = MagicMock()
    client.chat_structured = AsyncMock(side_effect=LLMError("LLM unavailable", retryable=False))
    registry = _make_stub_registry()

    result = await estimate_human_cost(
        llm_client=client,
        registry=registry,
        team_id=None,
        run_id=run_id,
        target_count=5,
        finding_count=10,
        task_types_performed=["scoring"],
        scan_duration_minutes=15.0,
    )

    assert result is None, "Should return None on LLM failure (never raise)"


# ---------------------------------------------------------------------------
# Test 8: When no LLMCostRecords exist for run_id, returns None
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_returns_none_when_no_records_for_run(hc_test_db):
    """estimate_human_cost returns None when no LLMCostRecords exist for the run_id."""
    client = _make_stub_llm_client()
    registry = _make_stub_registry()

    result = await estimate_human_cost(
        llm_client=client,
        registry=registry,
        team_id=None,
        run_id="nonexistent-run-xyz-999",
        target_count=5,
        finding_count=10,
        task_types_performed=["scoring"],
        scan_duration_minutes=15.0,
    )

    assert result is None, "Should return None when no records found for run_id"
