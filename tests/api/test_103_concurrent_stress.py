"""Concurrent submission stress tests -- Phase 103.

Proves the API survives concurrent load without deadlock, data corruption,
or SQLITE_BUSY errors across the full HTTP endpoint path.

Requirements covered:
  STRESS-01: 5 concurrent POST /analyze return 202, distinct task IDs, 5 DB records
  STRESS-02: 10 concurrent POST /auth/token all return 200 with valid JWTs
  STRESS-03: 3 writers + 5 readers WAL contention, zero lock errors, 50 records
"""
from __future__ import annotations

import asyncio
import time
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient
from sqlmodel import select

from aila.platform.tasks.models import TaskRecord, TaskStatus
from aila.storage.database import session_scope

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture(scope="function")
async def stress_client(test_db) -> AsyncClient:
    """Async client with a stub platform that has a config_registry returning
    None for Redis URL, forcing the sync fallback path in TaskQueue.submit().

    The sync fallback calls run_platform_handle which constructs AILAPlatform --
    that would fail in tests. Instead, we patch run_platform_handle to be a no-op
    so the full submit -> DB persist -> sync_fallback -> DONE flow completes.
    """
    from aila.api.app import create_app

    test_app = create_app()

    # Build a stub platform with config_registry that returns None for redis_url
    stub_config_registry = MagicMock()
    stub_config_registry.get.return_value = None  # No Redis -> sync fallback

    stub_runtime = MagicMock()
    stub_runtime.config_registry = stub_config_registry

    stub_platform = MagicMock()
    stub_platform.runtime = stub_runtime

    test_app.state.platform = stub_platform
    test_app.state.start_time = time.monotonic()

    async with AsyncClient(
        transport=ASGITransport(app=test_app),
        base_url="http://testserver",
    ) as client:
        yield client


# ---------------------------------------------------------------------------
# STRESS-01: 5 concurrent POST /analyze
# ---------------------------------------------------------------------------


async def test_stress_concurrent_analyze_submissions(
    stress_client: AsyncClient,
    operator_token: str,
) -> None:
    """STRESS-01: 5 concurrent POST /analyze return 202 with distinct task IDs.

    Uses a mock platform with no Redis so TaskQueue.submit() uses the sync
    fallback path. run_platform_handle is patched to a no-op since we cannot
    construct a real AILAPlatform in tests. The important thing: the full HTTP
    path (auth -> submit -> DB persist -> sync_fallback -> audit) completes
    without deadlock under concurrent load.
    """
    def _noop_handle(**_kwargs: object) -> None:
        """No-op replacement for run_platform_handle in sync fallback."""

    async def _submit(idx: int) -> tuple[int, dict]:
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(
                "aila.api.routers.scans.run_platform_handle",
                _noop_handle,
            )
            resp = await stress_client.post(
                "/analyze",
                json={"query_text": f"scan target-{idx} for vulnerabilities"},
                headers={"Authorization": f"Bearer {operator_token}"},
            )
        return resp.status_code, resp.json()

    # Fire all 5 concurrently
    results = await asyncio.gather(*(_submit(i) for i in range(5)))

    status_codes = [r[0] for r in results]
    bodies = [r[1] for r in results]

    # All 5 must return 202 Accepted
    assert all(
        code == 202 for code in status_codes
    ), f"Not all requests returned 202: {status_codes}"

    # All 5 must have distinct run_ids
    run_ids = [b["run_id"] for b in bodies]
    assert len(set(run_ids)) == 5, f"Expected 5 distinct run_ids, got {len(set(run_ids))}: {run_ids}"

    # All 5 must have status="submitted"
    assert all(
        b.get("status") == "submitted" for b in bodies
    ), f"Not all responses have status=submitted: {bodies}"

    # All 5 TaskRecords must exist in the DB (sync fallback marks them DONE)
    with session_scope() as session:
        records = list(
            session.exec(
                select(TaskRecord).where(TaskRecord.id.in_(run_ids))  # type: ignore[union-attr]
            ).all()
        )
    assert len(records) == 5, f"Expected 5 TaskRecords in DB, got {len(records)}"


# ---------------------------------------------------------------------------
# STRESS-02: 10 concurrent POST /auth/token
# ---------------------------------------------------------------------------


async def test_stress_concurrent_auth_token(
    async_client: AsyncClient,
    operator_key_record,
) -> None:
    """STRESS-02: 10 concurrent POST /auth/token with the same API key all return 200.

    Exercises the full HTTP path: JSON parsing -> DB lookup -> bcrypt verify ->
    JWT issuance -> audit event -> response. All 10 must succeed without DB
    lock errors or 500s. All 10 JWTs must be non-empty and contain valid claims.
    """
    raw_key: str = operator_key_record._raw_key  # type: ignore[attr-defined]

    async def _request_token() -> tuple[int, dict]:
        resp = await async_client.post(
            "/auth/token",
            json={"api_key": raw_key},
        )
        return resp.status_code, resp.json()

    results = await asyncio.gather(*(_request_token() for _ in range(10)))

    status_codes = [r[0] for r in results]
    bodies = [r[1] for r in results]

    # All 10 must return HTTP 200
    assert all(
        code == 200 for code in status_codes
    ), f"Not all requests returned 200: {status_codes}"

    # All 10 must return non-empty access_token
    tokens = [b.get("access_token", "") for b in bodies]
    assert all(
        token for token in tokens
    ), f"Some responses returned empty access_token: {tokens}"

    # All 10 must return token_type=bearer
    assert all(
        b.get("token_type") == "bearer" for b in bodies
    ), "Some responses have wrong token_type"

    # All 10 must return non-empty refresh_token
    refresh_tokens = [b.get("refresh_token", "") for b in bodies]
    assert all(
        rt for rt in refresh_tokens
    ), "Some responses returned empty refresh_token"

    # Verify JWTs are decodable (valid structure)
    import jwt as pyjwt

    from aila.config import get_settings

    settings = get_settings()
    for i, token in enumerate(tokens):
        payload = pyjwt.decode(token, settings.jwt_secret_key, algorithms=["HS256"])
        assert "key_id" in payload, f"Token {i} missing key_id claim"
        assert "role" in payload, f"Token {i} missing role claim"
        assert payload["role"] == "operator", f"Token {i} has wrong role: {payload['role']}"


# ---------------------------------------------------------------------------
# STRESS-03: WAL contention -- 3 writers + 5 readers
# ---------------------------------------------------------------------------


async def test_stress_wal_contention(test_db: None) -> None:
    """STRESS-03: 3 writers + 5 readers against WAL SQLite produce zero lock errors.

    Seeds 20 TaskRecords, then launches 3 writer threads (each inserting 10
    records) and 5 reader threads concurrently. WAL mode with busy_timeout=30000
    ensures writers wait rather than fail with SQLITE_BUSY.

    Assertions:
    - Zero exceptions from any thread
    - Final record count = 50 (20 seeded + 30 written)
    - Every reader saw at least 20 records (the seeded baseline)
    """
    # Seed 20 records
    seed_ids: list[str] = []
    with session_scope() as session:
        for i in range(20):
            tid = str(uuid4())
            seed_ids.append(tid)
            record = TaskRecord(
                id=tid,
                track="vulnerability",
                fn_path="aila.test.stress_seed",
                fn_module="__platform__",
                status=TaskStatus.QUEUED,
                user_id="seed-user",
                group_id="operator",
                kwargs_json="{}",
            )
            session.add(record)
        session.commit()

    # Verify seed
    with session_scope() as session:
        seed_count = len(list(session.exec(select(TaskRecord)).all()))
    assert seed_count == 20, f"Expected 20 seeded records, got {seed_count}"

    writer_errors: list[Exception] = []
    reader_errors: list[Exception] = []
    reader_counts: list[int] = []

    def _writer(writer_id: int) -> None:
        """Insert 10 TaskRecords in a single transaction."""
        try:
            with session_scope() as session:
                for j in range(10):
                    record = TaskRecord(
                        id=str(uuid4()),
                        track="vulnerability",
                        fn_path=f"aila.test.stress_writer_{writer_id}",
                        fn_module="__platform__",
                        status=TaskStatus.QUEUED,
                        user_id=f"writer-{writer_id}",
                        group_id="operator",
                        kwargs_json="{}",
                    )
                    session.add(record)
                session.commit()
        except Exception as exc:
            writer_errors.append(exc)

    def _reader(reader_id: int) -> None:
        """Read all TaskRecords and record the count."""
        try:
            with session_scope() as session:
                count = len(list(session.exec(select(TaskRecord)).all()))
                reader_counts.append(count)
        except Exception as exc:
            reader_errors.append(exc)

    # Launch 3 writers + 5 readers concurrently
    await asyncio.gather(
        asyncio.to_thread(_writer, 0),
        asyncio.to_thread(_writer, 1),
        asyncio.to_thread(_writer, 2),
        asyncio.to_thread(_reader, 0),
        asyncio.to_thread(_reader, 1),
        asyncio.to_thread(_reader, 2),
        asyncio.to_thread(_reader, 3),
        asyncio.to_thread(_reader, 4),
    )

    # Zero exceptions
    assert writer_errors == [], f"Writer threads raised errors: {writer_errors}"
    assert reader_errors == [], f"Reader threads raised errors: {reader_errors}"

    # Final count: 20 seeded + 30 written = 50
    with session_scope() as session:
        final_records = list(session.exec(select(TaskRecord)).all())
    assert len(final_records) == 50, (
        f"Expected 50 total records (20 seeded + 30 written), got {len(final_records)}"
    )

    # Every reader saw at least the 20 seeded records
    assert len(reader_counts) == 5, f"Expected 5 reader results, got {len(reader_counts)}"
    for i, count in enumerate(reader_counts):
        assert count >= 20, (
            f"Reader {i} saw only {count} records, expected at least 20 (seeded)"
        )
