"""Issue #40-7: the ``boot_grace_cutoff`` variable in
``_sweep_orphan_queued_tasks`` is dead code -- ``recency_cutoff``
(60s ago) already dominates the 10s ``boot_grace_cutoff`` window, so
the second predicate never eliminates a row the first didn't.

These tests prove (a) the symbol is gone from ``worker.py`` and
(b) the sweep still reaps a >60s-old QUEUED row that isn't in ARQ but
spares a <60s-old row (the invariant ``boot_grace_cutoff`` was meant
to protect).
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from sqlmodel import Session

import aila.platform.tasks.worker as worker_mod
from aila.platform.tasks.models import TaskRecord, TaskStatus

from .conftest import sqlite_db_env


def _async_iter_empty() -> Any:
    async def _gen() -> Any:
        return
        yield  # pragma: no cover  -- makes _gen an async generator

    return _gen()


def _fake_redis_client() -> MagicMock:
    """A MagicMock stand-in for the aioredis client the sweep opens.

    ``scan_iter`` yields no arq:queue:* keys, so the sweep's per-track
    membership map is empty and every non-cron QUEUED row past the
    recency cutoff is a reap candidate.
    """
    client = MagicMock()
    client.scan_iter = lambda **_k: _async_iter_empty()
    client.zrange = AsyncMock(return_value=[])
    client.aclose = AsyncMock()
    return client


def _insert_queued(
    session: Session, *, age_seconds: int, task_id: str | None = None,
) -> str:
    """Insert a QUEUED row with an explicit ``created_at`` in the past."""
    tid = task_id or str(uuid4())
    created = datetime.now(UTC) - timedelta(seconds=age_seconds)
    rec = TaskRecord(
        id=tid,
        track="platform",
        fn_path="aila.platform.tasks.queue.some_fn",
        fn_module="__platform__",
        status=TaskStatus.QUEUED,
        user_id="u",
        group_id="operator",
        kwargs_json="{}",
        created_at=created,
        updated_at=created,
    )
    session.add(rec)
    session.commit()
    return tid


@pytest.mark.asyncio
async def test_sweep_reaps_row_older_than_recency_cutoff(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 90s-old QUEUED row not in ARQ Redis is flipped to FAILED.

    Removing ``boot_grace_cutoff`` MUST NOT weaken this path -- the
    60s ``recency_cutoff`` is now the single guard.
    """
    monkeypatch.setenv("AILA_PLATFORM_REDIS_URL", "redis://127.0.0.1:6379/15")

    with sqlite_db_env(tmp_path, "sweep_reap") as (engine, _):
        with Session(engine) as s:
            reap_id = _insert_queued(s, age_seconds=90)

        with patch(
            "aila.platform.tasks.worker.aioredis.Redis.from_url",
            return_value=_fake_redis_client(),
        ):
            await worker_mod._sweep_orphan_queued_tasks()

        with Session(engine) as s:
            reaped = s.get(TaskRecord, reap_id)
            assert reaped is not None
            assert reaped.status == TaskStatus.FAILED
            assert reaped.error and "orphan-queued sweep" in reaped.error


@pytest.mark.asyncio
async def test_sweep_spares_row_within_recency_cutoff(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A 5s-old QUEUED row is spared even without ``boot_grace_cutoff``.

    This is the invariant ``boot_grace_cutoff`` was meant to protect --
    ``recency_cutoff`` (60s) is strictly tighter, so removing the 10s
    predicate did not open a new false-reap window.
    """
    monkeypatch.setenv("AILA_PLATFORM_REDIS_URL", "redis://127.0.0.1:6379/15")

    with sqlite_db_env(tmp_path, "sweep_spare") as (engine, _):
        with Session(engine) as s:
            fresh_id = _insert_queued(s, age_seconds=5)

        with patch(
            "aila.platform.tasks.worker.aioredis.Redis.from_url",
            return_value=_fake_redis_client(),
        ):
            await worker_mod._sweep_orphan_queued_tasks()

        with Session(engine) as s:
            fresh = s.get(TaskRecord, fresh_id)
            assert fresh is not None
            assert fresh.status == TaskStatus.QUEUED
            assert fresh.error is None
