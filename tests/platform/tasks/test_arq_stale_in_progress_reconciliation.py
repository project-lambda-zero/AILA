"""Phase 178: reaper reconciles orphaned arq:in-progress:* locks.

When a worker dies mid-job ARQ leaves an arq:in-progress:{job_id} key
behind with a 24h TTL, which blocks every subsequent job in the same
queue. The reaper must:

* Detect arq:in-progress:* keys whose matching TaskRecord is absent,
  terminal, or stale-heartbeat.
* Delete the lock plus the companion arq:job:* / arq:retry:* keys.
* Remove the job id from the arq:queue:{track} zset so real workers can
  make progress.

These tests require a live Redis — they skip cleanly otherwise.
"""
from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from sqlmodel import Session

from aila.platform.tasks.constants import (
    ARQ_IN_PROGRESS_PREFIX,
    ARQ_JOB_PREFIX,
    ARQ_QUEUE_KEY_TEMPLATE,
)
from aila.platform.tasks.models import TaskRecord, TaskStatus
from aila.platform.tasks.worker import _reconcile_orphan_arq_locks

from .conftest import sqlite_db_env


@pytest.mark.asyncio
async def test_orphan_lock_is_deleted(tmp_path, redis_cleanup, monkeypatch) -> None:
    """arq:in-progress:* with no DB record -> lock + companions removed."""
    monkeypatch.setenv("AILA_PLATFORM_REDIS_URL", redis_cleanup)

    import redis.asyncio as aioredis

    with sqlite_db_env(tmp_path, "orphan_lock") as (_engine, _):
        ghost_job = "ghost-job-id-no-db-record"
        client = aioredis.Redis.from_url(redis_cleanup)
        try:
            await client.set(f"{ARQ_IN_PROGRESS_PREFIX}{ghost_job}", b"1", ex=86400)
            await client.set(f"{ARQ_JOB_PREFIX}{ghost_job}", b"payload", ex=86400)
            await client.zadd(
                ARQ_QUEUE_KEY_TEMPLATE.format(track="vulnerability"),
                {ghost_job: 123.0},
            )

            await _reconcile_orphan_arq_locks()

            assert await client.exists(f"{ARQ_IN_PROGRESS_PREFIX}{ghost_job}") == 0
            assert await client.exists(f"{ARQ_JOB_PREFIX}{ghost_job}") == 0
            # Lock had no DB record so we could not know the track; we
            # leave the zset alone in that branch. No assertion on zset
            # here -- the next test proves zset cleanup when the DB row
            # exists.
        finally:
            await client.aclose()


@pytest.mark.asyncio
async def test_orphan_lock_with_stale_db_record_is_deleted(
    tmp_path, redis_cleanup, monkeypatch
) -> None:
    """Lock + DB row with stale heartbeat -> lock removed, zset cleaned."""
    monkeypatch.setenv("AILA_PLATFORM_REDIS_URL", redis_cleanup)

    import redis.asyncio as aioredis

    with sqlite_db_env(tmp_path, "orphan_stale_db") as (engine, _):
        job_id = "stale-hb-job"
        # DB record with an old heartbeat (simulating dead worker).
        with Session(engine) as s:
            rec = TaskRecord(
                id=job_id,
                track="vulnerability",
                fn_path="aila.modules.vulnerability.tasks.scan",
                fn_module="vulnerability",
                user_id="u",
                group_id="operator",
                status=TaskStatus.RUNNING,
                heartbeat_at=datetime.now(tz=UTC) - timedelta(seconds=86400 + 3600),
            )
            s.add(rec)
            s.commit()

        client = aioredis.Redis.from_url(redis_cleanup)
        try:
            await client.set(f"{ARQ_IN_PROGRESS_PREFIX}{job_id}", b"1", ex=86400)
            queue_key = ARQ_QUEUE_KEY_TEMPLATE.format(track="vulnerability")
            await client.zadd(queue_key, {job_id: 42.0})

            await _reconcile_orphan_arq_locks()

            assert await client.exists(f"{ARQ_IN_PROGRESS_PREFIX}{job_id}") == 0
            assert await client.zscore(queue_key, job_id) is None
        finally:
            await client.aclose()


@pytest.mark.asyncio
async def test_fresh_heartbeat_lock_left_alone(
    tmp_path, redis_cleanup, monkeypatch
) -> None:
    """Legit in-flight work -> lock untouched.

    No ``heartbeat_at`` set (pre-heartbeat or very first state transition
    not yet committed), so freshness falls back to ``started_at``.
    A recent ``started_at`` is well within REAPER_ZOMBIE_THRESHOLD_S so
    the lock must be left alone.
    """
    monkeypatch.setenv("AILA_PLATFORM_REDIS_URL", redis_cleanup)

    import redis.asyncio as aioredis

    with sqlite_db_env(tmp_path, "orphan_fresh") as (engine, _):
        job_id = "fresh-hb-job"
        with Session(engine) as s:
            rec = TaskRecord(
                id=job_id,
                track="vulnerability",
                fn_path="aila.modules.vulnerability.tasks.scan",
                fn_module="vulnerability",
                user_id="u",
                group_id="operator",
                status=TaskStatus.RUNNING,
                started_at=datetime.now(tz=UTC),
            )
            s.add(rec)
            s.commit()

        client = aioredis.Redis.from_url(redis_cleanup)
        try:
            await client.set(f"{ARQ_IN_PROGRESS_PREFIX}{job_id}", b"1", ex=86400)
            await _reconcile_orphan_arq_locks()
            # Recent started_at means the lock legitimately reflects
            # running work; reaper must not nuke it.
            assert await client.exists(f"{ARQ_IN_PROGRESS_PREFIX}{job_id}") == 1
        finally:
            await client.aclose()
