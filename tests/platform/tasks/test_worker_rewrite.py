"""Phase 179 Task 2 -- worker.py rewrite invariants.

Asserts the slim WorkerSettings shape (D-07..D-14), proves deleted symbols
no longer exist, and exercises the reaper's orphan-lock reconciliation
against real Memurai.
"""
from __future__ import annotations

import uuid

import pytest
import pytest_asyncio

from aila.platform.tasks.hooks import _on_job_end, _on_job_start


def test_worker_settings_shape() -> None:
    from aila.platform.tasks.template import _REGISTRY
    from aila.platform.tasks.worker import WorkerSettings

    assert WorkerSettings.max_tries == 3
    assert WorkerSettings.job_timeout == 3600
    assert WorkerSettings.retry_jobs is True
    assert WorkerSettings.allow_abort_jobs is True
    assert WorkerSettings.health_check_interval == 60
    assert WorkerSettings.keep_result == 3600
    assert WorkerSettings.on_job_start is _on_job_start
    assert WorkerSettings.on_job_end is _on_job_end

    # functions non-empty (registry bootstrap registered run_platform_handle)
    assert len(WorkerSettings.functions) > 0
    # Every entry is a registry-wrapped coroutine OR a legacy ARQ callable.
    # For the @platform_task-decorated ones, they must be present in the
    # registry's all_functions() list.
    registry_fns = set(_REGISTRY.all_functions())
    assert any(fn in registry_fns for fn in WorkerSettings.functions), (
        "WorkerSettings.functions should include @platform_task-wrapped callables"
    )


def test_worker_settings_cron_contains_reaper() -> None:
    from aila.platform.tasks.worker import WorkerSettings, reaper

    assert len(WorkerSettings.cron_jobs) == 1
    cron_entry = WorkerSettings.cron_jobs[0]
    # arq.cron returns a CronJob namedtuple with a .coroutine attribute
    # pointing at the wrapped callable.
    assert getattr(cron_entry, "coroutine", None) is reaper or (
        # Older ARQ versions call it .func
        getattr(cron_entry, "func", None) is reaper
    )


def test_legacy_symbols_removed_from_worker() -> None:
    import aila.platform.tasks.worker as worker

    for symbol in (
        "execute_task_job",
        "TaskCancelled",
        "_heartbeat_loop",
        "_refresh_worker_alive_key",
        "_finalize",
        "_persist_checkpoint",
        "save_checkpoint",
        "_clear_corrupt_checkpoint",
        "_sweep_orphaned_waiting",
        "_reenqueue_task",
    ):
        assert not hasattr(worker, symbol), (
            f"{symbol} must not exist on worker module (Phase 179 deletion)"
        )


def test_reaper_is_a_coroutine() -> None:
    import inspect

    from aila.platform.tasks.worker import reaper

    assert inspect.iscoroutinefunction(reaper)


@pytest_asyncio.fixture
async def redis_db15(redis_cleanup: str) -> str:
    """Yield the redis URL for the flushed test db-15 instance."""
    return redis_cleanup


@pytest.mark.asyncio
async def test_reaper_reconciles_orphan_in_progress_lock(
    redis_db15: str,
    test_db: None,  # noqa: ARG001
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Seed a bare arq:in-progress:ghost key and prove reaper deletes it."""
    import redis.asyncio as aioredis

    from aila.api.metrics import TASK_ZOMBIES_REAPED_TOTAL
    from aila.platform.tasks.worker import reaper

    monkeypatch.setenv("AILA_PLATFORM_REDIS_URL", redis_db15)

    ghost_job_id = f"ghost-{uuid.uuid4()}"
    client = aioredis.Redis.from_url(redis_db15, socket_connect_timeout=2.0)
    try:
        await client.set(f"arq:in-progress:{ghost_job_id}", "1")

        before = TASK_ZOMBIES_REAPED_TOTAL.labels(
            reason="orphaned_arq_lock",
        )._value.get()  # type: ignore[attr-defined]

        await reaper({})

        # Lock removed (no DB record -> reap).
        assert await client.exists(f"arq:in-progress:{ghost_job_id}") == 0

        after = TASK_ZOMBIES_REAPED_TOTAL.labels(
            reason="orphaned_arq_lock",
        )._value.get()  # type: ignore[attr-defined]
        assert after > before, (
            f"TASK_ZOMBIES_REAPED_TOTAL did not advance ({before} -> {after})"
        )
    finally:
        await client.aclose()
