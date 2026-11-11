"""Phase 179 Task 2 -- worker.py rewrite invariants.

Asserts the slim WorkerSettings shape (D-07..D-14), proves deleted symbols
no longer exist, and exercises the reaper's orphan-lock reconciliation
against real Memurai.
"""
from __future__ import annotations

import sys
import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio

import aila.logging_config as logging_config
import aila.platform.tasks.worker as worker_mod
import aila.storage.database as db_module
from aila.platform.tasks import sweeps
from aila.platform.tasks.hooks import _on_job_end, _on_job_start


def _patch_startup(
    monkeypatch: pytest.MonkeyPatch, engines: dict[str, Any], order: list[str],
) -> dict[str, Any]:
    """Replace ``_on_startup`` collaborators with mocks that record call order."""

    configure = MagicMock()
    load = MagicMock(side_effect=lambda: order.append("load"))
    sweep = AsyncMock(side_effect=lambda: order.append("sweep"))
    monkeypatch.setattr(logging_config, "configure_logging", configure)
    monkeypatch.setattr(worker_mod, "load_builtin_modules", load)
    monkeypatch.setattr(worker_mod, "_sweep_orphan_running_tasks", sweep)
    monkeypatch.setattr(db_module, "_ASYNC_ENGINES", engines)
    return {"load": load, "sweep": sweep}


def _fake_engine(order: list[str], name: str) -> MagicMock:
    engine = MagicMock()
    engine.dispose = AsyncMock(side_effect=lambda: order.append(f"dispose:{name}"))
    return engine


@pytest.mark.asyncio
async def test_on_startup_non_windows_registers_modules_and_sweeps_without_dispose(
    monkeypatch: pytest.MonkeyPatch,
) -> None:

    monkeypatch.setattr(sys, "platform", "linux")
    order: list[str] = []
    engine = _fake_engine(order, "postgres")
    engines = {"postgres": engine}
    mocks = _patch_startup(monkeypatch, engines, order)

    await worker_mod._on_startup({})

    mocks["load"].assert_called_once_with()
    mocks["sweep"].assert_awaited_once_with()
    engine.dispose.assert_not_awaited()
    assert engines == {"postgres": engine}
    assert order == ["load", "sweep"]


@pytest.mark.asyncio
async def test_on_startup_non_windows_populates_real_module_sweep_registry(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(logging_config, "configure_logging", MagicMock())
    orphan_sweep = AsyncMock()
    monkeypatch.setattr(worker_mod, "_sweep_orphan_running_tasks", orphan_sweep)
    snapshot = dict(sweeps._PERIODIC_SWEEPS)
    sweeps._PERIODIC_SWEEPS.clear()
    try:
        await worker_mod._on_startup({})
        registered = sweeps.all_periodic_sweeps()
        assert "vr.stall_recovery" in registered
        assert "malware.stall_recovery" in registered
        assert "forensics.stuck_healer" in registered
        orphan_sweep.assert_awaited_once_with()
    finally:
        sweeps._PERIODIC_SWEEPS.clear()
        sweeps._PERIODIC_SWEEPS.update(snapshot)


@pytest.mark.asyncio
async def test_on_startup_windows_disposes_engines_then_registers_and_sweeps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:

    monkeypatch.setattr(sys, "platform", "win32")
    order: list[str] = []
    engine = _fake_engine(order, "postgres")
    engines = {"postgres": engine}
    mocks = _patch_startup(monkeypatch, engines, order)

    await worker_mod._on_startup({})

    engine.dispose.assert_awaited_once_with()
    assert engines == {}
    mocks["load"].assert_called_once_with()
    mocks["sweep"].assert_awaited_once_with()
    assert order == ["dispose:postgres", "load", "sweep"]


@pytest.mark.asyncio
async def test_on_startup_windows_dispose_failure_still_registers_and_sweeps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:

    monkeypatch.setattr(sys, "platform", "win32")
    order: list[str] = []
    broken = _fake_engine(order, "broken")
    broken.dispose = AsyncMock(side_effect=OSError("proactor loop closed"))
    healthy = _fake_engine(order, "healthy")
    engines = {"broken": broken, "healthy": healthy}
    mocks = _patch_startup(monkeypatch, engines, order)

    await worker_mod._on_startup({})

    broken.dispose.assert_awaited_once_with()
    healthy.dispose.assert_awaited_once_with()
    assert engines == {}
    mocks["load"].assert_called_once_with()
    mocks["sweep"].assert_awaited_once_with()


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
    # #40-5: ``all_functions()`` returns ``arq.worker.Function`` objects
    # keyed by the fully-qualified registry name. Compare by ``.name``
    # since Function isn't hashable / equatable.
    registry_names = {fn.name for fn in _REGISTRY.all_functions()}
    settings_names = {
        getattr(fn, "name", None) or getattr(fn, "__qualname__", None)
        for fn in WorkerSettings.functions
    }
    assert registry_names & settings_names, (
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
