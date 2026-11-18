"""TaskQueue.wait_result -- worker result retrieval through platform Redis transport.

The ARQ pool and Job are the only external boundaries; both are replaced so the
test is deterministic and needs no Redis server.
"""
from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from arq.jobs import ResultNotFound

from aila.api.constants import MODULE_ID_PLATFORM
from aila.platform.exceptions import WorkerUnreachableError
from aila.platform.tasks import queue as queue_mod
from aila.platform.tasks.models import TaskHandle

_REDIS_URL = "redis://broker:6379/0"
_TRACK = "vulnerability"
_HANDLE = TaskHandle(task_id="task-abc")


def _queue() -> queue_mod.TaskQueue:
    tq = queue_mod.TaskQueue(config_registry=None, module_id=MODULE_ID_PLATFORM)
    tq._get_redis_url = lambda: _REDIS_URL  # type: ignore[method-assign]
    return tq


def _install(monkeypatch, *, result=None, result_exc=None, pool_exc=None):
    pool = SimpleNamespace(aclose=AsyncMock())
    create_pool = AsyncMock(return_value=pool, side_effect=pool_exc)
    monkeypatch.setattr(queue_mod, "create_pool", create_pool)

    job_instance = SimpleNamespace(
        result=AsyncMock(return_value=result, side_effect=result_exc),
    )
    job_cls = MagicMock(return_value=job_instance)
    monkeypatch.setattr(queue_mod, "Job", job_cls)
    return pool, create_pool, job_cls, job_instance


async def test_returns_deserialized_result_and_binds_track_queue(monkeypatch) -> None:
    pool, create_pool, job_cls, job_instance = _install(
        monkeypatch, result={"ok": 1}
    )

    out = await _queue().wait_result(_HANDLE, track=_TRACK, timeout_seconds=30.0)

    assert out == {"ok": 1}
    create_pool.assert_awaited_once()
    job_cls.assert_called_once_with(
        "task-abc", pool, _queue_name="arq:queue:vulnerability"
    )
    job_instance.result.assert_awaited_once_with(timeout=30.0, poll_delay=0.5)
    pool.aclose.assert_awaited_once()


async def test_timeout_maps_to_worker_unreachable_and_closes_pool(monkeypatch) -> None:
    pool, _, _, _ = _install(monkeypatch, result_exc=TimeoutError())

    with pytest.raises(WorkerUnreachableError, match="Timed out after 5.0s"):
        await _queue().wait_result(_HANDLE, track=_TRACK, timeout_seconds=5.0)

    pool.aclose.assert_awaited_once()


async def test_result_not_found_maps_to_worker_unreachable(monkeypatch) -> None:
    pool, _, _, _ = _install(monkeypatch, result_exc=ResultNotFound("gone"))

    with pytest.raises(WorkerUnreachableError, match="unavailable"):
        await _queue().wait_result(_HANDLE, track=_TRACK, timeout_seconds=5.0)

    pool.aclose.assert_awaited_once()


async def test_broker_unavailable_maps_to_worker_unreachable(monkeypatch) -> None:
    _, _, job_cls, _ = _install(monkeypatch, pool_exc=OSError("connection refused"))

    with pytest.raises(WorkerUnreachableError, match="unreachable"):
        await _queue().wait_result(_HANDLE, track=_TRACK, timeout_seconds=5.0)

    job_cls.assert_not_called()


async def test_missing_redis_url_rejected_without_connecting(monkeypatch) -> None:
    _, create_pool, _, _ = _install(monkeypatch, result={})
    tq = _queue()
    tq._get_redis_url = lambda: None  # type: ignore[method-assign]

    with pytest.raises(WorkerUnreachableError, match="not configured"):
        await tq.wait_result(_HANDLE, track=_TRACK, timeout_seconds=5.0)

    create_pool.assert_not_called()


async def test_job_exception_propagates_unchanged_and_closes_pool(monkeypatch) -> None:
    pool, _, _, _ = _install(monkeypatch, result_exc=ValueError("job failed"))

    with pytest.raises(ValueError, match="job failed"):
        await _queue().wait_result(_HANDLE, track=_TRACK, timeout_seconds=5.0)

    pool.aclose.assert_awaited_once()
