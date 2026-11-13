"""#434 -- a drain stops submissions from every TaskQueue instance.

The admin drain endpoint and module code each build their own TaskQueue, so
the drain flag must live in state they share (Redis), not on the instance.
The Redis server is replaced by an in-memory stand-in shared by every client
the queue opens; the ARQ enqueue is the other external boundary.
"""
from __future__ import annotations

import uuid
from unittest.mock import AsyncMock

import pytest
from sqlmodel import select

from aila.api.constants import MODULE_ID_PLATFORM
from aila.platform.tasks import queue as queue_mod
from aila.platform.tasks.models import TaskRecord
from aila.storage.database import async_session_scope

_REDIS_URL = "redis://shared-broker:6379/0"


class _RedisServer:
    """One Redis server; every client opened against it sees the same keys."""

    def __init__(self) -> None:
        self.keys: dict[str, str] = {}

    def client(self, url: str, **_: object) -> _RedisClient:
        assert url == _REDIS_URL
        return _RedisClient(self)


class _RedisClient:
    def __init__(self, server: _RedisServer) -> None:
        self._server = server

    async def exists(self, key: str) -> int:
        return int(key in self._server.keys)

    async def set(self, key: str, value: str) -> bool:
        self._server.keys[key] = value
        return True

    async def delete(self, key: str) -> int:
        return int(self._server.keys.pop(key, None) is not None)

    async def aclose(self) -> None:
        return None


async def _dummy_task(ctx: dict, **kwargs: object) -> dict:
    return {}


def _queue() -> queue_mod.TaskQueue:
    tq = queue_mod.TaskQueue(config_registry=None, module_id=MODULE_ID_PLATFORM)
    tq._get_redis_url = lambda: _REDIS_URL  # type: ignore[method-assign]
    tq._compute_investigation_defer = AsyncMock(return_value=0.0)  # type: ignore[method-assign]
    tq._arq_enqueue_async = AsyncMock(return_value=True)  # type: ignore[method-assign]
    return tq


async def _records_for_track(track: str) -> list[TaskRecord]:
    async with async_session_scope() as session:
        return list((await session.exec(select(TaskRecord).where(TaskRecord.track == track))).all())


@pytest.mark.usefixtures("test_db")
async def test_drain_rejects_submissions_from_a_fresh_instance_until_undrained(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server = _RedisServer()
    monkeypatch.setattr(queue_mod.aioredis.Redis, "from_url", server.client)
    track = f"drain-{uuid.uuid4().hex[:8]}"

    admin_queue = _queue()
    await admin_queue.drain()

    module_queue = _queue()
    with pytest.raises(RuntimeError, match="draining"):
        await module_queue.submit(track=track, fn=_dummy_task, kwargs={"n": 1}, user_id="u1")

    module_queue._arq_enqueue_async.assert_not_awaited()
    assert await _records_for_track(track) == []

    await _queue().undrain()

    handle = await module_queue.submit(track=track, fn=_dummy_task, kwargs={"n": 2}, user_id="u1")

    module_queue._arq_enqueue_async.assert_awaited_once()
    assert [r.id for r in await _records_for_track(track)] == [handle.task_id]
