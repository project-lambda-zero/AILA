"""Phase 178: TaskQueue.submit no longer has a sync fallback.

The previous behaviour was to silently execute tasks in-process when
Redis was unreachable. This test module proves:

1. submit() raises WorkerUnreachableError when AILA_PLATFORM_REDIS_URL is
   unset (no DB orphan written).
2. submit() raises WorkerUnreachableError when the configured Redis host
   rejects connections, rolling back the DB record that was transiently
   created for dedup semantics.
3. The sync-fallback attribute is gone from TaskQueue (grep audit).
"""
from __future__ import annotations

import pytest

from aila.platform.exceptions import WorkerUnreachableError
from aila.platform.tasks.models import TaskRecord, TaskStatus
from aila.platform.tasks.queue import TaskQueue

from .conftest import sqlite_db_env


def _module_fn():
    """Function callable by the queue; lives in this module so module-boundary passes."""
    def fn(**_kwargs):  # noqa: ARG001 -- deliberate stub
        return None

    fn.__qualname__ = "fn"
    fn.__module__ = "aila.platform.tasks.queue"  # pretend it's platform
    return fn


@pytest.mark.asyncio
async def test_submit_raises_when_redis_url_unset(tmp_path, monkeypatch) -> None:
    """No AILA_PLATFORM_REDIS_URL -> WorkerUnreachableError, no DB record."""
    monkeypatch.delenv("AILA_PLATFORM_REDIS_URL", raising=False)

    with sqlite_db_env(tmp_path, "no_redis") as (engine, _):
        queue = TaskQueue(config_registry=None, module_id="__platform__")

        with pytest.raises(WorkerUnreachableError) as exc_info:
            await queue.submit(
                track="platform",
                fn=_module_fn(),
                kwargs={"x": 1},
                user_id="u1",
                group_id="operator",
            )

        # Typed exception surfaces HTTP 503 via the envelope pipeline.
        assert exc_info.value.__class__.code == "WORKER_UNREACHABLE"
        assert exc_info.value.__class__.http_status == 503

        # No DB record left behind -- caller gets a clean 503, nothing to
        # clean up later.
        from sqlmodel import Session, select

        with Session(engine) as s:
            rows = s.exec(select(TaskRecord)).all()
            assert rows == [], f"Expected no TaskRecord; found {len(rows)}"


@pytest.mark.asyncio
async def test_submit_raises_when_redis_host_unreachable(tmp_path, monkeypatch) -> None:
    """Unreachable Redis host -> WorkerUnreachableError, no orphan DB row."""
    # Port 1 is privileged + closed on every sane host.
    monkeypatch.setenv("AILA_PLATFORM_REDIS_URL", "redis://127.0.0.1:1/0")

    with sqlite_db_env(tmp_path, "unreach_redis") as (engine, _):
        queue = TaskQueue(config_registry=None, module_id="__platform__")

        with pytest.raises(WorkerUnreachableError):
            await queue.submit(
                track="platform",
                fn=_module_fn(),
                kwargs={"y": 2},
                user_id="u1",
                group_id="operator",
            )

        from sqlmodel import Session, select

        with Session(engine) as s:
            # The submit path transiently inserts a queued TaskRecord, then
            # rolls it back when enqueue fails. Ensure nothing is leaked.
            stuck = s.exec(
                select(TaskRecord).where(TaskRecord.status == TaskStatus.QUEUED)
            ).all()
            assert stuck == [], f"queued orphans leaked: {stuck}"


def test_sync_fallback_attribute_is_gone() -> None:
    """No _sync_fallback method on TaskQueue anymore."""
    assert not hasattr(TaskQueue, "_sync_fallback")


def test_sync_fallback_string_is_gone_from_tasks_source() -> None:
    """Static audit -- the literal sync_fallback / no_redis.fallback must not
    appear in the tasks tree anymore. The routers legitimately use
    ``_no_redis_generator`` for SSE streams; that is a different concern.
    """
    import pathlib

    tasks_dir = pathlib.Path(__file__).resolve().parents[3] / "src" / "aila" / "platform" / "tasks"
    offending = []
    for py in tasks_dir.rglob("*.py"):
        text = py.read_text(encoding="utf-8")
        if "_sync_fallback" in text:
            offending.append(str(py))
    assert not offending, f"_sync_fallback survived in: {offending}"
