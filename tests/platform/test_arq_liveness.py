"""Batched ARQ liveness probe: one pooled pipeline, prefix-complete, fail-closed to None."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import pytest
from redis.exceptions import ConnectionError as RedisConnectionError

from aila.platform.tasks import liveness
from aila.platform.tasks.constants import (
    ARQ_IN_PROGRESS_PREFIX,
    ARQ_JOB_PREFIX,
    ARQ_RETRY_PREFIX,
)
from aila.platform.tasks.liveness import arq_active_task_ids


class _FakePipeline:
    def __init__(self, counts: list[int] | None, error: BaseException | None) -> None:
        self._counts = counts
        self._error = error
        self.exists_calls: list[tuple[str, ...]] = []
        self.transaction: bool | None = None

    def exists(self, *keys: str) -> None:
        self.exists_calls.append(keys)

    async def execute(self) -> list[int]:
        if self._error is not None:
            raise self._error
        assert self._counts is not None
        return self._counts


class _FakeClient:
    def __init__(self, pipeline: _FakePipeline) -> None:
        self._pipeline = pipeline

    def pipeline(self, *, transaction: bool) -> _FakePipeline:
        self._pipeline.transaction = transaction
        return self._pipeline


def _install_pool(
    monkeypatch: pytest.MonkeyPatch,
    pipeline: _FakePipeline,
) -> list[int]:
    opened: list[int] = []

    @asynccontextmanager
    async def _get_redis() -> AsyncIterator[_FakeClient]:
        opened.append(1)
        yield _FakeClient(pipeline)

    monkeypatch.setattr(liveness, "get_redis", _get_redis)
    return opened


async def test_live_means_any_prefix_present_per_id(monkeypatch: pytest.MonkeyPatch) -> None:
    # Per-id result matches the old single-key probes: live iff any of the three keys exists.
    pipeline = _FakePipeline(counts=[1, 0, 1], error=None)
    _install_pool(monkeypatch, pipeline)

    live = await arq_active_task_ids(["queued-only", "gone", "retry-only"])

    assert live == frozenset({"queued-only", "retry-only"})
    assert pipeline.exists_calls == [
        (
            f"{ARQ_IN_PROGRESS_PREFIX}queued-only",
            f"{ARQ_JOB_PREFIX}queued-only",
            f"{ARQ_RETRY_PREFIX}queued-only",
        ),
        (
            f"{ARQ_IN_PROGRESS_PREFIX}gone",
            f"{ARQ_JOB_PREFIX}gone",
            f"{ARQ_RETRY_PREFIX}gone",
        ),
        (
            f"{ARQ_IN_PROGRESS_PREFIX}retry-only",
            f"{ARQ_JOB_PREFIX}retry-only",
            f"{ARQ_RETRY_PREFIX}retry-only",
        ),
    ]


async def test_probe_checks_all_three_prefixes_in_one_pipeline(monkeypatch: pytest.MonkeyPatch) -> None:
    pipeline = _FakePipeline(counts=[0, 2, 1], error=None)
    opened = _install_pool(monkeypatch, pipeline)

    active = await arq_active_task_ids(["task-a", "task-b", "task-c"])

    assert active == frozenset({"task-b", "task-c"})
    assert opened == [1]
    assert pipeline.transaction is False
    assert pipeline.exists_calls == [
        (
            f"{ARQ_IN_PROGRESS_PREFIX}task-a",
            f"{ARQ_JOB_PREFIX}task-a",
            f"{ARQ_RETRY_PREFIX}task-a",
        ),
        (
            f"{ARQ_IN_PROGRESS_PREFIX}task-b",
            f"{ARQ_JOB_PREFIX}task-b",
            f"{ARQ_RETRY_PREFIX}task-b",
        ),
        (
            f"{ARQ_IN_PROGRESS_PREFIX}task-c",
            f"{ARQ_JOB_PREFIX}task-c",
            f"{ARQ_RETRY_PREFIX}task-c",
        ),
    ]


async def test_probe_deduplicates_ids_preserving_order(monkeypatch: pytest.MonkeyPatch) -> None:
    pipeline = _FakePipeline(counts=[1, 0], error=None)
    _install_pool(monkeypatch, pipeline)

    active = await arq_active_task_ids(["task-a", "task-b", "task-a"])

    assert active == frozenset({"task-a"})
    assert len(pipeline.exists_calls) == 2


async def test_empty_input_never_touches_redis(monkeypatch: pytest.MonkeyPatch) -> None:
    def _get_redis() -> Any:
        raise AssertionError("empty input must not open a Redis client")

    monkeypatch.setattr(liveness, "get_redis", _get_redis)

    assert await arq_active_task_ids([]) == frozenset()


@pytest.mark.parametrize(
    "error",
    [RedisConnectionError("down"), OSError("socket closed"), TimeoutError("slow")],
)
async def test_probe_failure_returns_unknown(monkeypatch: pytest.MonkeyPatch, error: BaseException) -> None:
    _install_pool(monkeypatch, _FakePipeline(counts=None, error=error))

    assert await arq_active_task_ids(["task-a"]) is None
