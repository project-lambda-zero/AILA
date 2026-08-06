"""Issue #40-5: ``_enqueue_dependents`` must enqueue dependents by their
fully-qualified registry name (``TaskRecord.fn_path``), not by the bare
``__qualname__``.

Two modules that happen to define ``run_target_analysis`` collide in
ARQ's function map when either side keys on the bare name -- the
dispatcher then routes the right job id to the wrong module's body
(CLAUDE.md #19). ``_Registry.all_functions`` now hands ARQ each function
under its fully-qualified ``{fn.__module__}.{fn.__qualname__}`` name, so
every enqueue site MUST address ARQ by that same qualified key.

These tests patch the ARQ pool so no live Redis is required. They assert
the ARQ enqueue side-effect (call name = full ``fn_path``) alongside the
DB status flip WAITING -> QUEUED that ``_enqueue_dependents`` performs.
"""
from __future__ import annotations

import uuid
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import pytest_asyncio
from sqlmodel import select

from aila.platform.tasks.constants import ARQ_QUEUE_KEY_TEMPLATE
from aila.platform.tasks.hooks import _JobOutcome, _on_job_end, _stash_outcome
from aila.platform.tasks.models import TaskRecord, TaskStatus
from aila.platform.tasks.template import _REGISTRY
from aila.storage.database import async_session_scope


@pytest.fixture(autouse=True)
def _isolate_registry() -> Any:
    snapshot = dict(_REGISTRY._tasks)  # noqa: SLF001
    _REGISTRY.clear()
    try:
        yield
    finally:
        _REGISTRY.clear()
        _REGISTRY._tasks.update(snapshot)  # noqa: SLF001


def _pool_mock() -> MagicMock:
    pool = MagicMock()
    pool.enqueue_job = AsyncMock()
    pool.aclose = AsyncMock()
    return pool


async def _get(tid: str) -> TaskRecord:
    async with async_session_scope() as session:
        rec = (
            await session.exec(select(TaskRecord).where(TaskRecord.id == tid))
        ).first()
    assert rec is not None
    return rec


@pytest_asyncio.fixture
async def parent_and_dep(test_db: None) -> tuple[str, str, str]:  # noqa: ARG001
    """Insert a RUNNING parent and a WAITING dependent whose fn_path is
    the fully-qualified registry key for a hypothetical module task.
    Returns ``(parent_id, dep_id, dep_fn_path)``.
    """
    parent_id = str(uuid.uuid4())
    dep_id = str(uuid.uuid4())
    # A qualified path chosen to expose the historical bug: the trailing
    # segment ``run_target_analysis`` collides with the malware module's
    # own callable name per CLAUDE.md #19. Enqueuing by the bare segment
    # would have shipped this dependent to whichever ``run_target_analysis``
    # ARQ resolved last; the qualified path pins it to this module.
    dep_fn_path = "aila.modules.vulnerability.tasks.run_target_analysis"
    async with async_session_scope() as session:
        session.add(
            TaskRecord(
                id=parent_id,
                track="vulnerability",
                fn_path="aila.modules.vulnerability.tasks.parent_scan",
                fn_module="vulnerability",
                status=TaskStatus.RUNNING,
                user_id="u",
                group_id="operator",
                kwargs_json="{}",
            ),
        )
        session.add(
            TaskRecord(
                id=dep_id,
                track="vulnerability",
                fn_path=dep_fn_path,
                fn_module="vulnerability",
                status=TaskStatus.WAITING,
                user_id="u",
                group_id="operator",
                kwargs_json='{"target": "example"}',
                depends_on_json=f'["{parent_id}"]',
            ),
        )
        await session.commit()
    return parent_id, dep_id, dep_fn_path


@pytest.mark.asyncio
async def test_enqueue_dependents_uses_qualified_fn_path(
    parent_and_dep: tuple[str, str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The dependent's ARQ enqueue argument is the full ``fn_path``,
    not the trailing bare segment.

    Historical bug (#40-5): ``_enqueue_dependents`` did
    ``fn_short = rec.fn_path.rsplit(".", 1)[-1]`` and enqueued by that
    bare name. ARQ's function map is now keyed on the fully-qualified
    registry name -- the bare form would miss on any bare-name
    collision across modules (CLAUDE.md #19) and route the dependent
    to whichever module ARQ imported last.
    """
    parent_id, dep_id, dep_fn_path = parent_and_dep

    monkeypatch.setenv("AILA_PLATFORM_REDIS_URL", "redis://127.0.0.1:6379/15")

    pool = _pool_mock()
    with patch(
        "aila.platform.tasks.hooks._create_pool",
        new=AsyncMock(return_value=pool),
    ):
        _stash_outcome(parent_id, 1, _JobOutcome(kind="success", result={}))
        await _on_job_end({"job_id": parent_id, "job_try": 1})

    # DB side-effect: dependent promoted WAITING -> QUEUED.
    dep = await _get(dep_id)
    assert dep.status == TaskStatus.QUEUED

    # ARQ side-effect: enqueue call issued with the fully-qualified
    # ``fn_path`` and the dep's job id / queue key / kwargs.
    pool.enqueue_job.assert_awaited_once()
    call = pool.enqueue_job.await_args
    assert call.args == (dep_fn_path,), (
        "_enqueue_dependents must pass the fully-qualified fn_path so ARQ's "
        "qualified-name registry resolves to the right module (CLAUDE.md #19)."
    )
    assert call.kwargs["_queue_name"] == ARQ_QUEUE_KEY_TEMPLATE.format(
        track="vulnerability",
    )
    assert call.kwargs["_job_id"] == dep_id
    assert call.kwargs["target"] == "example"
    pool.aclose.assert_awaited()


@pytest.mark.asyncio
async def test_enqueue_dependents_skips_row_without_fn_path(
    test_db: None,  # noqa: ARG001
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A dependent row whose ``fn_path`` is empty is skipped with a
    warning; the row stays QUEUED but no enqueue is attempted (there is
    no callable to address). Prior to #40-5 the branch relied on the
    bare short-name derived from ``fn_path``, so an empty path silently
    passed the ``not fn_short`` guard for the wrong reason. The
    qualified-name branch checks ``fn_path`` directly."""
    parent_id = str(uuid.uuid4())
    dep_id = str(uuid.uuid4())
    async with async_session_scope() as session:
        session.add(
            TaskRecord(
                id=parent_id,
                track="vulnerability",
                fn_path="aila.modules.x.parent",
                fn_module="x",
                status=TaskStatus.RUNNING,
                user_id="u",
                group_id="operator",
                kwargs_json="{}",
            ),
        )
        session.add(
            TaskRecord(
                id=dep_id,
                track="vulnerability",
                fn_path="",
                fn_module="x",
                status=TaskStatus.WAITING,
                user_id="u",
                group_id="operator",
                kwargs_json="{}",
                depends_on_json=f'["{parent_id}"]',
            ),
        )
        await session.commit()

    monkeypatch.setenv("AILA_PLATFORM_REDIS_URL", "redis://127.0.0.1:6379/15")

    pool = _pool_mock()
    with patch(
        "aila.platform.tasks.hooks._create_pool",
        new=AsyncMock(return_value=pool),
    ):
        _stash_outcome(parent_id, 1, _JobOutcome(kind="success", result={}))
        await _on_job_end({"job_id": parent_id, "job_try": 1})

    # No enqueue attempt for the empty-path row.
    pool.enqueue_job.assert_not_awaited()
    # The DB row is still promoted (unchanged from prior behavior; the
    # orphan-queued reaper will surface it as a real problem).
    dep = await _get(dep_id)
    assert dep.status == TaskStatus.QUEUED
