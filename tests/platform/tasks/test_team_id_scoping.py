"""#53 -- task team_id inheritance + scoped reads.

Two mechanisms:
1. TaskQueue.submit stamps team_id from the _current_task_team_id ContextVar
   when the caller does not pass one, so a follow-up spawned inside a running
   worker inherits its parent task's team_id. An explicit team_id wins; outside
   any task the ContextVar default (None) leaves the task unscoped.
2. TaskRepository.list_for_user / get_for_user filter by team_id for a
   team-scoped caller; a god-tier admin (team_id=None) sees every team.
"""
from __future__ import annotations

import json
from unittest.mock import AsyncMock

import pytest

from aila.api.auth import AuthContext
from aila.api.constants import MODULE_ID_PLATFORM
from aila.platform.tasks import queue as queue_mod
from aila.platform.tasks.models import TaskRecord, TaskStatus
from aila.platform.tasks.storage import TaskRepository
from aila.platform.uow import UnitOfWork


async def _dummy_task(ctx: dict, **kwargs: object) -> dict:
    return {}


def _make_queue() -> queue_mod.TaskQueue:
    tq = queue_mod.TaskQueue(config_registry=None, module_id=MODULE_ID_PLATFORM)
    # Reach TaskRecord creation without touching real Redis: the URL check
    # passes, defer is zero, and the enqueue is a successful no-op so the
    # record is not rolled back.
    tq._get_redis_url = lambda: "redis://fake:6379/0"  # type: ignore[method-assign]
    tq._compute_investigation_defer = AsyncMock(return_value=0.0)  # type: ignore[method-assign]
    tq._arq_enqueue_async = AsyncMock(return_value=True)  # type: ignore[method-assign]
    return tq


async def _submitted_team_id(handle_id: str) -> str | None:
    async with UnitOfWork() as uow:
        record = await uow.session.get(TaskRecord, handle_id)
    assert record is not None
    return record.team_id


@pytest.mark.usefixtures("test_db")
async def test_submit_inherits_team_id_from_contextvar() -> None:
    tq = _make_queue()
    token = queue_mod._current_task_team_id.set("team-ctx")
    try:
        handle = await tq.submit(
            track="test-a", fn=_dummy_task, kwargs={"n": 1}, user_id="u1",
        )
    finally:
        queue_mod._current_task_team_id.reset(token)
    assert await _submitted_team_id(handle.task_id) == "team-ctx"


@pytest.mark.usefixtures("test_db")
async def test_submit_explicit_team_id_overrides_contextvar() -> None:
    tq = _make_queue()
    token = queue_mod._current_task_team_id.set("team-ctx")
    try:
        handle = await tq.submit(
            track="test-b", fn=_dummy_task, kwargs={"n": 2}, user_id="u1",
            team_id="team-explicit",
        )
    finally:
        queue_mod._current_task_team_id.reset(token)
    assert await _submitted_team_id(handle.task_id) == "team-explicit"


@pytest.mark.usefixtures("test_db")
async def test_submit_outside_task_context_is_unscoped() -> None:
    tq = _make_queue()
    handle = await tq.submit(
        track="test-c", fn=_dummy_task, kwargs={"n": 3}, user_id="u1",
    )
    assert await _submitted_team_id(handle.task_id) is None


async def _seed_task(task_id: str, team_id: str | None, group_id: str = "operator") -> None:
    async with UnitOfWork() as uow:
        uow.session.add(TaskRecord(
            id=task_id,
            track="scan",
            fn_path="aila.platform.x.run",
            fn_module="__platform__",
            status=TaskStatus.RUNNING,
            user_id="u1",
            group_id=group_id,
            team_id=team_id,
            kwargs_json=json.dumps({}),
        ))
        await uow.session.commit()


def _auth(team_id: str | None, role: str = "operator") -> AuthContext:
    return AuthContext(user_id="u1", role=role, auth_type="user", team_id=team_id)


@pytest.mark.usefixtures("test_db")
async def test_list_for_user_team_scoped() -> None:
    await _seed_task("t-a", team_id="team-a")
    await _seed_task("t-b", team_id="team-b")
    async with UnitOfWork() as uow:
        rows = await TaskRepository.list_for_user(uow.session, _auth("team-a"))
    ids = {r.id for r in rows}
    assert "t-a" in ids
    assert "t-b" not in ids


@pytest.mark.usefixtures("test_db")
async def test_list_for_user_god_tier_sees_all() -> None:
    await _seed_task("t-a", team_id="team-a")
    await _seed_task("t-b", team_id="team-b")
    async with UnitOfWork() as uow:
        rows = await TaskRepository.list_for_user(uow.session, _auth(None, role="admin"))
    ids = {r.id for r in rows}
    assert {"t-a", "t-b"} <= ids


@pytest.mark.usefixtures("test_db")
async def test_get_for_user_cross_team_is_none() -> None:
    await _seed_task("t-b", team_id="team-b")
    async with UnitOfWork() as uow:
        row = await TaskRepository.get_for_user(uow.session, "t-b", _auth("team-a"))
    assert row is None


@pytest.mark.usefixtures("test_db")
async def test_get_for_user_god_tier_reads_any_team() -> None:
    await _seed_task("t-b", team_id="team-b")
    async with UnitOfWork() as uow:
        row = await TaskRepository.get_for_user(uow.session, "t-b", _auth(None, role="admin"))
    assert row is not None
