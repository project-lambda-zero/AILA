"""One active full-analysis task per forensics project.

The readiness check auto-enqueues full analysis when the analyzer is ready;
the full-analysis route enqueues it on demand. Whichever runs second must
not create a second active task. The real ``TaskQueue`` persists the task
rows against the test database; only the readiness probe and the ARQ
enqueue are replaced.
"""
from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest
from sqlmodel import select

from aila.api.auth import AuthContext
from aila.modules.forensics.api_router import create_forensics_router
from aila.modules.forensics.api_router import limiter as _forensics_limiter
from aila.modules.forensics.db_models import ForensicsProjectRecord
from aila.modules.forensics.workflow.task import run_forensics_analysis
from aila.platform.tasks import queue as queue_mod
from aila.platform.tasks.models import TaskRecord
from aila.platform.tasks.queue import qualified_task_name
from aila.storage.database import async_session_scope
from aila.storage.db_models import ManagedSystemRecord

pytestmark = pytest.mark.usefixtures("test_db")


@pytest.fixture(autouse=True)
def _disable_forensics_limiter():
    prev = _forensics_limiter.enabled
    _forensics_limiter.enabled = False
    yield
    _forensics_limiter.enabled = prev


class _Req:
    """Request stand-in; neither route reads it with the limiter disabled."""


def _endpoint(path: str, method: str):
    for route in create_forensics_router().routes:
        if getattr(route, "path", None) == path and method in (getattr(route, "methods", set()) or set()):
            return route.endpoint
    raise AssertionError(f"route {method} {path} not registered")


def _queue() -> queue_mod.TaskQueue:
    tq = queue_mod.TaskQueue(config_registry=None, module_id="forensics")
    tq._get_redis_url = lambda: "redis://fake:6379/0"  # type: ignore[method-assign]
    tq._drain_requested = AsyncMock(return_value=False)  # type: ignore[method-assign]
    tq._compute_investigation_defer = AsyncMock(return_value=0.0)  # type: ignore[method-assign]
    tq._arq_enqueue_async = AsyncMock(return_value=True)  # type: ignore[method-assign]
    return tq


async def _seed_project() -> str:
    suffix = uuid4().hex[:8]
    async with async_session_scope() as session:
        system = ManagedSystemRecord(name=f"sys-{suffix}", host="10.0.0.1", username="u")
        session.add(system)
        await session.flush()
        project = ForensicsProjectRecord(
            name=f"proj-{suffix}", system_id=system.id, evidence_directory=f"/evidence/{suffix}",
        )
        session.add(project)
        await session.commit()
        return project.id


async def _active_tasks(project_id: str) -> list[str]:
    async with async_session_scope() as session:
        rows = (await session.exec(
            select(TaskRecord).where(
                TaskRecord.fn_path == qualified_task_name(run_forensics_analysis),
                TaskRecord.status.in_(["queued", "running", "waiting"]),  # type: ignore[union-attr]
            )
        )).all()
    return [row.id for row in rows if f'"project_id": "{project_id}"' in (row.kwargs_json or "")]


async def _readiness(project_id: str, auth: AuthContext) -> None:
    with patch(
        "aila.modules.forensics.services.machine_readiness.MachineReadinessService.check_readiness",
        new=AsyncMock(return_value=MagicMock(ready=True)),
    ):
        await _endpoint("/projects/{project_id}/readiness-check", "POST")(_Req(), project_id, auth=auth)


async def _trigger(project_id: str, auth: AuthContext) -> dict[str, str]:
    envelope = await _endpoint("/projects/{project_id}/full-analysis", "POST")(
        request=_Req(), project_id=project_id, auth=auth,
    )
    return envelope.data


@pytest.mark.parametrize("order", ["readiness_then_trigger", "trigger_then_readiness"])
async def test_readiness_and_trigger_leave_one_active_full_analysis(order: str) -> None:
    project_id = await _seed_project()
    auth = AuthContext(user_id="admin", role="admin", auth_type="user", team_id=None)

    with patch("aila.api.deps.get_task_queue", return_value=_queue()):
        if order == "readiness_then_trigger":
            await _readiness(project_id, auth)
            response = await _trigger(project_id, auth)
        else:
            response = await _trigger(project_id, auth)
            await _readiness(project_id, auth)

    active = await _active_tasks(project_id)
    assert len(active) == 1
    assert response["task_id"] == active[0]
