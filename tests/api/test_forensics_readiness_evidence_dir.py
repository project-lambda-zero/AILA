"""Readiness requires a readable evidence directory (#447).

The readiness endpoint submits the ``run_forensics_readiness`` task; the
worker runs ``MachineReadinessService`` against the test database. The
analyzer SSH session is a fake that fails any command naming the evidence
directory when the directory is "missing"; the tool list is empty so only the
evidence probe decides readiness. The real ``TaskQueue`` persists task rows;
only the ARQ enqueue is replaced.
"""
from __future__ import annotations

import json
from typing import Any
from unittest.mock import ANY, AsyncMock, patch
from uuid import uuid4

import pytest
from fastapi.routing import APIRoute
from sqlmodel import select

from aila.api.auth import AuthContext
from aila.api.schemas.tasks import TaskActionResponse
from aila.modules.forensics.api_router import create_forensics_router
from aila.modules.forensics.api_router import limiter as _forensics_limiter
from aila.modules.forensics.db_models import ForensicsProjectRecord
from aila.modules.forensics.services.machine_readiness import MachineReadinessService
from aila.modules.forensics.workflow.task import (
    run_forensics_analysis,
    run_forensics_readiness,
)
from aila.platform.exceptions import UpstreamError
from aila.platform.tasks import queue as queue_mod
from aila.platform.tasks.context import TaskContext
from aila.platform.tasks.models import TaskRecord
from aila.platform.tasks.queue import qualified_task_name
from aila.storage.database import async_session_scope
from aila.storage.db_models import ManagedSystemRecord

pytestmark = pytest.mark.usefixtures("test_db")

_AUTH = AuthContext(user_id="admin", role="admin", auth_type="user", team_id=None)


@pytest.fixture(autouse=True)
def _disable_forensics_limiter():
    prev = _forensics_limiter.enabled
    _forensics_limiter.enabled = False
    yield
    _forensics_limiter.enabled = prev


class _Req:
    """Request stand-in; the route does not read it with the limiter disabled."""


class _AnalyzerSsh:
    def __init__(self, evidence_directory: str, present: bool) -> None:
        self.evidence_directory = evidence_directory
        self.present = present
        self.evidence_probes = 0

    async def run_command(self, _integration: dict[str, Any], command: str, **_: Any) -> str:
        if self.evidence_directory in command:
            self.evidence_probes += 1
            if not self.present:
                raise UpstreamError("command exited 1")
        return ""


def _queue() -> queue_mod.TaskQueue:
    tq = queue_mod.TaskQueue(config_registry=None, module_id="forensics")
    tq._get_redis_url = lambda: "redis://fake:6379/0"  # type: ignore[method-assign]
    tq._drain_requested = AsyncMock(return_value=False)  # type: ignore[method-assign]
    tq._compute_investigation_defer = AsyncMock(return_value=0.0)  # type: ignore[method-assign]
    tq._arq_enqueue_async = AsyncMock(return_value=True)  # type: ignore[method-assign]
    return tq


def _route(path: str, method: str) -> APIRoute:
    for route in create_forensics_router().routes:
        if isinstance(route, APIRoute) and route.path == path and method in route.methods:
            return route
    raise AssertionError(f"route {method} {path} not registered")


async def _seed_project(analyzer_os: str, project_kind: str) -> ForensicsProjectRecord:
    suffix = uuid4().hex[:8]
    async with async_session_scope() as session:
        system = ManagedSystemRecord(name=f"sys-{suffix}", host="10.0.0.1", username="u")
        session.add(system)
        await session.flush()
        assert system.id is not None
        project = ForensicsProjectRecord(
            name=f"proj-{suffix}", system_id=system.id, evidence_directory=f"/evidence/{suffix}",
            analyzer_os=analyzer_os, project_kind=project_kind,
        )
        session.add(project)
        await session.commit()
        await session.refresh(project)
        return project


async def _seed_readiness_task(project_id: str) -> str:
    """Persist the readiness TaskRecord the worker reads ``group_id`` from."""
    task_id = str(uuid4())
    async with async_session_scope() as session:
        session.add(TaskRecord(
            id=task_id,
            track="forensics_readiness",
            fn_path=qualified_task_name(run_forensics_readiness),
            fn_module="forensics",
            status="running",
            user_id="admin",
            group_id="admin",
            team_id=None,
            kwargs_json=json.dumps({"project_id": project_id}),
        ))
        await session.commit()
    return task_id


async def _project_status(project_id: str) -> str:
    async with async_session_scope() as session:
        project = await session.get(ForensicsProjectRecord, project_id)
    assert project is not None
    return project.status


async def _active_tasks(project_id: str) -> list[str]:
    async with async_session_scope() as session:
        rows = (await session.exec(
            select(TaskRecord).where(
                TaskRecord.fn_path == qualified_task_name(run_forensics_analysis),
                TaskRecord.status.in_(["queued", "running", "waiting"]),  # type: ignore[union-attr]
            )
        )).all()
    return [row.id for row in rows if f'"project_id": "{project_id}"' in (row.kwargs_json or "")]


async def _run_readiness_worker(
    project: ForensicsProjectRecord, present: bool,
) -> tuple[dict[str, Any], _AnalyzerSsh, AsyncMock]:
    ssh = _AnalyzerSsh(project.evidence_directory, present)
    task_id = await _seed_readiness_task(project.id)
    store = AsyncMock()
    with (
        patch("aila.modules.forensics.tools._ssh_helper.get_ssh_service", AsyncMock(return_value=ssh)),
        patch("aila.modules.forensics.services.machine_readiness._load_tool_requirements", return_value={}),
        patch("aila.modules.forensics.workflow.task.default_task_queue", return_value=_queue()),
        patch("aila.modules.forensics.workflow.task.store_task_json_result", store),
    ):
        ctx = TaskContext(task_id=task_id, job_try=1, user_id="admin", team_id=None)
        payload = await run_forensics_readiness.__wrapped__(ctx, project_id=project.id)
    return payload, ssh, store


_KINDS = [("linux", "disk_evidence"), ("windows", "disk_evidence"), ("linux", "raw_directory")]


@pytest.mark.parametrize(("analyzer_os", "project_kind"), _KINDS)
async def test_missing_evidence_directory_is_not_ready_and_enqueues_nothing(
    analyzer_os: str, project_kind: str,
) -> None:
    project = await _seed_project(analyzer_os, project_kind)

    payload, ssh, store = await _run_readiness_worker(project, present=False)

    assert ssh.evidence_probes == 1
    assert payload["ready"] is False
    assert project.evidence_directory in payload["message"]
    store.assert_awaited_once_with(task_id=ANY, module_id="forensics", payload=payload, team_id=None)
    assert await _project_status(project.id) == "created"
    assert await _active_tasks(project.id) == []


@pytest.mark.parametrize(("analyzer_os", "project_kind"), _KINDS)
async def test_readable_evidence_directory_is_ready_and_enqueues_analysis(
    analyzer_os: str, project_kind: str,
) -> None:
    project = await _seed_project(analyzer_os, project_kind)

    payload, ssh, store = await _run_readiness_worker(project, present=True)

    assert ssh.evidence_probes == 1
    assert payload["ready"] is True
    store.assert_awaited_once_with(task_id=ANY, module_id="forensics", payload=payload, team_id=None)
    assert await _project_status(project.id) == "ready"
    assert len(await _active_tasks(project.id)) == 1


async def test_readiness_endpoint_queues_worker_task_without_inline_probe() -> None:
    project = await _seed_project("linux", "disk_evidence")
    route = _route("/projects/{project_id}/readiness-check", "POST")
    inline_check = AsyncMock()

    with (
        patch.object(MachineReadinessService, "check_readiness", inline_check),
        patch("aila.api.deps.get_task_queue", return_value=_queue()),
    ):
        response = await route.endpoint(_Req(), project.id, auth=_AUTH)

    assert route.status_code == 202
    assert isinstance(response, TaskActionResponse)
    assert response.status == "queued"
    inline_check.assert_not_awaited()
    async with async_session_scope() as session:
        rows = (await session.exec(
            select(TaskRecord).where(
                TaskRecord.fn_path == qualified_task_name(run_forensics_readiness),
            )
        )).all()
    matching = [row for row in rows if f'"project_id": "{project.id}"' in (row.kwargs_json or "")]
    assert [row.id for row in matching] == [response.task_id]
    assert matching[0].track == "forensics_readiness"
    assert await _project_status(project.id) == "created"
