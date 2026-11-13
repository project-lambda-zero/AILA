"""Readiness requires a readable evidence directory (#447).

Drives the real readiness route and ``MachineReadinessService`` against the
test database. The analyzer SSH session is a fake that fails any command
naming the evidence directory when the directory is "missing"; the tool list
is empty so only the evidence probe decides readiness. The real
``TaskQueue`` persists task rows; only the ARQ enqueue is replaced.
"""
from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest
from fastapi.routing import APIRoute
from sqlmodel import select

from aila.api.auth import AuthContext
from aila.modules.forensics.api_router import create_forensics_router
from aila.modules.forensics.api_router import limiter as _forensics_limiter
from aila.modules.forensics.db_models import ForensicsProjectRecord
from aila.modules.forensics.workflow.task import run_forensics_analysis
from aila.platform.exceptions import UpstreamError
from aila.platform.tasks import queue as queue_mod
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
    tq._compute_investigation_defer = AsyncMock(return_value=0.0)  # type: ignore[method-assign]
    tq._arq_enqueue_async = AsyncMock(return_value=True)  # type: ignore[method-assign]
    return tq


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


async def _readiness(project: ForensicsProjectRecord, present: bool) -> tuple[Any, _AnalyzerSsh]:
    ssh = _AnalyzerSsh(project.evidence_directory, present)
    endpoint = next(
        route.endpoint for route in create_forensics_router().routes
        if isinstance(route, APIRoute) and route.path == "/projects/{project_id}/readiness-check"
    )
    with (
        patch("aila.modules.forensics.tools._ssh_helper.get_ssh_service", AsyncMock(return_value=ssh)),
        patch("aila.modules.forensics.services.machine_readiness._load_tool_requirements", return_value={}),
        patch("aila.api.deps.get_task_queue", return_value=_queue()),
    ):
        envelope = await endpoint(_Req(), project.id, auth=_AUTH)
    return envelope.data, ssh


_KINDS = [("linux", "disk_evidence"), ("windows", "disk_evidence"), ("linux", "raw_directory")]


@pytest.mark.parametrize(("analyzer_os", "project_kind"), _KINDS)
async def test_missing_evidence_directory_is_not_ready_and_enqueues_nothing(
    analyzer_os: str, project_kind: str,
) -> None:
    project = await _seed_project(analyzer_os, project_kind)

    result, ssh = await _readiness(project, present=False)

    assert ssh.evidence_probes == 1
    assert result.ready is False
    assert project.evidence_directory in result.message
    assert await _project_status(project.id) == "created"
    assert await _active_tasks(project.id) == []


@pytest.mark.parametrize(("analyzer_os", "project_kind"), _KINDS)
async def test_readable_evidence_directory_is_ready_and_enqueues_analysis(
    analyzer_os: str, project_kind: str,
) -> None:
    project = await _seed_project(analyzer_os, project_kind)

    result, ssh = await _readiness(project, present=True)

    assert ssh.evidence_probes == 1
    assert result.ready is True
    assert await _project_status(project.id) == "ready"
    assert len(await _active_tasks(project.id)) == 1
