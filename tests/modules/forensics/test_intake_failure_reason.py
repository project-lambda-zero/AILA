"""Intake records why a project failed and clears that reason on success.

The SSH service is replaced with a fake: the listing command either raises a
transport error or returns a one-file listing. Runs against the test database.
"""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, patch
from uuid import uuid4

import pytest

from aila.modules.forensics.contracts.status import ProjectStatus
from aila.modules.forensics.db_models import ForensicsProjectRecord
from aila.modules.forensics.workflow.states.intake import state_intake
from aila.platform.exceptions import UpstreamError
from aila.storage.database import async_session_scope

pytestmark = pytest.mark.usefixtures("test_db")


class _Emitter:
    async def emit(self, stage: str, message: str, meta: dict[str, Any]) -> None:
        return None


def _services() -> SimpleNamespace:
    return SimpleNamespace(
        emitter=_Emitter(),
        settings=None,
        evidence_directory="/evidence",
        integration={"id": 1, "host": "analyzer.invalid"},
        run_id=f"run-423-{uuid4().hex[:8]}",
    )


async def _seed(project_id: str, failure_reason: str | None = None) -> None:
    async with async_session_scope() as session:
        session.add(ForensicsProjectRecord(
            id=project_id,
            name=project_id,
            system_id=0,
            evidence_directory="/evidence",
            status=ProjectStatus.CREATED.value,
            failure_reason=failure_reason,
        ))
        await session.commit()


async def _read(project_id: str) -> ForensicsProjectRecord:
    async with async_session_scope() as session:
        project = await session.get(ForensicsProjectRecord, project_id)
    assert project is not None
    return project


async def test_failed_intake_persists_status_and_reason() -> None:
    project_id = f"proj-423-{uuid4().hex[:8]}"
    await _seed(project_id)
    ssh = AsyncMock()
    ssh.run_command.side_effect = UpstreamError("analyzer ssh transport down")

    with patch(
        "aila.modules.forensics.tools._ssh_helper.get_ssh_service",
        new=AsyncMock(return_value=ssh),
    ), pytest.raises(UpstreamError):
        await state_intake({"project_id": project_id, "analyzer_os": "linux"}, _services())

    project = await _read(project_id)
    assert project.status == ProjectStatus.FAILED.value
    assert project.failure_reason
    assert "UpstreamError" in project.failure_reason


async def test_successful_intake_clears_stale_failure_reason() -> None:
    project_id = f"proj-423-{uuid4().hex[:8]}"
    await _seed(project_id, failure_reason="old")
    ssh = AsyncMock()
    ssh.run_command.return_value = "1048576 /evidence/webserver01_root.img\n"

    with patch(
        "aila.modules.forensics.tools._ssh_helper.get_ssh_service",
        new=AsyncMock(return_value=ssh),
    ):
        await state_intake({"project_id": project_id, "analyzer_os": "linux"}, _services())

    project = await _read(project_id)
    assert project.status != ProjectStatus.FAILED.value
    assert project.failure_reason is None
