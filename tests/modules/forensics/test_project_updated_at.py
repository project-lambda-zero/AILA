"""A forensics project status write advances ``updated_at``.

Runs against the test database: the project row is seeded with both
timestamps in the past, then the intake state's status writer runs.
"""
from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest

from aila.modules.forensics.contracts.status import ProjectStatus
from aila.modules.forensics.db_models import ForensicsProjectRecord
from aila.modules.forensics.workflow.states.intake import _set_project_status
from aila.platform.contracts import utc_now
from aila.storage.database import async_session_scope

pytestmark = pytest.mark.usefixtures("test_db")


async def test_status_write_advances_updated_at() -> None:
    project_id = f"proj-{uuid4().hex[:8]}"
    seeded_at = utc_now() - timedelta(hours=1)
    async with async_session_scope() as session:
        session.add(ForensicsProjectRecord(
            id=project_id, name=project_id, system_id=0, evidence_directory="/evidence",
            created_at=seeded_at, updated_at=seeded_at,
        ))
        await session.commit()

    await _set_project_status(project_id, ProjectStatus.ANALYZING)

    async with async_session_scope() as session:
        project = await session.get(ForensicsProjectRecord, project_id)
    assert project is not None
    assert project.status == ProjectStatus.ANALYZING.value
    assert project.created_at == seeded_at
    assert project.updated_at > project.created_at
