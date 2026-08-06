"""#36 -- record_audit_event stamps the acting team on the audit row.

The audit read (GET /audit) filters AuditEventRecord by team_id, but the write
path never stamped it, so team-scoped users saw an empty audit trail. Request
handlers now pass team_id; worker/workflow callers inherit it from the
task-engine context var; pre-auth events stay team-less.
"""
from __future__ import annotations

import pytest
from sqlmodel import select

from aila.platform.services.audit import record_audit_event
from aila.platform.tasks import queue as queue_mod
from aila.storage.database import async_session_scope
from aila.storage.db_models import AuditEventRecord


async def _read_team(run_id: str) -> tuple[bool, str | None]:
    async with async_session_scope() as session:
        rec = (
            await session.exec(
                select(AuditEventRecord).where(AuditEventRecord.run_id == run_id)
            )
        ).first()
    return (rec is not None, rec.team_id if rec is not None else None)


@pytest.mark.usefixtures("test_db")
async def test_audit_event_explicit_team_id() -> None:
    async with async_session_scope() as session:
        record_audit_event(session, run_id="audit-r1", stage="s", action="a", team_id="team-x")
        await session.commit()
    found, team = await _read_team("audit-r1")
    assert found
    assert team == "team-x"


@pytest.mark.usefixtures("test_db")
async def test_audit_event_falls_back_to_context_var() -> None:
    token = queue_mod._current_task_team_id.set("team-ctx")
    try:
        async with async_session_scope() as session:
            record_audit_event(session, run_id="audit-r2", stage="s", action="a")
            await session.commit()
    finally:
        queue_mod._current_task_team_id.reset(token)
    found, team = await _read_team("audit-r2")
    assert found
    assert team == "team-ctx", "worker/workflow callers inherit the task team"


@pytest.mark.usefixtures("test_db")
async def test_audit_event_team_less_without_team() -> None:
    async with async_session_scope() as session:
        record_audit_event(session, run_id="audit-r3", stage="s", action="a")
        await session.commit()
    found, team = await _read_team("audit-r3")
    assert found
    assert team is None, "a pre-auth / god-tier event stays team-less"
