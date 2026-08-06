"""#36 -- the system_registry agent tool stamps the calling team on insert.

The REST create path (systems.py) already stamps team_id=auth.team_id, but the
agent-tool registration path built ManagedSystemRecord without a team, so a
system an agent registered on a team's behalf was invisible to that team's
scoped reads. The tool now stamps the team from the task-engine context var.
"""
from __future__ import annotations

from uuid import uuid4

import pytest
from sqlmodel import select

from aila.config import get_settings
from aila.platform.tasks import queue as queue_mod
from aila.platform.tools.registry import SystemRegistryTool
from aila.storage.database import async_session_scope
from aila.storage.db_models import ManagedSystemRecord


@pytest.mark.usefixtures("test_db")
async def test_registry_tool_stamps_team_from_contextvar() -> None:
    tool = SystemRegistryTool(get_settings())
    name = f"agent-sys-{uuid4().hex[:6]}"
    token = queue_mod._current_task_team_id.set("team-tool")
    try:
        await tool.forward(
            action="upsert",
            integration={"name": name, "host": "10.9.9.9", "username": "u"},
        )
    finally:
        queue_mod._current_task_team_id.reset(token)

    async with async_session_scope() as session:
        rec = (
            await session.exec(
                select(ManagedSystemRecord).where(ManagedSystemRecord.name == name)
            )
        ).first()
    assert rec is not None
    assert rec.team_id == "team-tool"


@pytest.mark.usefixtures("test_db")
async def test_registry_tool_unscoped_outside_task() -> None:
    tool = SystemRegistryTool(get_settings())
    name = f"boot-sys-{uuid4().hex[:6]}"
    await tool.forward(
        action="upsert",
        integration={"name": name, "host": "10.9.9.8", "username": "u"},
    )
    async with async_session_scope() as session:
        rec = (
            await session.exec(
                select(ManagedSystemRecord).where(ManagedSystemRecord.name == name)
            )
        ).first()
    assert rec is not None
    assert rec.team_id is None
