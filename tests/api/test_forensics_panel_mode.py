"""Panel mode selects the real panel task at the investigation start route."""
from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from uuid import uuid4

import pytest

from aila.api import deps as api_deps
from aila.api.auth import AuthContext
from aila.modules.forensics.api_router import create_forensics_router
from aila.modules.forensics.api_router import limiter as forensics_limiter
from aila.modules.forensics.contracts.investigation import InvestigationRequest
from aila.modules.forensics.db_models import ForensicsProjectRecord, InvestigationRunRecord
from aila.modules.forensics.workflow.panel.task import run_forensics_panel_investigate
from aila.storage.database import async_session_scope
from aila.storage.db_models import ManagedSystemRecord


@pytest.fixture(autouse=True)
def _disable_limiter():
    previous = forensics_limiter.enabled
    forensics_limiter.enabled = False
    yield
    forensics_limiter.enabled = previous


class _Queue:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def submit(self, **kwargs: Any) -> SimpleNamespace:
        self.calls.append(kwargs)
        return SimpleNamespace(task_id="panel-task-1")


def _endpoint():
    for route in create_forensics_router().routes:
        if (
            getattr(route, "path", None) == "/projects/{project_id}/investigate"
            and "POST" in (getattr(route, "methods", set()) or set())
        ):
            return route.endpoint
    raise AssertionError("investigation start route not registered")


async def test_panel_mode_enqueues_panel_graph_with_team_scope(
    test_db, monkeypatch: pytest.MonkeyPatch,
) -> None:
    suffix = uuid4().hex[:8]
    queue = _Queue()
    monkeypatch.setattr(api_deps, "get_task_queue", lambda _track, _request: queue)
    async with async_session_scope() as session:
        system = ManagedSystemRecord(
            name=f"analyzer-{suffix}", host=f"analyzer-{suffix}.test", username="examiner",
        )
        session.add(system)
        await session.flush()
        project = ForensicsProjectRecord(
            name=f"project-{suffix}", system_id=system.id,
            evidence_directory="/evidence", team_id="team-panel",
        )
        session.add(project)
        await session.commit()
        project_id = project.id

    envelope = await _endpoint()(
        request=SimpleNamespace(),
        project_id=project_id,
        body=InvestigationRequest(question="How did it persist?", mode="panel"),
        auth=AuthContext(
            user_id="examiner-user", role="operator", auth_type="user", team_id="team-panel",
        ),
    )

    assert envelope.data.status == "pending"
    assert envelope.data.task_id == "panel-task-1"
    [call] = queue.calls
    assert call["fn"] is run_forensics_panel_investigate
    assert call["kwargs"] == {
        "investigation_id": envelope.data.id,
        "project_id": project_id,
        "question": "How did it persist?",
    }
    assert call["team_id"] == "team-panel"
    async with async_session_scope() as session:
        inv = await session.get(InvestigationRunRecord, envelope.data.id)
        assert inv is not None and inv.team_id == "team-panel"
