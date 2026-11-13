"""#420 forensics live events: status writes on forensics rows reach SSE.

Uses the real forensics record classes on an in-memory SQLite engine (no
Redis, no shared test database):

* a committed ``status`` write on a forensics investigation or project row
  publishes exactly one ``EntityStatusChanged`` tagged ``forensics``;
* the same write, delivered over the real domain event bus and forwarder,
  reaches the owning team's SSE queue as ``investigation.status_changed`` or
  ``project.status_changed`` with the status transition in ``data``.
"""
from __future__ import annotations

import asyncio
import json
import uuid
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.pool import StaticPool
from sqlmodel import Session, SQLModel

from aila.api import events
from aila.modules.forensics.db_models.investigation import InvestigationRunRecord
from aila.modules.forensics.db_models.project import ForensicsProjectRecord
from aila.platform.events import entity_status


@pytest.fixture
def forensics_engine():
    # StaticPool: the end-to-end tests write from a worker thread and read the
    # same in-memory database back, so every thread must share one connection.
    engine = create_engine(
        "sqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    SQLModel.metadata.create_all(
        engine,
        tables=[
            SQLModel.metadata.tables["forensics_projects"],
            SQLModel.metadata.tables["forensics_investigations"],
        ],
    )
    yield engine
    engine.dispose()


@pytest.fixture
def captured_publishes():
    published: list = []
    with patch.object(entity_status, "publish", published.append):
        yield published


def _project(project_id: str, team_id: str) -> ForensicsProjectRecord:
    return ForensicsProjectRecord(
        id=project_id,
        name="case",
        system_id=1,
        evidence_directory="/evidence",
        team_id=team_id,
    )


def _run(run_id: str, team_id: str) -> InvestigationRunRecord:
    return InvestigationRunRecord(
        id=run_id,
        project_id="proj",
        team_id=team_id,
        question="what happened",
        status="pending",
    )


def _set_status(
    session: Session,
    model: type[ForensicsProjectRecord] | type[InvestigationRunRecord],
    row_id: str,
    status: str,
) -> None:
    row = session.get(model, row_id)
    assert row is not None
    row.status = status
    session.commit()


# ---------------------------------------------------------------------------
# Forensics status writes -> EntityStatusChanged
# ---------------------------------------------------------------------------


def test_committed_forensics_project_status_publishes_entity_event(
    forensics_engine, captured_publishes
) -> None:
    project_id = f"proj-{uuid.uuid4()}"
    team_id = f"team-{uuid.uuid4()}"
    with Session(forensics_engine) as session:
        session.add(_project(project_id, team_id))
        session.commit()
        _set_status(session, ForensicsProjectRecord, project_id, "analyzing")

    assert [(e.payload.previous_status, e.payload.status) for e in captured_publishes] == [
        (None, "created"),
        ("created", "analyzing"),
    ]
    last = captured_publishes[-1]
    assert last.team_id == team_id
    assert last.source_module == "forensics"
    assert last.payload.module_id == "forensics"
    assert last.payload.entity_kind == "project"
    assert last.payload.entity_id == project_id


def test_committed_forensics_investigation_status_publishes_entity_event(
    forensics_engine, captured_publishes
) -> None:
    run_id = f"run-{uuid.uuid4()}"
    team_id = f"team-{uuid.uuid4()}"
    with Session(forensics_engine) as session:
        session.add(_run(run_id, team_id))
        session.commit()
        _set_status(session, InvestigationRunRecord, run_id, "running")

    assert [(e.payload.previous_status, e.payload.status) for e in captured_publishes] == [
        (None, "pending"),
        ("pending", "running"),
    ]
    last = captured_publishes[-1]
    assert last.team_id == team_id
    assert last.source_module == "forensics"
    assert last.payload.entity_kind == "investigation"
    assert last.payload.entity_id == run_id


# ---------------------------------------------------------------------------
# Domain bus -> forwarder -> SSE queue (real bus, real forwarder)
# ---------------------------------------------------------------------------


@pytest.fixture
async def forensics_stream(monkeypatch):
    user_id = f"user-{uuid.uuid4()}"
    seen_scopes: list[str | None] = []

    async def _recipients(scope: str | None) -> list[str]:
        seen_scopes.append(scope)
        return [user_id]

    monkeypatch.setattr(events, "investigation_status_recipients", _recipients)
    queue = await events.subscribe_user(user_id)
    events.install_investigation_status_forwarder()
    yield SimpleNamespace(queue=queue, seen_scopes=seen_scopes)
    events.uninstall_investigation_status_forwarder()
    await events.unsubscribe_user(user_id, queue)


async def test_forensics_project_status_change_reaches_sse_queue(
    forensics_engine, forensics_stream
) -> None:
    project_id = f"proj-{uuid.uuid4()}"
    team_id = f"team-{uuid.uuid4()}"

    def _write() -> None:
        with Session(forensics_engine) as session:
            session.add(_project(project_id, team_id))
            session.commit()
        with Session(forensics_engine) as session:
            _set_status(session, ForensicsProjectRecord, project_id, "analyzing")

    # Writers run on worker threads; delivery must still land on the API loop.
    await asyncio.to_thread(_write)

    frames = [
        json.loads(await asyncio.wait_for(forensics_stream.queue.get(), timeout=2)) for _ in range(2)
    ]
    assert [f["type"] for f in frames] == ["project.status_changed", "project.status_changed"]
    assert [f["data"] for f in frames] == [
        {"module": "forensics", "project_id": project_id, "status": "created", "previous_status": None},
        {"module": "forensics", "project_id": project_id, "status": "analyzing", "previous_status": "created"},
    ]
    assert forensics_stream.seen_scopes == [team_id, team_id]


async def test_forensics_investigation_status_change_reaches_sse_queue(
    forensics_engine, forensics_stream
) -> None:
    run_id = f"run-{uuid.uuid4()}"
    team_id = f"team-{uuid.uuid4()}"

    def _write() -> None:
        with Session(forensics_engine) as session:
            session.add(_run(run_id, team_id))
            session.commit()
        with Session(forensics_engine) as session:
            _set_status(session, InvestigationRunRecord, run_id, "running")

    await asyncio.to_thread(_write)

    frames = [
        json.loads(await asyncio.wait_for(forensics_stream.queue.get(), timeout=2)) for _ in range(2)
    ]
    assert [f["type"] for f in frames] == ["investigation.status_changed", "investigation.status_changed"]
    assert frames[-1]["data"] == {
        "module": "forensics",
        "investigation_id": run_id,
        "status": "running",
        "previous_status": "pending",
    }
    assert forensics_stream.seen_scopes == [team_id, team_id]
