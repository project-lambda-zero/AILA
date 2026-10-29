"""#145 live events: investigation status push + resumable progress SSE.

Function-level tests with fakes (no Redis, no shared test database):

* a committed ``status`` write on a tracked ORM class publishes exactly one
  ``EntityStatusChanged`` carrying previous/new status and the team scope;
  rollbacks and no-op writes publish nothing;
* the API-side forwarder turns that domain event into an
  ``investigation.status_changed`` SSE payload for every recipient, including
  when the bus delivers it on a non-loop (worker) thread;
* task progress SSE frames carry ``id:`` lines and a reconnect with
  ``last_id`` replays only what came after it, with no duplicate between the
  catchup replay and the live read.
"""
from __future__ import annotations

import asyncio
import json
import uuid
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from aila.api import events
from aila.api.routers import tasks as tasks_router
from aila.platform.events import entity_status
from aila.platform.events.domain_events import EntityStatusChanged, EntityStatusChangedPayload

# ---------------------------------------------------------------------------
# ORM status tracking -> EntityStatusChanged
# ---------------------------------------------------------------------------


class _Base(DeclarativeBase):
    pass


class _TrackedRow(_Base):
    __tablename__ = "test_live_events_145_rows"

    id: Mapped[str] = mapped_column(primary_key=True)
    status: Mapped[str]
    team_id: Mapped[str | None]


@pytest.fixture
def tracked_session():
    entity_status.track_status_changes(_TrackedRow, module_id="vr", entity_kind="investigation")
    engine = create_engine("sqlite://")
    _Base.metadata.create_all(engine)
    published: list[EntityStatusChanged] = []
    with patch.object(entity_status, "publish", published.append), Session(engine) as session:
        yield session, published
    entity_status._TRACKED.pop(_TrackedRow, None)
    engine.dispose()


def test_committed_status_change_publishes_entity_event(tracked_session) -> None:
    session, published = tracked_session
    row_id = f"inv-{uuid.uuid4()}"
    team_id = f"team-{uuid.uuid4()}"

    session.add(_TrackedRow(id=row_id, status="created", team_id=team_id))
    session.commit()
    row = session.get(_TrackedRow, row_id)
    row.status = "running"
    session.commit()

    assert [(e.payload.previous_status, e.payload.status) for e in published] == [
        (None, "created"),
        ("created", "running"),
    ]
    last = published[-1]
    assert last.team_id == team_id
    assert last.source_module == "vr"
    assert last.payload.module_id == "vr"
    assert last.payload.entity_kind == "investigation"
    assert last.payload.entity_id == row_id


def test_rollback_and_unchanged_status_publish_nothing(tracked_session) -> None:
    session, published = tracked_session
    row_id = f"inv-{uuid.uuid4()}"
    session.add(_TrackedRow(id=row_id, status="running", team_id=None))
    session.commit()
    published.clear()

    row = session.get(_TrackedRow, row_id)
    row.status = "completed"
    session.flush()
    session.rollback()
    assert published == []

    row = session.get(_TrackedRow, row_id)
    row.status = "running"  # same value: not a transition
    session.commit()
    assert published == []


# ---------------------------------------------------------------------------
# EntityStatusChanged -> investigation.status_changed on /events/stream
# ---------------------------------------------------------------------------


def _status_event(team_id: str, entity_kind: str = "investigation") -> EntityStatusChanged:
    return EntityStatusChanged(
        team_id=team_id,
        source_module="malware",
        payload=EntityStatusChangedPayload(
            module_id="malware",
            entity_kind=entity_kind,
            entity_id=f"inv-{uuid.uuid4()}",
            previous_status="running",
            status="completed",
        ),
    )


@pytest.fixture
async def forwarder(monkeypatch):
    user_id = f"user-{uuid.uuid4()}"
    team_id = f"team-{uuid.uuid4()}"
    seen_teams: list[str | None] = []

    async def _recipients(scope: str | None) -> list[str]:
        seen_teams.append(scope)
        return [user_id]

    monkeypatch.setattr(events, "investigation_status_recipients", _recipients)
    monkeypatch.setattr(events, "bus_subscribe", lambda _name, _fn: None)
    monkeypatch.setattr(events, "bus_unsubscribe", lambda _fn: None)
    queue = await events.subscribe_user(user_id)
    events.install_investigation_status_forwarder()
    yield SimpleNamespace(queue=queue, team_id=team_id, seen_teams=seen_teams)
    events.uninstall_investigation_status_forwarder()
    await events.unsubscribe_user(user_id, queue)


async def test_forwarder_emits_investigation_status_changed(forwarder) -> None:
    evt = _status_event(forwarder.team_id)
    # Bus subscribers may run on a worker thread; delivery must still land
    # on the API loop that owns the SSE queues.
    await asyncio.to_thread(events._forward_investigation_status, evt)

    frame = json.loads(await asyncio.wait_for(forwarder.queue.get(), timeout=2))
    assert frame["type"] == events.INVESTIGATION_STATUS_CHANGED
    assert frame["data"] == {
        "module": "malware",
        "investigation_id": evt.payload.entity_id,
        "status": "completed",
        "previous_status": "running",
    }
    assert forwarder.seen_teams == [forwarder.team_id]


async def test_forwarder_ignores_other_entity_kinds(forwarder) -> None:
    events._forward_investigation_status(_status_event(forwarder.team_id, entity_kind="campaign"))
    await asyncio.sleep(0.05)
    assert forwarder.queue.empty()
    assert forwarder.seen_teams == []


# ---------------------------------------------------------------------------
# Task progress SSE: id lines + duplicate-free last_id resume
# ---------------------------------------------------------------------------


def _sid(stream_id: str) -> tuple[int, int]:
    ms, _, seq = stream_id.partition("-")
    return int(ms), int(seq or 0)


class _FakeRedisStream:
    """XRANGE/XREAD over an in-memory stream with Redis id semantics."""

    def __init__(self, entries: list[tuple[str, dict[str, str]]]) -> None:
        self.entries = entries
        self.xread_from: list[str] = []

    async def xrange(self, _key: str, start: str, _end: str):
        return [e for e in self.entries if _sid(e[0]) >= _sid(start)]

    async def xread(self, streams: dict[str, str], block: int, count: int):
        ((key, after),) = streams.items()
        self.xread_from.append(after)
        newer = [e for e in self.entries if _sid(e[0]) > _sid(after)]
        return [(key, newer)] if newer else []


def _progress(stage: str) -> dict[str, str]:
    return {"stage": stage, "message": stage, "percent": "10", "timestamp": "t"}


async def test_task_sse_frames_carry_ids_and_resume_skips_seen() -> None:
    task_id = f"task-{uuid.uuid4()}"
    redis = _FakeRedisStream([
        ("1-0", _progress("init")),
        ("2-0", _progress("inventory")),
        ("3-0", _progress("advisory")),
        ("4-0", _progress("scoring")),
    ])

    @asynccontextmanager
    async def _get_redis():
        yield redis

    # _check_terminal: not terminal after catchup, terminal on the first ping.
    terminal_reads = iter([None, SimpleNamespace(status="done")])

    @asynccontextmanager
    async def _session_scope():
        result = MagicMock()
        result.first.side_effect = lambda: next(terminal_reads)
        session = MagicMock()
        session.exec = AsyncMock(return_value=result)
        yield session

    request = MagicMock()
    request.is_disconnected = AsyncMock(return_value=False)

    with (
        patch("aila.api.sse_gate.enforce_sse_cap"),
        patch.object(tasks_router, "pool_available", return_value=True),
        patch.object(tasks_router, "async_session_scope", _session_scope),
        patch.object(tasks_router.TaskRepository, "get_for_user", AsyncMock(return_value=object())),
        patch("aila.platform.tasks.progress.get_redis", _get_redis),
        patch("aila.platform.tasks.get_task_tuning", lambda _key, default: default),
    ):
        # Client already received through 2-0 and reconnects with it.
        response = await tasks_router.stream_task_events(
            task_id=task_id, request=request, last_id="2-0", auth=MagicMock(),
        )
        body = "".join([str(chunk) async for chunk in response.body_iterator])

    frames = [f for f in body.split("\n\n") if f]
    ids = [line.removeprefix("id: ") for f in frames for line in f.split("\n") if line.startswith("id: ")]
    stages = [
        json.loads(line.removeprefix("data: ")).get("stage")
        for f in frames
        for line in f.split("\n")
        if line.startswith("data: ")
    ]

    assert ids == ["3-0", "4-0"]
    assert stages[:2] == ["advisory", "scoring"]
    assert "inventory" not in stages
    # Live read starts after the newest replayed id, never re-reading it.
    assert redis.xread_from[0] == "4-0"
    assert frames[-1].startswith("event: done")
