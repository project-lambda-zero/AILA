"""Progress SSE resume cursor: ``Last-Event-ID`` header vs ``last_id`` query (#361).

Drives the real scan, task and investigation stream handlers through their
``StreamingResponse`` body iterators. Redis, the database and the SSE
connection cap are replaced at the boundary by in-memory fakes; no network.
"""
from __future__ import annotations

import json
from collections.abc import AsyncIterator, Iterator
from contextlib import ExitStack, asynccontextmanager, contextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi import HTTPException

from aila.api.auth import AuthContext
from aila.api.constants import ROLE_ADMIN
from aila.api.routers import scans as scans_router
from aila.api.routers import tasks as tasks_router
from aila.modules.forensics import api_router as forensics_api
from aila.modules.forensics.api_router import create_forensics_router

_KINDS = ("scan", "task", "investigation")
_RUN_ID = "run-361"
_PROJECT_ID = "project-361"
_INVESTIGATION_ID = "investigation-361"
_ALL_IDS = [f"{n}-0" for n in range(1, 7)]


def _sid(stream_id: str) -> tuple[int, int]:
    ms, _, seq = stream_id.partition("-")
    return int(ms), int(seq or 0)


class _FakeRedisStream:
    """XRANGE/XREAD over an in-memory stream with Redis id semantics."""

    def __init__(self, entries: list[tuple[str, dict[str, str]]]) -> None:
        self.entries = entries

    async def xrange(self, _key: str, start: str, _end: str):
        return [e for e in self.entries if _sid(e[0]) >= _sid(start)]

    async def xread(self, streams: dict[str, str], block: int, count: int):
        ((key, after),) = streams.items()
        newer = [e for e in self.entries if _sid(e[0]) > _sid(after)]
        return [(key, newer)] if newer else []


class _Request:
    def __init__(self, headers: dict[str, str]) -> None:
        self.headers = headers

    async def is_disconnected(self) -> bool:
        return False


class _FakeUoW:
    def __init__(self, session: MagicMock) -> None:
        self.session = session

    async def __aenter__(self) -> _FakeUoW:
        return self

    async def __aexit__(self, *_exc: object) -> bool:
        return False


@pytest.fixture(autouse=True)
def _disable_forensics_limiter() -> Iterator[None]:
    """Disable the module-local slowapi limiter for direct-invocation tests."""
    prev = forensics_api.limiter.enabled
    forensics_api.limiter.enabled = False
    yield
    forensics_api.limiter.enabled = prev


def _progress(stage: str) -> dict[str, str]:
    return {"stage": stage, "message": stage, "percent": "10", "timestamp": "t"}


def _entries() -> list[tuple[str, dict[str, str]]]:
    return [(event_id, _progress(f"stage{event_id}")) for event_id in _ALL_IDS]


def _reads_for(kind: str) -> list[object]:
    """Queued ``result.first()`` values, in the order each handler reads them.

    scan/task: the first terminal check sees a live task, the ping sees it done.
    investigation: project, investigation, then status reads (live, then done).
    """
    if kind == "investigation":
        return [
            SimpleNamespace(id=_PROJECT_ID, team_id=None),
            SimpleNamespace(id=_INVESTIGATION_ID, project_id=_PROJECT_ID, task_id=_RUN_ID, status="running"),
            SimpleNamespace(status="running"),
            SimpleNamespace(status="completed"),
        ]
    return [None, SimpleNamespace(status="done", heartbeat_at=None)]


@contextmanager
def _patched(kind: str, redis: _FakeRedisStream, session: MagicMock) -> Iterator[None]:
    @asynccontextmanager
    async def _get_redis() -> AsyncIterator[_FakeRedisStream]:
        yield redis

    @asynccontextmanager
    async def _session_scope() -> AsyncIterator[MagicMock]:
        yield session

    with ExitStack() as stack:
        stack.enter_context(patch("aila.api.sse_gate.enforce_sse_cap"))
        stack.enter_context(patch("aila.platform.tasks.progress.get_redis", _get_redis))
        stack.enter_context(patch("aila.platform.tasks.get_task_tuning", lambda _key, default: default))
        if kind == "investigation":
            stack.enter_context(patch.object(forensics_api, "pool_available", return_value=True))
            stack.enter_context(patch.object(forensics_api, "UnitOfWork", lambda: _FakeUoW(session)))
        else:
            module = scans_router if kind == "scan" else tasks_router
            stack.enter_context(patch.object(module, "pool_available", return_value=True))
            stack.enter_context(patch.object(module, "async_session_scope", _session_scope))
            stack.enter_context(
                patch.object(module.TaskRepository, "get_for_user", AsyncMock(return_value=object()))
            )
        yield


async def _call(kind: str, request: _Request, last_id: str | None):
    if kind == "scan":
        return await scans_router.stream_scan_events(
            run_id=_RUN_ID, request=request, last_id=last_id, auth=MagicMock(),
        )
    if kind == "task":
        return await tasks_router.stream_task_events(
            task_id=_RUN_ID, request=request, last_id=last_id, auth=MagicMock(),
        )
    endpoint = next(
        route.endpoint
        for route in create_forensics_router().routes
        if getattr(route, "path", None) == "/projects/{project_id}/investigations/{investigation_id}/events"
    )
    admin = AuthContext(user_id="admin-361", role=ROLE_ADMIN, auth_type="user", team_id=None)
    return await endpoint(
        request=request,
        project_id=_PROJECT_ID,
        investigation_id=_INVESTIGATION_ID,
        last_id=last_id,
        auth=admin,
    )


def _sse_frames(body: str) -> list[tuple[str | None, str | None, dict | None]]:
    """Parse an SSE body into ``(id, event, data)`` tuples, one per frame."""
    frames: list[tuple[str | None, str | None, dict | None]] = []
    for raw in body.split("\n\n"):
        event_id = event = data = None
        for line in raw.splitlines():
            if line.startswith("id: "):
                event_id = line[len("id: "):]
            elif line.startswith("event: "):
                event = line[len("event: "):]
            elif line.startswith("data: "):
                data = json.loads(line[len("data: "):])
        if event_id is not None or event is not None or data is not None:
            frames.append((event_id, event, data))
    return frames


async def _stream(
    kind: str, *, last_id: str | None, last_event_id: str | None = None,
) -> list[tuple[str | None, str | None, dict | None]]:
    redis = _FakeRedisStream(_entries())
    reads = _reads_for(kind)
    result = MagicMock()
    result.first.side_effect = lambda: reads.pop(0)
    session = MagicMock()
    session.exec = AsyncMock(return_value=result)
    headers = {} if last_event_id is None else {"last-event-id": last_event_id}
    with _patched(kind, redis, session):
        response = await _call(kind, _Request(headers), last_id)
        body = "".join([str(chunk) async for chunk in response.body_iterator])
    return _sse_frames(body)


def _replayed_ids(frames: list[tuple[str | None, str | None, dict | None]]) -> list[str]:
    return [event_id for event_id, _, _ in frames if event_id is not None]


@pytest.mark.parametrize("kind", _KINDS)
async def test_header_alone_resumes_after_last_event_id(kind: str) -> None:
    frames = await _stream(kind, last_id=None, last_event_id="5-0")

    assert _replayed_ids(frames) == ["6-0"]


@pytest.mark.parametrize("kind", _KINDS)
async def test_query_cursor_overrides_header(kind: str) -> None:
    frames = await _stream(kind, last_id="2-0", last_event_id="5-0")

    assert _replayed_ids(frames) == ["3-0", "4-0", "5-0", "6-0"]


@pytest.mark.parametrize("kind", _KINDS)
async def test_explicit_zero_query_replays_everything_despite_header(kind: str) -> None:
    frames = await _stream(kind, last_id="0", last_event_id="5-0")

    assert _replayed_ids(frames) == _ALL_IDS


@pytest.mark.parametrize("kind", _KINDS)
async def test_fresh_connection_replays_from_start(kind: str) -> None:
    frames = await _stream(kind, last_id=None, last_event_id=None)

    assert _replayed_ids(frames) == _ALL_IDS


@pytest.mark.parametrize("kind", _KINDS)
@pytest.mark.parametrize("malformed", ["abc", "5", "5-x", "1-" + "0" * 63])
async def test_malformed_header_is_treated_as_fresh(kind: str, malformed: str) -> None:
    frames = await _stream(kind, last_id=None, last_event_id=malformed)

    assert _replayed_ids(frames) == _ALL_IDS


@pytest.mark.parametrize("kind", _KINDS)
@pytest.mark.parametrize("malformed", ["abc", "5", "1-x", ""])
async def test_malformed_query_cursor_is_rejected_with_400(kind: str, malformed: str) -> None:
    with pytest.raises(HTTPException) as exc:
        await _stream(kind, last_id=malformed, last_event_id="5-0")

    assert exc.value.status_code == 400
