"""#362 VR SSE streams emit stable event ids and resume native reconnects.

The VR project event stream and the investigation-message stream are driven
through the real handlers from ``create_vr_router`` against seeded rows in the
Postgres ``test_db`` fixture. Each test asserts consumer-visible frames only:

- every row frame carries ``id: <iso-8601 UTC ts>|<row id>``;
- a ``Last-Event-ID`` reconnect resumes strictly after the represented
  ``(timestamp, row id)`` position, including a later row id at the same
  timestamp, and never replays the represented row;
- rows sharing a timestamp stream in row-id order;
- an explicit ``since_iso`` keeps precedence over ``Last-Event-ID``;
- a fresh connection and malformed header values start at the current time;
- a malformed ``since_iso`` is a 422;
- the investigation stream honours ``branch_id``, including on resume;
- the cursor helpers round-trip ids and reject malformed values.

The investigation-message stream is seeded with a terminal status so it drains
and emits ``done``; the project stream never terminates, so frames are read
up to the expected count and the generator is closed.

The slowapi limiter is disabled by the ``_disable_slowapi_limiter`` autouse
fixture in ``tests/api/conftest.py``, so the endpoints run their inner
closures directly. The global SSE connection cap (``aila.api.sse_gate``) is
patched out during the handler call, as in the other SSE tests, so the cap's
registry read does not sit between the test and the stream behavior under test.
"""
from __future__ import annotations

import asyncio
import json
from datetime import UTC, datetime, timedelta, timezone
from typing import Any
from unittest.mock import patch
from uuid import uuid4

import pytest
from fastapi import HTTPException
from starlette.requests import Request
from starlette.responses import StreamingResponse
from starlette.routing import Route

from aila.api.auth import AuthContext
from aila.modules.vr.api_router import create_vr_router
from aila.modules.vr.contracts import PayloadKind, SenderKind
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationMessageRecord,
    VRInvestigationRecord,
    VRProjectRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.modules.vr.sse_cursor import format_event_id
from aila.storage.database import async_session_scope

_INV_STREAM = "/investigations/{investigation_id}/messages/stream"
_PROJECT_STREAM = "/projects/{project_id}/events"

_T1 = datetime(2020, 1, 1, 12, 0, 0, tzinfo=UTC)
_T2 = _T1 + timedelta(seconds=1)
_BEFORE_T1 = (_T1 - timedelta(seconds=1)).isoformat()
_FRAME_TIMEOUT_S = 10.0


def _endpoint(path: str, method: str) -> Any:
    for route in create_vr_router().routes:
        if isinstance(route, Route) and route.path == path and method in route.methods:
            return route.endpoint
    raise AssertionError(f"route {method} {path} not registered")


def _auth(team_id: str) -> AuthContext:
    return AuthContext(
        user_id=f"u-{team_id}",
        role="analyst",
        auth_type="user",
        team_id=team_id,
    )


def _request(last_event_id: str | None = None) -> Request:
    headers = []
    if last_event_id is not None:
        headers.append((b"last-event-id", last_event_id.encode("ascii")))
    scope = {
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": headers,
        "query_string": b"",
    }
    return Request(scope)


def _parse_frame(chunk: str) -> dict[str, Any]:
    frame: dict[str, Any] = {"id": None, "event": None, "data": None}
    for line in chunk.strip("\n").split("\n"):
        key, _, value = line.partition(": ")
        if key == "id":
            frame["id"] = value
        elif key == "event":
            frame["event"] = value
        elif key == "data":
            frame["data"] = json.loads(value)
    return frame


async def _drain(response: StreamingResponse) -> list[dict[str, Any]]:
    """Read a terminating stream to completion."""
    frames: list[dict[str, Any]] = []

    async def _consume() -> None:
        async for chunk in response.body_iterator:
            frames.append(_parse_frame(str(chunk)))

    await asyncio.wait_for(_consume(), timeout=_FRAME_TIMEOUT_S)
    return frames


async def _take(response: StreamingResponse, count: int) -> list[dict[str, Any]]:
    """Read ``count`` frames from a non-terminating stream, then close it."""
    iterator: Any = response.body_iterator
    frames: list[dict[str, Any]] = []

    async def _consume() -> None:
        while len(frames) < count:
            frames.append(_parse_frame(str(await iterator.__anext__())))

    try:
        await asyncio.wait_for(_consume(), timeout=_FRAME_TIMEOUT_S)
    finally:
        await iterator.aclose()
    return frames


def _message_ids(frames: list[dict[str, Any]]) -> list[str]:
    return [f["data"]["payload"]["id"] for f in frames if f["event"] == "message.created"]


async def _seed_team() -> tuple[str, str]:
    suffix = uuid4().hex[:8]
    team_id = f"team-362-{suffix}"
    async with async_session_scope() as session:
        ws = VRWorkspaceRecord(team_id=team_id, name="W", slug=f"w-{suffix}")
        session.add(ws)
        await session.flush()
        target = VRTargetRecord(
            team_id=team_id, workspace_id=ws.id, display_name="t",
            kind="native_binary",
        )
        session.add(target)
        await session.flush()
        target_id = target.id
        await session.commit()
    return team_id, target_id


async def _seed_project(team_id: str, target_id: str) -> str:
    async with async_session_scope() as session:
        project = VRProjectRecord(
            target_id=target_id, team_id=team_id, name="p-362", status="active",
        )
        session.add(project)
        await session.flush()
        project_id = project.id
        await session.commit()
    return project_id


async def _seed_investigation(
    team_id: str,
    target_id: str,
    *,
    status: str,
    project_id: str | None,
    messages: list[tuple[str, datetime]],
) -> str:
    """Create an investigation with one branch and one message per ``(id, ts)``."""
    async with async_session_scope() as session:
        inv = VRInvestigationRecord(
            team_id=team_id,
            target_id=target_id,
            project_id=project_id,
            title="inv-362",
            status=status,
        )
        session.add(inv)
        await session.flush()
        inv_id = inv.id
        branch = VRInvestigationBranchRecord(investigation_id=inv_id)
        session.add(branch)
        await session.flush()
        branch_id = branch.id
        session.add_all([
            VRInvestigationMessageRecord(
                id=msg_id,
                investigation_id=inv_id,
                branch_id=branch_id,
                sender_kind=SenderKind.ENGINE.value,
                payload_kind=PayloadKind.TEXT.value,
                payload_json=json.dumps({"text": msg_id}),
                created_at=ts,
            )
            for msg_id, ts in messages
        ])
        await session.commit()
    return inv_id


async def _seed_two_branch_investigation(
    team_id: str,
    target_id: str,
    *,
    messages: list[tuple[str, int, datetime]],
) -> tuple[str, str, str]:
    """Create one completed investigation with two branches.

    ``messages`` holds ``(msg_id, branch_index, ts)``; ``branch_index`` is 0 or
    1. Returns ``(investigation_id, branch_a_id, branch_b_id)``.
    """
    async with async_session_scope() as session:
        inv = VRInvestigationRecord(
            team_id=team_id,
            target_id=target_id,
            project_id=None,
            title="inv-362-branches",
            status="completed",
        )
        session.add(inv)
        await session.flush()
        inv_id = inv.id
        branches = [VRInvestigationBranchRecord(investigation_id=inv_id) for _ in range(2)]
        session.add_all(branches)
        await session.flush()
        branch_ids = [b.id for b in branches]
        session.add_all([
            VRInvestigationMessageRecord(
                id=msg_id,
                investigation_id=inv_id,
                branch_id=branch_ids[index],
                sender_kind=SenderKind.ENGINE.value,
                payload_kind=PayloadKind.TEXT.value,
                payload_json=json.dumps({"text": msg_id}),
                created_at=ts,
            )
            for msg_id, index, ts in messages
        ])
        await session.commit()
    return inv_id, branch_ids[0], branch_ids[1]


async def _open_investigation_stream(
    auth: AuthContext,
    investigation_id: str,
    *,
    last_event_id: str | None = None,
    since_iso: str | None = None,
    branch_id: str | None = None,
) -> StreamingResponse:
    handler = _endpoint(_INV_STREAM, "GET")
    with patch("aila.api.sse_gate.enforce_sse_cap"):
        return await handler(
            request=_request(last_event_id),
            investigation_id=investigation_id,
            branch_id=branch_id,
            since_iso=since_iso,
            auth=auth,
        )


async def _open_project_stream(
    auth: AuthContext,
    project_id: str,
    *,
    last_event_id: str | None = None,
    since_iso: str | None = None,
) -> StreamingResponse:
    handler = _endpoint(_PROJECT_STREAM, "GET")
    with patch("aila.api.sse_gate.enforce_sse_cap"):
        return await handler(
            request=_request(last_event_id),
            project_id=project_id,
            since_iso=since_iso,
            auth=auth,
        )


def _event_id(msg_id: str, ts: datetime) -> str:
    return f"{ts.isoformat()}|{msg_id}"


async def test_investigation_message_frames_carry_stable_event_id(test_db) -> None:
    team_id, target_id = await _seed_team()
    p = uuid4().hex[:8]
    inv_id = await _seed_investigation(
        team_id, target_id, status="completed", project_id=None,
        messages=[(f"{p}-a", _T1)],
    )

    response = await _open_investigation_stream(
        _auth(team_id), inv_id, since_iso=_BEFORE_T1,
    )
    frames = await _drain(response)

    message_frames = [f for f in frames if f["event"] == "message.created"]
    assert [f["id"] for f in message_frames] == [_event_id(f"{p}-a", _T1)]


async def test_investigation_reconnect_resumes_after_cursor_with_same_timestamp_tie(
    test_db,
) -> None:
    team_id, target_id = await _seed_team()
    p = uuid4().hex[:8]
    inv_id = await _seed_investigation(
        team_id, target_id, status="completed", project_id=None,
        messages=[(f"{p}-a", _T1), (f"{p}-b", _T1), (f"{p}-c", _T2)],
    )

    response = await _open_investigation_stream(
        _auth(team_id), inv_id, last_event_id=_event_id(f"{p}-a", _T1),
    )
    frames = await _drain(response)

    assert _message_ids(frames) == [f"{p}-b", f"{p}-c"]


async def test_investigation_same_timestamp_messages_stream_in_row_id_order(
    test_db,
) -> None:
    team_id, target_id = await _seed_team()
    p = uuid4().hex[:8]
    inv_id = await _seed_investigation(
        team_id, target_id, status="completed", project_id=None,
        messages=[(f"{p}-c", _T1), (f"{p}-a", _T1), (f"{p}-b", _T1)],
    )

    response = await _open_investigation_stream(
        _auth(team_id), inv_id, since_iso=_BEFORE_T1,
    )
    frames = await _drain(response)

    assert _message_ids(frames) == [f"{p}-a", f"{p}-b", f"{p}-c"]


async def test_investigation_stream_filters_frames_to_requested_branch(test_db) -> None:
    team_id, target_id = await _seed_team()
    p = uuid4().hex[:8]
    inv_id, branch_a, _branch_b = await _seed_two_branch_investigation(
        team_id, target_id,
        messages=[
            (f"{p}-a1", 0, _T1),
            (f"{p}-b1", 1, _T1),
            (f"{p}-a2", 0, _T2),
        ],
    )

    response = await _open_investigation_stream(
        _auth(team_id), inv_id, branch_id=branch_a, since_iso=_BEFORE_T1,
    )
    frames = await _drain(response)

    assert _message_ids(frames) == [f"{p}-a1", f"{p}-a2"]


async def test_investigation_branch_resume_skips_other_branch_rows(test_db) -> None:
    team_id, target_id = await _seed_team()
    p = uuid4().hex[:8]
    inv_id, branch_a, _branch_b = await _seed_two_branch_investigation(
        team_id, target_id,
        messages=[
            (f"{p}-a1", 0, _T1),
            (f"{p}-b1", 1, _T2),
            (f"{p}-a2", 0, _T2),
        ],
    )

    response = await _open_investigation_stream(
        _auth(team_id), inv_id, branch_id=branch_a,
        last_event_id=_event_id(f"{p}-a1", _T1),
    )
    frames = await _drain(response)

    assert _message_ids(frames) == [f"{p}-a2"]


async def test_investigation_since_iso_takes_precedence_over_last_event_id(
    test_db,
) -> None:
    team_id, target_id = await _seed_team()
    p = uuid4().hex[:8]
    inv_id = await _seed_investigation(
        team_id, target_id, status="completed", project_id=None,
        messages=[(f"{p}-a", _T1), (f"{p}-b", _T1), (f"{p}-c", _T2)],
    )

    response = await _open_investigation_stream(
        _auth(team_id),
        inv_id,
        last_event_id=_event_id(f"{p}-b", _T1),
        since_iso=(_T1 - timedelta(seconds=1)).isoformat(),
    )
    frames = await _drain(response)

    assert _message_ids(frames) == [f"{p}-a", f"{p}-b", f"{p}-c"]


async def test_investigation_fresh_connection_omits_existing_messages(test_db) -> None:
    team_id, target_id = await _seed_team()
    p = uuid4().hex[:8]
    inv_id = await _seed_investigation(
        team_id, target_id, status="completed", project_id=None,
        messages=[(f"{p}-a", _T1)],
    )

    response = await _open_investigation_stream(_auth(team_id), inv_id)
    frames = await _drain(response)

    assert _message_ids(frames) == []


@pytest.mark.parametrize(
    "malformed",
    [
        "not-a-cursor",
        f"{_T1.isoformat()}|",
        f"{_T1.replace(tzinfo=None).isoformat()}|x",
        "x" * 200,
    ],
)
async def test_investigation_malformed_last_event_id_is_treated_as_fresh(
    test_db, malformed: str,
) -> None:
    team_id, target_id = await _seed_team()
    p = uuid4().hex[:8]
    inv_id = await _seed_investigation(
        team_id, target_id, status="completed", project_id=None,
        messages=[(f"{p}-a", _T1)],
    )

    response = await _open_investigation_stream(
        _auth(team_id), inv_id, last_event_id=malformed,
    )
    frames = await _drain(response)

    assert _message_ids(frames) == []


async def test_investigation_malformed_since_iso_is_422(test_db) -> None:
    team_id, target_id = await _seed_team()
    inv_id = await _seed_investigation(
        team_id, target_id, status="completed", project_id=None, messages=[],
    )

    with pytest.raises(HTTPException) as exc:
        await _open_investigation_stream(
            _auth(team_id), inv_id, since_iso="not-a-timestamp",
        )
    assert exc.value.status_code == 422


async def test_project_message_frames_carry_stable_event_id(test_db) -> None:
    team_id, target_id = await _seed_team()
    project_id = await _seed_project(team_id, target_id)
    p = uuid4().hex[:8]
    await _seed_investigation(
        team_id, target_id, status="running", project_id=project_id,
        messages=[(f"{p}-a", _T1)],
    )

    response = await _open_project_stream(
        _auth(team_id), project_id, since_iso=_BEFORE_T1,
    )
    frames = await _take(response, count=2)

    message_frames = [f for f in frames if f["event"] == "message.created"]
    assert [f["id"] for f in message_frames] == [_event_id(f"{p}-a", _T1)]


async def test_project_reconnect_resumes_after_cursor_with_same_timestamp_tie(
    test_db,
) -> None:
    team_id, target_id = await _seed_team()
    project_id = await _seed_project(team_id, target_id)
    p = uuid4().hex[:8]
    await _seed_investigation(
        team_id, target_id, status="running", project_id=project_id,
        messages=[(f"{p}-a", _T1), (f"{p}-b", _T1), (f"{p}-c", _T2)],
    )

    response = await _open_project_stream(
        _auth(team_id), project_id, last_event_id=_event_id(f"{p}-a", _T1),
    )
    frames = await _take(response, count=3)

    assert _message_ids(frames) == [f"{p}-b", f"{p}-c"]


async def test_project_stream_does_not_skip_rows_past_a_full_batch(
    test_db, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A full message batch must not let a newer branch row move the cursor past unread messages."""
    monkeypatch.setattr("aila.modules.vr.api_router._SSE_BATCH_LIMIT", 3)
    team_id, target_id = await _seed_team()
    project_id = await _seed_project(team_id, target_id)
    p = uuid4().hex[:8]
    seeded = [(f"{p}-{i}", _T1 + timedelta(milliseconds=i)) for i in range(5)]
    await _seed_investigation(
        team_id, target_id, status="running", project_id=project_id, messages=seeded,
    )

    response = await _open_project_stream(_auth(team_id), project_id, since_iso=_BEFORE_T1)
    # open + five messages + the branch row, whose updated_at is the seed time.
    frames = await _take(response, count=7)

    assert _message_ids(frames) == [msg_id for msg_id, _ in seeded]


def test_format_event_id_normalises_timestamp_to_utc() -> None:
    offset = timezone(timedelta(hours=2))
    local = _T1.astimezone(offset)

    assert format_event_id(local, "row-x") == format_event_id(_T1, "row-x")


async def test_project_fresh_connection_omits_existing_messages(test_db) -> None:
    team_id, target_id = await _seed_team()
    project_id = await _seed_project(team_id, target_id)
    p = uuid4().hex[:8]
    await _seed_investigation(
        team_id, target_id, status="running", project_id=project_id,
        messages=[(f"{p}-a", _T1)],
    )

    response = await _open_project_stream(_auth(team_id), project_id)
    frames = await _take(response, count=1)

    assert frames[0]["event"] == "open"
    assert _message_ids(frames) == []
