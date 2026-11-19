"""SSE replay of campaign event streams from PostgreSQL with a Redis wake-up hint."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncGenerator
from datetime import UTC, datetime
from typing import Any

import pytest
from redis.exceptions import RedisError

import aila.platform.events.replay as replay_module
from aila.platform.events.outbox import append_event, create_stream
from aila.platform.events.replay import (
    HEARTBEAT_FRAME,
    InvalidEventCursorError,
    format_event_frame,
    parse_last_event_id,
    stream_campaign_events,
)
from aila.storage.database import async_session_scope
from aila.storage.event_models import EventEnvelope

STREAM = "replay-stream"
TEAM = "team-r"
MODULE = "pentest"
RESYNC_MARKER = "event: resync"


async def _new_stream() -> None:
    async with async_session_scope() as session:
        await create_stream(session, stream_id=STREAM, team_id=TEAM, module_id=MODULE)
        await session.commit()


async def _append(count: int) -> None:
    async with async_session_scope() as session:
        for index in range(count):
            await append_event(
                session,
                stream_id=STREAM,
                team_id=TEAM,
                module_id=MODULE,
                event_type="step.recorded",
                payload={"index": index},
            )
        await session.commit()


@pytest.fixture
def no_wakeup(monkeypatch: pytest.MonkeyPatch) -> None:
    """Redis reports the pool as available, but every wake-up read fails.

    Delivery must then rely on the PostgreSQL poll alone.
    """

    def _unavailable() -> None:
        raise RedisError("redis unavailable")

    monkeypatch.setattr(replay_module, "pool_available", lambda: True)
    monkeypatch.setattr(replay_module, "get_redis", _unavailable)


async def _collect_events(stream: AsyncGenerator[str, None], count: int) -> list[str]:
    """Read until ``count`` event frames arrive. Heartbeats are skipped."""
    frames: list[str] = []
    while len(frames) < count:
        frame = await anext(stream)
        if frame != HEARTBEAT_FRAME:
            frames.append(frame)
    return frames


def _sequence_of(frame: str) -> int:
    assert frame.startswith("id: ")
    return int(frame.split("\n", 1)[0].removeprefix("id: "))


@pytest.mark.parametrize(
    ("raw", "expected"),
    [(None, 0), ("", 0), ("0", 0), ("42", 42), ("9223372036854775807", 2**63 - 1)],
)
def test_parse_last_event_id_accepts_valid_cursors(raw: str | None, expected: int) -> None:
    assert parse_last_event_id(raw) == expected


@pytest.mark.parametrize(
    "raw",
    ["-1", " 1", "1a", "+1", "00000000000000000000", "9223372036854775808", "\u0661"],
)
def test_parse_last_event_id_rejects_malformed_cursors(raw: str) -> None:
    with pytest.raises(InvalidEventCursorError):
        parse_last_event_id(raw)


def test_format_event_frame_carries_sequence_as_id_and_no_event_field() -> None:
    envelope = EventEnvelope(
        event_id="evt-1",
        stream_id=STREAM,
        sequence=7,
        event_type="injected\nevent: evil",
        payload={"note": "hello"},
        created_at=datetime(2026, 11, 19, 12, 0, tzinfo=UTC),
    )

    frame = format_event_frame(envelope)

    assert frame.startswith("id: 7\ndata: ")
    assert frame.endswith("\n\n")
    assert "\nevent:" not in frame
    body = json.loads(frame.split("data: ", 1)[1].rstrip("\n"))
    assert body["sequence"] == 7
    assert body["event_type"] == "injected\nevent: evil"
    assert body["payload"] == {"note": "hello"}


@pytest.mark.parametrize(
    ("kwargs"),
    [
        {"after_sequence": -1},
        {"after_sequence": 0, "page_size": 0},
        {"after_sequence": 0, "page_size": 501},
        {"after_sequence": 0, "page_size": 10, "queue_maxsize": 10},
    ],
)
async def test_stream_rejects_invalid_arguments(kwargs: dict[str, Any]) -> None:
    stream = stream_campaign_events(stream_id=STREAM, **kwargs)
    with pytest.raises(ValueError):
        await anext(stream)


async def test_resume_after_cursor_has_no_gaps_or_duplicates(
    test_db: None, no_wakeup: None
) -> None:
    await _new_stream()
    await _append(5)

    first = stream_campaign_events(
        stream_id=STREAM,
        after_sequence=0,
        page_size=2,
        queue_maxsize=5,
        poll_interval_s=0.01,
        heartbeat_interval_s=0.05,
    )
    delivered = await _collect_events(first, 3)
    await first.aclose()
    last_delivered = _sequence_of(delivered[-1])

    # Reconnect as a browser would, from Last-Event-ID = the last frame received.
    resumed = stream_campaign_events(
        stream_id=STREAM,
        after_sequence=last_delivered,
        page_size=2,
        queue_maxsize=5,
        poll_interval_s=0.01,
        heartbeat_interval_s=0.05,
    )
    remaining = await _collect_events(resumed, 2)
    await resumed.aclose()

    sequences = [_sequence_of(frame) for frame in delivered + remaining]
    assert sequences == [1, 2, 3, 4, 5]


async def test_live_event_is_delivered_by_poll_when_wakeup_is_unavailable(
    test_db: None, no_wakeup: None
) -> None:
    await _new_stream()
    await _append(1)

    stream = stream_campaign_events(
        stream_id=STREAM,
        after_sequence=0,
        page_size=10,
        queue_maxsize=20,
        poll_interval_s=0.01,
        heartbeat_interval_s=0.05,
    )
    try:
        assert _sequence_of((await _collect_events(stream, 1))[0]) == 1
        await _append(1)
        assert _sequence_of((await _collect_events(stream, 1))[0]) == 2
    finally:
        await stream.aclose()


async def test_slow_consumer_gets_explicit_resync_and_stream_ends(
    test_db: None, no_wakeup: None
) -> None:
    await _new_stream()
    await _append(10)

    stream = stream_campaign_events(
        stream_id=STREAM,
        after_sequence=0,
        page_size=1,
        queue_maxsize=3,
        poll_interval_s=0.01,
        heartbeat_interval_s=5.0,
    )
    first = await anext(stream)
    assert _sequence_of(first) == 1

    # Let the producer run ahead of the consumer until the bounded queue overflows.
    await asyncio.sleep(0.5)

    frames = [frame async for frame in stream]

    assert len(frames) == 1
    assert RESYNC_MARKER in frames[0]


async def test_idle_stream_emits_heartbeat(test_db: None, no_wakeup: None) -> None:
    await _new_stream()

    stream = stream_campaign_events(
        stream_id=STREAM,
        after_sequence=0,
        page_size=10,
        queue_maxsize=20,
        poll_interval_s=0.01,
        heartbeat_interval_s=0.02,
    )
    try:
        assert await anext(stream) == HEARTBEAT_FRAME
    finally:
        await stream.aclose()
