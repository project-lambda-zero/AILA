"""SSE replay for campaign event streams.

PostgreSQL rows are the only payload source. Redis XREAD is a wake-up hint: a
missed or trimmed wake-up delays delivery until the poll interval and never
drops an event. Each connection buffers at most ``queue_maxsize`` frames. A
consumer that falls that far behind receives an explicit ``resync`` frame and the
stream ends, so the client reconnects with Last-Event-ID and resumes without a gap.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
from collections.abc import AsyncGenerator
from dataclasses import dataclass

from redis.exceptions import RedisError
from sqlalchemy.exc import SQLAlchemyError

from aila.platform.events.outbox import MAX_READ_LIMIT, campaign_event_redis_key, read_events
from aila.platform.services.redis_pool import get_redis, pool_available
from aila.storage.database import async_session_scope
from aila.storage.event_models import EventEnvelope

__all__ = [
    "HEARTBEAT_FRAME",
    "InvalidEventCursorError",
    "format_event_frame",
    "parse_last_event_id",
    "stream_campaign_events",
]

_log = logging.getLogger(__name__)

HEARTBEAT_FRAME = ": heartbeat\n\n"
RESYNC_FRAME = 'event: resync\ndata: {"reason": "slow_consumer"}\n\n'
REPLAY_UNAVAILABLE_FRAME = 'event: error\ndata: {"reason": "replay_unavailable"}\n\n'

MAX_CURSOR_DIGITS = 19
MAX_SEQUENCE = 2**63 - 1
DEFAULT_PAGE_SIZE = MAX_READ_LIMIT
DEFAULT_QUEUE_MAXSIZE = 1000
DEFAULT_POLL_INTERVAL_S = 2.0
DEFAULT_HEARTBEAT_INTERVAL_S = 15.0
_WAKEUP_READ_COUNT = 100


class InvalidEventCursorError(ValueError):
    """Raised for a Last-Event-ID that is not a non-negative decimal sequence."""


@dataclass(frozen=True, slots=True)
class _Frame:
    text: str
    terminal: bool


def parse_last_event_id(raw: str | None) -> int:
    """Parse a Last-Event-ID header. Missing or empty means replay from the beginning."""
    if raw is None or raw == "":
        return 0
    if len(raw) > MAX_CURSOR_DIGITS or not raw.isascii() or not raw.isdigit():
        raise InvalidEventCursorError("Last-Event-ID must be a non-negative decimal sequence")
    value = int(raw)
    if value > MAX_SEQUENCE:
        raise InvalidEventCursorError("Last-Event-ID exceeds the sequence range")
    return value


def format_event_frame(envelope: EventEnvelope) -> str:
    """Render one event as an SSE frame. The event type lives in the JSON body, so no
    module-supplied text can inject SSE field lines."""
    data = json.dumps(
        {
            "event_id": envelope.event_id,
            "stream_id": envelope.stream_id,
            "sequence": envelope.sequence,
            "event_type": envelope.event_type,
            "payload": envelope.payload,
            "created_at": envelope.created_at.isoformat(),
        },
        separators=(",", ":"),
    )
    return f"id: {envelope.sequence}\ndata: {data}\n\n"


async def _read_page(stream_id: str, after_sequence: int, page_size: int) -> list[EventEnvelope]:
    # Ambient team context (set by the request middleware) scopes these reads.
    async with async_session_scope() as session:
        return await read_events(
            session,
            stream_id=stream_id,
            after_sequence=after_sequence,
            limit=page_size,
        )


def _as_text(value: str | bytes) -> str:
    return value.decode() if isinstance(value, bytes) else value


async def _wait_for_wakeup(stream_id: str, last_id: str, timeout_s: float) -> str:
    """Block on Redis XREAD as a wake-up hint and return the id to resume from.

    Any Redis failure degrades to a plain sleep, so PostgreSQL polling still delivers events.
    """
    if not pool_available():
        await asyncio.sleep(timeout_s)
        return last_id
    try:
        async with get_redis() as client:
            result = await client.xread(
                {campaign_event_redis_key(stream_id): last_id},
                block=max(1, int(timeout_s * 1000)),
                count=_WAKEUP_READ_COUNT,
            )
    except (RedisError, OSError, TimeoutError) as exc:
        _log.warning("campaign event wake-up unavailable: %s", type(exc).__name__)
        await asyncio.sleep(timeout_s)
        return last_id
    if not result:
        return last_id
    _, entries = result[0]
    return _as_text(entries[-1][0])


def _drain(queue: asyncio.Queue[_Frame]) -> None:
    while not queue.empty():
        queue.get_nowait()


async def _produce(
    stream_id: str,
    after_sequence: int,
    page_size: int,
    poll_interval_s: float,
    queue: asyncio.Queue[_Frame],
) -> None:
    cursor = after_sequence
    wake_id = "$"
    try:
        while True:
            envelopes = await _read_page(stream_id, cursor, page_size)
            for envelope in envelopes:
                try:
                    queue.put_nowait(_Frame(format_event_frame(envelope), terminal=False))
                except asyncio.QueueFull:
                    _drain(queue)
                    queue.put_nowait(_Frame(RESYNC_FRAME, terminal=True))
                    return
                cursor = envelope.sequence
            if len(envelopes) == page_size:
                continue
            wake_id = await _wait_for_wakeup(stream_id, wake_id, poll_interval_s)
    except (SQLAlchemyError, OSError, TimeoutError) as exc:
        _log.warning("campaign event replay failed: %s", type(exc).__name__)
        _drain(queue)
        queue.put_nowait(_Frame(REPLAY_UNAVAILABLE_FRAME, terminal=True))


async def stream_campaign_events(
    *,
    stream_id: str,
    after_sequence: int,
    page_size: int = DEFAULT_PAGE_SIZE,
    queue_maxsize: int = DEFAULT_QUEUE_MAXSIZE,
    poll_interval_s: float = DEFAULT_POLL_INTERVAL_S,
    heartbeat_interval_s: float = DEFAULT_HEARTBEAT_INTERVAL_S,
) -> AsyncGenerator[str, None]:
    """Yield SSE frames for events after ``after_sequence``, then live events, in order.

    The caller validates the stream's team scope and parses Last-Event-ID with
    ``parse_last_event_id``. The queue must hold a full page so that a fast consumer
    is never mistaken for a slow one.
    """
    if after_sequence < 0:
        raise ValueError("after_sequence must be >= 0")
    if not 1 <= page_size <= MAX_READ_LIMIT:
        raise ValueError(f"page_size must be within 1..{MAX_READ_LIMIT}")
    if queue_maxsize <= page_size:
        raise ValueError("queue_maxsize must exceed page_size")
    queue: asyncio.Queue[_Frame] = asyncio.Queue(maxsize=queue_maxsize)
    producer = asyncio.create_task(
        _produce(stream_id, after_sequence, page_size, poll_interval_s, queue),
        name="campaign-event-replay",
    )
    try:
        while True:
            try:
                frame = await asyncio.wait_for(queue.get(), timeout=heartbeat_interval_s)
            except TimeoutError:
                yield HEARTBEAT_FRAME
                continue
            yield frame.text
            if frame.terminal:
                return
    finally:
        producer.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await producer
