"""Transactional campaign event streams with an at-least-once Redis relay.

``append_event`` runs inside the caller's transaction, so the stream sequence
and the domain mutation commit together. The relay publishes unpublished outbox
rows to Redis and marks each row only after its Redis entry exists. A crash
between publish and mark republishes the row; Redis rejects the duplicate id
and the relay treats that as already published. Delivery is at-least-once with
stable ids. No exactly-once guarantee is claimed.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from uuid import uuid4

from redis.exceptions import RedisError, ResponseError
from sqlalchemy import func
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import col, select
from sqlmodel.ext.asyncio.session import AsyncSession

from aila.platform.contracts import JsonObject, utc_now
from aila.platform.services.redis_pool import get_redis, pool_available
from aila.storage.database import async_session_scope
from aila.storage.event_models import EventEnvelope, EventOutboxRecord, EventStreamRecord

__all__ = [
    "CAMPAIGN_EVENT_MAXLEN",
    "CAMPAIGN_EVENT_STREAM_PREFIX",
    "MAX_READ_LIMIT",
    "EventOutboxRelay",
    "EventStreamMismatchError",
    "EventStreamNotFoundError",
    "append_event",
    "campaign_event_redis_key",
    "create_stream",
    "oldest_unpublished_age_seconds",
    "read_events",
]

_log = logging.getLogger(__name__)

CAMPAIGN_EVENT_STREAM_PREFIX = "aila:campaign_events:"
CAMPAIGN_EVENT_MAXLEN = 10_000
MAX_READ_LIMIT = 500

RELAY_BATCH_SIZE = 100
RELAY_STREAMS_PER_CYCLE = 20
RELAY_IDLE_INTERVAL_S = 1.0
RELAY_ERROR_BACKOFF_S = 5.0
RELAY_STOP_TIMEOUT_S = 5.0

# Redis reports an XADD whose explicit id is not greater than the stream top
# with "...equal or smaller than the target stream top item".
_DUPLICATE_ID_MARKER = "equal or smaller"


class EventStreamNotFoundError(LookupError):
    """Raised when an event is appended to a stream that does not exist."""


class EventStreamMismatchError(ValueError):
    """Raised when an append names a team or module that does not own the stream."""


def campaign_event_redis_key(stream_id: str) -> str:
    return f"{CAMPAIGN_EVENT_STREAM_PREFIX}{stream_id}"


def _envelope(row: EventOutboxRecord) -> EventEnvelope:
    return EventEnvelope(
        event_id=row.event_id,
        stream_id=row.stream_id,
        sequence=row.sequence,
        event_type=row.event_type,
        payload=row.payload,
        created_at=row.created_at,
    )


async def create_stream(
    session: AsyncSession,
    *,
    stream_id: str,
    team_id: str,
    module_id: str,
) -> None:
    session.add(EventStreamRecord(id=stream_id, team_id=team_id, module_id=module_id))


async def append_event(
    session: AsyncSession,
    *,
    stream_id: str,
    team_id: str,
    module_id: str,
    event_type: str,
    payload: JsonObject,
    event_id: str | None = None,
) -> EventEnvelope:
    """Allocate the next sequence and stage the outbox row in the caller's transaction.

    The stream row is locked for update, so sequences are gapless and monotonic
    per stream. Nothing is committed here; the caller commits with its domain write.
    """
    stream = (
        await session.exec(
            select(EventStreamRecord).where(EventStreamRecord.id == stream_id).with_for_update()
        )
    ).one_or_none()
    if stream is None:
        raise EventStreamNotFoundError(stream_id)
    if stream.team_id != team_id or stream.module_id != module_id:
        raise EventStreamMismatchError(stream_id)

    sequence = stream.last_sequence + 1
    stream.last_sequence = sequence
    row = EventOutboxRecord(
        event_id=event_id or str(uuid4()),
        stream_id=stream_id,
        team_id=team_id,
        module_id=module_id,
        sequence=sequence,
        event_type=event_type,
        payload=dict(payload),
        created_at=utc_now(),
    )
    session.add(row)
    await session.flush()
    return _envelope(row)


async def read_events(
    session: AsyncSession,
    *,
    stream_id: str,
    after_sequence: int,
    limit: int = MAX_READ_LIMIT,
) -> list[EventEnvelope]:
    """Return up to ``limit`` events with sequence greater than ``after_sequence``, ascending."""
    if after_sequence < 0:
        raise ValueError("after_sequence must be >= 0")
    if not 1 <= limit <= MAX_READ_LIMIT:
        raise ValueError(f"limit must be within 1..{MAX_READ_LIMIT}")
    rows = (
        await session.exec(
            select(EventOutboxRecord)
            .where(EventOutboxRecord.stream_id == stream_id)
            .where(EventOutboxRecord.sequence > after_sequence)
            .order_by(col(EventOutboxRecord.sequence))
            .limit(limit)
        )
    ).all()
    return [_envelope(row) for row in rows]


async def oldest_unpublished_age_seconds(
    session: AsyncSession,
    *,
    stream_id: str | None = None,
) -> float | None:
    """Age in seconds of the oldest outbox row not yet published, or None if none are pending."""
    statement = select(func.min(EventOutboxRecord.created_at)).where(
        col(EventOutboxRecord.published_at).is_(None)
    )
    if stream_id is not None:
        statement = statement.where(EventOutboxRecord.stream_id == stream_id)
    oldest = (await session.exec(statement)).one()
    if oldest is None:
        return None
    return max(0.0, (utc_now() - oldest).total_seconds())


async def _publish_entry(stream_id: str, sequence: int, maxlen: int) -> None:
    """XADD one event with id ``{sequence}-0``.

    An entry already holding that id (a crash after XADD but before the row was
    marked) counts as published.
    """
    async with get_redis() as client:
        try:
            await client.xadd(
                campaign_event_redis_key(stream_id),
                {"sequence": str(sequence)},
                id=f"{sequence}-0",
                maxlen=maxlen,
                approximate=True,
            )
        except ResponseError as exc:
            if _DUPLICATE_ID_MARKER not in str(exc):
                raise


class EventOutboxRelay:
    """Bounded background loop that publishes unpublished outbox rows to Redis.

    Each cycle locks up to ``streams_per_cycle`` streams with SKIP LOCKED. A locked
    stream is published in sequence order by one replica at a time, so a later
    sequence is never published ahead of an earlier one. A row is marked published
    only after its Redis entry exists.
    """

    def __init__(
        self,
        *,
        batch_size: int = RELAY_BATCH_SIZE,
        streams_per_cycle: int = RELAY_STREAMS_PER_CYCLE,
        idle_interval_s: float = RELAY_IDLE_INTERVAL_S,
        error_backoff_s: float = RELAY_ERROR_BACKOFF_S,
        maxlen: int = CAMPAIGN_EVENT_MAXLEN,
    ) -> None:
        if batch_size < 1 or streams_per_cycle < 1 or maxlen < 1:
            raise ValueError("batch_size, streams_per_cycle and maxlen must be >= 1")
        self._batch_size = batch_size
        self._streams_per_cycle = streams_per_cycle
        self._idle_interval_s = idle_interval_s
        self._error_backoff_s = error_backoff_s
        self._maxlen = maxlen
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    def start(self) -> None:
        if self._task is not None:
            return
        self._stop = asyncio.Event()
        self._task = asyncio.create_task(self._run(), name="campaign-event-relay")

    async def stop(self) -> None:
        task = self._task
        if task is None:
            return
        self._task = None
        self._stop.set()
        done, _ = await asyncio.wait({task}, timeout=RELAY_STOP_TIMEOUT_S)
        if not done:
            task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    async def publish_cycle(self) -> int:
        """Publish one bounded cycle and return the number of rows marked published."""
        if not pool_available():
            return 0
        async with async_session_scope() as session:
            streams = (
                await session.exec(
                    select(EventStreamRecord)
                    .where(
                        col(EventStreamRecord.id).in_(
                            select(EventOutboxRecord.stream_id).where(
                                col(EventOutboxRecord.published_at).is_(None)
                            )
                        )
                    )
                    .order_by(col(EventStreamRecord.id))
                    .limit(self._streams_per_cycle)
                    .with_for_update(skip_locked=True)
                )
            ).all()
            published = 0
            failure: RedisError | None = None
            for stream in streams:
                count, failure = await self._publish_stream(session, stream.id)
                published += count
                if failure is not None:
                    break
            await session.commit()
        if failure is not None:
            raise failure
        return published

    async def _publish_stream(
        self, session: AsyncSession, stream_id: str
    ) -> tuple[int, RedisError | None]:
        rows = (
            await session.exec(
                select(EventOutboxRecord)
                .where(EventOutboxRecord.stream_id == stream_id)
                .where(col(EventOutboxRecord.published_at).is_(None))
                .order_by(col(EventOutboxRecord.sequence))
                .limit(self._batch_size)
            )
        ).all()
        published = 0
        for row in rows:
            try:
                await _publish_entry(stream_id, row.sequence, self._maxlen)
            except RedisError as exc:
                return published, exc
            row.published_at = utc_now()
            published += 1
        return published, None

    async def _run(self) -> None:
        while not self._stop.is_set():
            delay = self._idle_interval_s
            try:
                published = await self.publish_cycle()
            except (RedisError, OSError, TimeoutError, SQLAlchemyError) as exc:
                _log.warning("campaign event relay cycle failed: %s", type(exc).__name__)
                delay = self._error_backoff_s
            else:
                if published:
                    continue
            await self._sleep(delay)

    async def _sleep(self, delay: float) -> None:
        with contextlib.suppress(TimeoutError):
            await asyncio.wait_for(self._stop.wait(), timeout=delay)
