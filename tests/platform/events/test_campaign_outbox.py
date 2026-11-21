"""Transactional outbox for campaign event streams and the Redis relay."""

from __future__ import annotations

from collections.abc import AsyncIterator, Iterator
from contextlib import asynccontextmanager
from typing import Any

import pytest
from redis.exceptions import RedisError, ResponseError

import aila.platform.events.outbox as outbox_module
from aila.platform.events.outbox import (
    CAMPAIGN_EVENT_STREAM_PREFIX,
    EventOutboxRelay,
    EventStreamMismatchError,
    EventStreamNotFoundError,
    append_event,
    create_stream,
    oldest_unpublished_age_seconds,
    read_events,
)
from aila.storage.database import async_session_scope

STREAM = "stream-a"
TEAM = "team-a"
MODULE = "pentest"


async def _new_stream(
    stream_id: str = STREAM, team_id: str = TEAM, module_id: str = MODULE
) -> None:
    async with async_session_scope() as session:
        await create_stream(session, stream_id=stream_id, team_id=team_id, module_id=module_id)
        await session.commit()


async def _append(count: int, stream_id: str = STREAM) -> None:
    async with async_session_scope() as session:
        for index in range(count):
            await append_event(
                session,
                stream_id=stream_id,
                team_id=TEAM,
                module_id=MODULE,
                event_type="step.recorded",
                payload={"index": index},
            )
        await session.commit()


class _FakeRedis:
    """Records XADD calls. Can fail on the Nth call or report a duplicate id."""

    def __init__(
        self, *, fail_on_call: int | None = None, duplicate_sequence: int | None = None
    ) -> None:
        self.entries: list[tuple[str, int]] = []
        self._calls = 0
        self._fail_on_call = fail_on_call
        self._duplicate_sequence = duplicate_sequence

    async def xadd(
        self, name: str, fields: dict[str, str], id: str, maxlen: int, approximate: bool
    ) -> str:
        self._calls += 1
        sequence = int(id.partition("-")[0])
        if self._calls == self._fail_on_call:
            raise RedisError("redis unavailable")
        if sequence == self._duplicate_sequence:
            raise ResponseError(
                "The ID specified in XADD is equal or smaller than the target stream top item"
            )
        self.entries.append((name, sequence))
        return id


@pytest.fixture
def fake_redis(monkeypatch: pytest.MonkeyPatch) -> Iterator[Any]:
    """Patch the outbox relay to a configurable fake Redis client."""
    holder: dict[str, Any] = {}

    @asynccontextmanager
    async def _get_redis() -> AsyncIterator[Any]:
        yield holder["client"]

    monkeypatch.setattr(outbox_module, "get_redis", _get_redis)
    monkeypatch.setattr(outbox_module, "pool_available", lambda: True)
    yield holder


def _use(holder: dict[str, Any], client: _FakeRedis) -> None:
    holder["client"] = client


async def test_rolled_back_append_leaves_no_rows(test_db: None) -> None:
    await _new_stream()
    async with async_session_scope() as session:
        await append_event(
            session,
            stream_id=STREAM,
            team_id=TEAM,
            module_id=MODULE,
            event_type="step.recorded",
            payload={},
        )
        await session.rollback()

    async with async_session_scope() as session:
        assert await read_events(session, stream_id=STREAM, after_sequence=0) == []
        assert await oldest_unpublished_age_seconds(session) is None

    # The stream counter rolled back too, so the next committed event is sequence 1.
    await _append(1)
    async with async_session_scope() as session:
        events = await read_events(session, stream_id=STREAM, after_sequence=0)
    assert [event.sequence for event in events] == [1]


async def test_sequences_are_gapless_and_ordered(test_db: None) -> None:
    await _new_stream()
    await _append(5)

    async with async_session_scope() as session:
        events = await read_events(session, stream_id=STREAM, after_sequence=0)

    assert [event.sequence for event in events] == [1, 2, 3, 4, 5]
    assert [event.payload for event in events] == [{"index": i} for i in range(5)]
    assert all(
        event.stream_id == STREAM and event.event_type == "step.recorded" for event in events
    )


async def test_read_events_honors_cursor_and_limit(test_db: None) -> None:
    await _new_stream()
    await _append(4)

    async with async_session_scope() as session:
        after_two = await read_events(session, stream_id=STREAM, after_sequence=2, limit=10)
        first_one = await read_events(session, stream_id=STREAM, after_sequence=0, limit=1)

    assert [event.sequence for event in after_two] == [3, 4]
    assert [event.sequence for event in first_one] == [1]


@pytest.mark.parametrize(("after_sequence", "limit"), [(-1, 10), (0, 0), (0, 501)])
async def test_read_events_rejects_out_of_bounds_arguments(
    test_db: None, after_sequence: int, limit: int
) -> None:
    await _new_stream()
    async with async_session_scope() as session:
        with pytest.raises(ValueError):
            await read_events(session, stream_id=STREAM, after_sequence=after_sequence, limit=limit)


async def test_append_to_missing_stream_raises(test_db: None) -> None:
    async with async_session_scope() as session:
        with pytest.raises(EventStreamNotFoundError):
            await append_event(
                session,
                stream_id="missing",
                team_id=TEAM,
                module_id=MODULE,
                event_type="step.recorded",
                payload={},
            )


async def test_append_with_wrong_team_or_module_raises(test_db: None) -> None:
    await _new_stream()
    async with async_session_scope() as session:
        with pytest.raises(EventStreamMismatchError):
            await append_event(
                session,
                stream_id=STREAM,
                team_id="other-team",
                module_id=MODULE,
                event_type="step.recorded",
                payload={},
            )
        with pytest.raises(EventStreamMismatchError):
            await append_event(
                session,
                stream_id=STREAM,
                team_id=TEAM,
                module_id="other-module",
                event_type="step.recorded",
                payload={},
            )


async def test_oldest_unpublished_age_is_none_without_pending_rows(test_db: None) -> None:
    await _new_stream()
    async with async_session_scope() as session:
        assert await oldest_unpublished_age_seconds(session) is None
        assert await oldest_unpublished_age_seconds(session, stream_id=STREAM) is None


async def test_oldest_unpublished_age_reports_pending_rows(test_db: None) -> None:
    await _new_stream()
    await _append(2)
    async with async_session_scope() as session:
        age = await oldest_unpublished_age_seconds(session, stream_id=STREAM)
    assert age is not None
    assert age >= 0.0


async def test_relay_publishes_and_marks_rows(test_db: None, fake_redis: dict[str, Any]) -> None:
    await _new_stream()
    await _append(3)
    client = _FakeRedis()
    _use(fake_redis, client)

    published = await EventOutboxRelay().publish_cycle()

    assert published == 3
    key = f"{CAMPAIGN_EVENT_STREAM_PREFIX}{STREAM}"
    assert client.entries == [(key, 1), (key, 2), (key, 3)]
    async with async_session_scope() as session:
        assert await oldest_unpublished_age_seconds(session) is None

    assert await EventOutboxRelay().publish_cycle() == 0


async def test_relay_failure_leaves_unpublished_rows_for_retry(
    test_db: None, fake_redis: dict[str, Any]
) -> None:
    await _new_stream()
    await _append(3)
    failing = _FakeRedis(fail_on_call=2)
    _use(fake_redis, failing)

    with pytest.raises(RedisError):
        await EventOutboxRelay().publish_cycle()

    # Row 1 was published before the failure and stays marked. Rows 2 and 3 must be retried.
    healthy = _FakeRedis()
    _use(fake_redis, healthy)
    assert await EventOutboxRelay().publish_cycle() == 2
    assert [sequence for _, sequence in healthy.entries] == [2, 3]


async def test_relay_treats_duplicate_redis_id_as_published(
    test_db: None, fake_redis: dict[str, Any]
) -> None:
    await _new_stream()
    await _append(3)
    client = _FakeRedis(duplicate_sequence=1)
    _use(fake_redis, client)

    published = await EventOutboxRelay().publish_cycle()

    assert published == 3
    assert [sequence for _, sequence in client.entries] == [2, 3]
    async with async_session_scope() as session:
        assert await oldest_unpublished_age_seconds(session) is None


async def test_relay_cycle_is_bounded_by_batch_size(
    test_db: None, fake_redis: dict[str, Any]
) -> None:
    await _new_stream()
    await _append(5)
    _use(fake_redis, _FakeRedis())
    relay = EventOutboxRelay(batch_size=2)

    assert await relay.publish_cycle() == 2
    assert await relay.publish_cycle() == 2
    assert await relay.publish_cycle() == 1
    assert await relay.publish_cycle() == 0
