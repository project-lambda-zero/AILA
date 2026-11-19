"""probe_arq_worker per-track contract against a live Redis (skipped when unreachable).

Each configured track is probed through its own ``arq:queue:<track>:health-check``
key. Tracks come from ``AILA_PLATFORM_WORKER_HEALTH_TRACKS``.
"""

from __future__ import annotations

import socket
from collections.abc import AsyncIterator

import pytest
import pytest_asyncio
import redis.asyncio as aioredis

from aila.platform.services.health_probes import probe_arq_worker
from aila.platform.tasks.constants import ARQ_IN_PROGRESS_PREFIX, ARQ_QUEUE_KEY_TEMPLATE

TEST_REDIS_URL = "redis://127.0.0.1:6379/15"
TRACKS = "vr,vulnerability"


def _redis_reachable() -> bool:
    try:
        with socket.create_connection(("127.0.0.1", 6379), timeout=0.5):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not _redis_reachable(), reason="Memurai/Redis not reachable on 127.0.0.1:6379",
)


def _health_key(track: str) -> str:
    return f"{ARQ_QUEUE_KEY_TEMPLATE.format(track=track)}:health-check:rewrite-test"


@pytest.fixture(autouse=True)
def configured_tracks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AILA_PLATFORM_WORKER_HEALTH_TRACKS", TRACKS)


@pytest_asyncio.fixture
async def clean_redis() -> AsyncIterator[str]:
    client = aioredis.Redis.from_url(TEST_REDIS_URL, socket_connect_timeout=2.0)
    try:
        await client.flushdb()
        yield TEST_REDIS_URL
        await client.flushdb()
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_probe_reports_running_when_every_track_heartbeats(
    clean_redis: str,
) -> None:
    client = aioredis.Redis.from_url(clean_redis)
    try:
        for track in TRACKS.split(","):
            await client.set(_health_key(track), "1", px=60_000)
    finally:
        await client.aclose()

    result = await probe_arq_worker(redis_url=clean_redis)

    assert result.status == "running"
    assert result.details is not None
    assert result.details["tracks_live"] == ["vr", "vulnerability"]
    assert result.details["tracks_missing"] == []
    assert result.details["last_heartbeat_age_s"] < 60


@pytest.mark.asyncio
async def test_probe_reports_degraded_when_one_track_lacks_heartbeat(
    clean_redis: str,
) -> None:
    client = aioredis.Redis.from_url(clean_redis)
    try:
        await client.set(_health_key("vulnerability"), "1", px=60_000)
    finally:
        await client.aclose()

    result = await probe_arq_worker(redis_url=clean_redis)

    assert result.status == "degraded"
    assert result.details is not None
    assert result.details["tracks_missing"] == ["vr"]
    assert result.message is not None
    assert "vr" in result.message


@pytest.mark.asyncio
async def test_probe_reports_offline_when_no_health_key_present(
    clean_redis: str,
) -> None:
    result = await probe_arq_worker(redis_url=clean_redis)

    assert result.status == "offline"
    assert result.details is not None
    assert result.details["tracks_missing"] == ["vr", "vulnerability"]


@pytest.mark.asyncio
async def test_probe_ignores_expired_health_key(
    clean_redis: str,
) -> None:
    client = aioredis.Redis.from_url(clean_redis)
    try:
        await client.set(_health_key("vr"), "1", px=1)
        await client.set(_health_key("vulnerability"), "1", px=1)
    finally:
        await client.aclose()

    result = await probe_arq_worker(redis_url=clean_redis)

    assert result.status == "offline"


@pytest.mark.asyncio
async def test_probe_details_carry_queue_and_in_progress_counts(
    clean_redis: str,
) -> None:
    client = aioredis.Redis.from_url(clean_redis)
    try:
        await client.set(_health_key("vr"), "1", px=60_000)
        await client.set(_health_key("vulnerability"), "1", px=60_000)
        await client.zadd(ARQ_QUEUE_KEY_TEMPLATE.format(track="vr"), {"job-a": 1, "job-b": 2})
        await client.set(f"{ARQ_IN_PROGRESS_PREFIX}job-c", "1")
    finally:
        await client.aclose()

    result = await probe_arq_worker(redis_url=clean_redis)

    assert result.status == "running"
    assert result.details is not None
    assert result.details["queue_depth"] == 2
    assert result.details["in_progress_count"] == 1
    assert "dead_letter_count" in result.details
