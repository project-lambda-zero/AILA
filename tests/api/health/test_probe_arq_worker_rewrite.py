"""Phase 179 Task 2 -- probe_arq_worker rewrite (ARQ-native health-check key).

Asserts the probe reports ``running`` when ``arq:<queue>:health-check`` has
a positive TTL, ``offline`` when the key is missing, and that the legacy
``aila:worker:alive:*`` key is IGNORED (proves the legacy scan path is
deleted).
"""
from __future__ import annotations

import pytest
import pytest_asyncio

from aila.platform.services.health_probes import probe_arq_worker

TEST_REDIS_URL_DEFAULT = "redis://127.0.0.1:6379/15"


def _redis_reachable() -> bool:
    import socket
    try:
        with socket.create_connection(("127.0.0.1", 6379), timeout=0.5):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not _redis_reachable(), reason="Memurai/Redis not reachable on 127.0.0.1:6379",
)


@pytest_asyncio.fixture
async def clean_redis() -> str:
    import redis.asyncio as aioredis

    client = aioredis.Redis.from_url(TEST_REDIS_URL_DEFAULT, socket_connect_timeout=2.0)
    try:
        await client.flushdb()
    finally:
        await client.aclose()
    yield TEST_REDIS_URL_DEFAULT
    client = aioredis.Redis.from_url(TEST_REDIS_URL_DEFAULT, socket_connect_timeout=2.0)
    try:
        await client.flushdb()
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_probe_reports_running_when_health_key_fresh(clean_redis: str) -> None:
    import redis.asyncio as aioredis

    client = aioredis.Redis.from_url(clean_redis, socket_connect_timeout=2.0)
    try:
        # Seed with 65s TTL -- probe should compute age < 60s.
        await client.set("arq:queue:vulnerability:health-check", "1", ex=65)
    finally:
        await client.aclose()

    result = await probe_arq_worker(redis_url=clean_redis)
    assert result.status == "running"
    assert result.details is not None
    assert "last_heartbeat_age_s" in result.details
    assert result.details["last_heartbeat_age_s"] < 60


@pytest.mark.asyncio
async def test_probe_reports_offline_when_health_key_missing(clean_redis: str) -> None:
    # Fresh db -- no health-check key seeded.
    result = await probe_arq_worker(redis_url=clean_redis)
    assert result.status == "offline"
    assert result.details is not None
    assert "queue_depth" in result.details
    assert "in_progress_count" in result.details
    assert "dead_letter_count" in result.details


@pytest.mark.asyncio
async def test_probe_ignores_legacy_aila_worker_alive_key(clean_redis: str) -> None:
    """Seeding the legacy liveness key does NOT make the probe report healthy."""
    import redis.asyncio as aioredis

    client = aioredis.Redis.from_url(clean_redis, socket_connect_timeout=2.0)
    try:
        # Seed only the legacy key -- health-check key absent.
        await client.set("aila:worker:alive:vulnerability", "2026-04-12T00:00:00Z", ex=300)
    finally:
        await client.aclose()

    result = await probe_arq_worker(redis_url=clean_redis)
    # Legacy key is ignored: probe still reports offline because the
    # ARQ-native health-check key is missing.
    assert result.status == "offline"


@pytest.mark.asyncio
async def test_probe_details_carry_queue_and_dead_letter_counts(
    clean_redis: str,
) -> None:
    import redis.asyncio as aioredis

    client = aioredis.Redis.from_url(clean_redis, socket_connect_timeout=2.0)
    try:
        await client.set("arq:queue:vulnerability:health-check", "1", ex=60)
        await client.zadd("arq:queue:vulnerability", {"job-a": 1.0, "job-b": 2.0})
        await client.zadd(
            "arq:dead-letter:vulnerability", {"payload-1": 100.0},
        )
        await client.set("arq:in-progress:job-c", "1")
    finally:
        await client.aclose()

    result = await probe_arq_worker(redis_url=clean_redis)
    assert result.status == "running"
    assert result.details is not None
    assert result.details["queue_depth"] == 2
    assert result.details["dead_letter_count"] == 1
    assert result.details["in_progress_count"] == 1
