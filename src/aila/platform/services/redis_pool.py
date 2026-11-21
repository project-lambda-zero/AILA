"""Shared async Redis connection pool for AILA platform.

All components that need Redis should use get_redis() rather than
creating their own connections.  The pool is initialized once during
application startup (lifespan) and closed on shutdown.

Usage::

    from aila.platform.services.redis_pool import get_redis

    async with get_redis() as client:
        await client.set("key", "value")
"""
from __future__ import annotations

import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
from sqlalchemy.exc import SQLAlchemyError

__all__ = [
    "close_redis_pool",
    "get_redis",
    "init_redis_pool",
    "pool_available",
]

_log = logging.getLogger(__name__)
_pool: aioredis.ConnectionPool | None = None
_url: str | None = None


async def _configured_redis_url() -> str | None:
    """Resolve the platform Redis URL through the config registry.

    ``ConfigRegistry.get`` already applies ``AILA_PLATFORM_REDIS_URL`` before the
    stored value, so the env var is not read here. The registry import is
    function-local: ``aila.storage.registry`` imports this module lazily, so a
    top-level import would form a cycle.
    """
    try:
        from aila.platform.tasks.constants import CONFIG_KEY_REDIS_URL, CONFIG_NS_PLATFORM
        from aila.storage.registry import ConfigRegistry

        return await ConfigRegistry().get(CONFIG_NS_PLATFORM, CONFIG_KEY_REDIS_URL) or None
    except (OSError, RuntimeError, ValueError, SQLAlchemyError) as exc:
        _log.warning("Platform Redis URL unavailable from config registry: %s", type(exc).__name__)
        return None


async def init_redis_pool(url: str | None = None, max_connections: int = 20) -> None:
    """Initialize the shared Redis connection pool.

    Args:
        url: Redis URL.  Falls back to ``AILA_PLATFORM_REDIS_URL``, then the
            platform ``redis_url`` config registry entry.
        max_connections: Maximum number of connections in the pool.

    Raises:
        redis.exceptions.ConnectionError: If Redis is unreachable.
    """
    global _pool, _url
    resolved_url = url or await _configured_redis_url()
    if not resolved_url:
        _log.warning("No Redis URL configured; Redis features will be unavailable")
        return
    _url = resolved_url
    _pool = aioredis.ConnectionPool.from_url(
        resolved_url,
        max_connections=max_connections,
        decode_responses=True,
    )
    # Verify connectivity
    client = aioredis.Redis(connection_pool=_pool)
    try:
        await client.ping()
    finally:
        await client.aclose()
    _log.info("Redis connection pool initialized (%d max connections)", max_connections)


async def close_redis_pool() -> None:
    """Close the shared Redis connection pool.

    Safe to call multiple times or when pool was never initialized.
    """
    global _pool
    if _pool is not None:
        await _pool.aclose()
        _pool = None
        _log.info("Redis connection pool closed")


@asynccontextmanager
async def get_redis() -> AsyncGenerator[aioredis.Redis, None]:
    """Get a Redis client backed by the shared pool.

    Use as an async context manager::

        async with get_redis() as client:
            await client.get("my-key")

    Raises:
        RuntimeError: If pool was not initialized via init_redis_pool().
    """
    if _pool is None:
        # Auto-init when the pool wasn't explicitly initialized (e.g. ARQ worker, reaper cron).
        _auto_url = await _configured_redis_url()
        if _auto_url:
            await init_redis_pool(_auto_url)
        if _pool is None:
            raise RuntimeError("Redis pool not initialized and no Redis URL configured.")
    client = aioredis.Redis(connection_pool=_pool)
    try:
        yield client
    finally:
        await client.aclose()


def pool_available() -> bool:
    """Check if the Redis pool has been initialized."""
    return _pool is not None
