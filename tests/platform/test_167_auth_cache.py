"""Auth revocation cache tests for Phase 167 Plan 05 (TEAM-09).

Tests cover:
- Store and check round-trip
- TTL expiry behavior
- Cache invalidation
- Eviction on overflow
- Clear operation
- Concurrent access safety
- Module-level singleton behavior
- Singleton reset for test isolation

These tests are pure in-memory -- no database needed.
"""
from __future__ import annotations

import asyncio

import pytest

from aila.api.auth_cache import AuthRevocationCache, get_auth_cache, reset_auth_cache


@pytest.fixture(autouse=True)
def _reset_singleton():
    """Reset the module-level singleton before and after each test."""
    reset_auth_cache()
    yield
    reset_auth_cache()


@pytest.mark.asyncio
async def test_cache_store_and_check():
    """Store a value, check returns it correctly for both valid and revoked."""
    cache = AuthRevocationCache(ttl_seconds=10.0, max_size=100)

    # Store valid entry
    await cache.store("api_key:abc123", True)
    result = await cache.check("api_key:abc123")
    assert result is True

    # Store revoked entry
    await cache.store("api_key:revoked", False)
    result = await cache.check("api_key:revoked")
    assert result is False

    # Non-existent key returns None
    result = await cache.check("api_key:nonexistent")
    assert result is None


@pytest.mark.asyncio
async def test_cache_ttl_expiry():
    """Store a value with very short TTL, verify it expires."""
    cache = AuthRevocationCache(ttl_seconds=0.05, max_size=100)

    await cache.store("user:u1", True)
    # Immediately after store, should be cached
    result = await cache.check("user:u1")
    assert result is True

    # Wait for TTL to expire
    await asyncio.sleep(0.1)

    # After TTL, should return None (expired)
    result = await cache.check("user:u1")
    assert result is None


@pytest.mark.asyncio
async def test_cache_invalidate():
    """Store a value, invalidate it, verify it's gone."""
    cache = AuthRevocationCache(ttl_seconds=10.0, max_size=100)

    await cache.store("api_key:to_revoke", True)
    result = await cache.check("api_key:to_revoke")
    assert result is True

    # Invalidate
    await cache.invalidate("api_key:to_revoke")
    result = await cache.check("api_key:to_revoke")
    assert result is None

    # Invalidating a non-existent key should not raise
    await cache.invalidate("api_key:never_existed")


@pytest.mark.asyncio
async def test_cache_eviction_on_overflow():
    """Fill cache to max_size, verify oldest entries are evicted."""
    max_size = 10
    cache = AuthRevocationCache(ttl_seconds=10.0, max_size=max_size)

    # Fill the cache to capacity
    for i in range(max_size):
        await cache.store(f"key:{i}", True)
        # Small sleep to ensure monotonic timestamps differ
        await asyncio.sleep(0.001)

    assert cache.size == max_size

    # Store one more -- should trigger eviction of oldest 10% (1 entry)
    await cache.store("key:overflow", True)

    # Cache size should still be at most max_size
    assert cache.size <= max_size

    # The overflow entry should be present
    result = await cache.check("key:overflow")
    assert result is True

    # The oldest entry (key:0) should have been evicted
    result = await cache.check("key:0")
    assert result is None


@pytest.mark.asyncio
async def test_cache_clear():
    """Store multiple values, clear all, verify empty."""
    cache = AuthRevocationCache(ttl_seconds=10.0, max_size=100)

    await cache.store("a", True)
    await cache.store("b", False)
    await cache.store("c", True)
    assert cache.size == 3

    await cache.clear()
    assert cache.size == 0

    # All entries should be gone
    assert await cache.check("a") is None
    assert await cache.check("b") is None
    assert await cache.check("c") is None


@pytest.mark.asyncio
async def test_cache_concurrent_access():
    """Multiple concurrent stores and checks should not corrupt state."""
    cache = AuthRevocationCache(ttl_seconds=10.0, max_size=1000)

    async def store_and_check(key: str, value: bool) -> bool | None:
        await cache.store(key, value)
        return await cache.check(key)

    # Run 50 concurrent store+check operations
    tasks = [store_and_check(f"concurrent:{i}", i % 2 == 0) for i in range(50)]
    results = await asyncio.gather(*tasks)

    # All results should be valid booleans (not None -- TTL is long)
    for i, result in enumerate(results):
        expected = i % 2 == 0
        assert result is expected, f"Key concurrent:{i} expected {expected}, got {result}"

    # All entries should be in the cache
    assert cache.size == 50


@pytest.mark.asyncio
async def test_cache_singleton():
    """get_auth_cache returns the same instance on repeated calls."""
    c1 = get_auth_cache()
    c2 = get_auth_cache()
    assert c1 is c2, "get_auth_cache() should return the same singleton instance"

    # Verify it's a real AuthRevocationCache
    assert isinstance(c1, AuthRevocationCache)

    # Verify default TTL and max_size
    assert c1._ttl == 30.0
    assert c1._max_size == 10_000


@pytest.mark.asyncio
async def test_cache_reset():
    """reset_auth_cache creates a fresh instance on next get_auth_cache call."""
    c1 = get_auth_cache()
    await c1.store("persist_check", True)

    reset_auth_cache()

    c2 = get_auth_cache()
    assert c2 is not c1, "After reset, get_auth_cache() should return a new instance"

    # New instance should be empty
    assert c2.size == 0
    result = await c2.check("persist_check")
    assert result is None
