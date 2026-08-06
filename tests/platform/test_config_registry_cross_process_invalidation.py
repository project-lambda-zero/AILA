"""Cross-process ConfigRegistry cache invalidation (#56).

Registry cache used to be process-local: a ``set()`` in worker A did NOT
invalidate worker B's in-memory cache, so B served the stale value for up to
``cache_ttl`` seconds (default 60s). The fix wires an INCR-backed Redis
version key: any ``set()`` bumps the counter; peer registries poll it
(throttled) on the next ``get`` / ``get_sync`` and drop entries older than
the current version.

These tests exercise the invalidation flow directly by injecting a shared
in-process fake Redis client into two ConfigRegistry instances (simulating
two worker processes). ``version_poll_interval=0.0`` disables the throttle so
every get triggers a fresh Redis read -- keeps the assertions deterministic
without waiting on wall-clock time.

Requires ``test_db`` because ``ConfigRegistry.register`` and
``ConfigRegistry.set`` both hit ``ConfigEntryRecord`` for real. Redis is
faked; the DB is real.
"""
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any
from uuid import uuid4

import pytest
from pydantic import BaseModel

from aila.storage.registry import ConfigRegistry

# ---------------------------------------------------------------------------
# Fake Redis client (in-memory, shared by peer registries in one test run)
# ---------------------------------------------------------------------------


class _FakeAsyncRedis:
    """In-memory async client with just the two methods ConfigRegistry uses.

    ``store`` is shared across peer registries so an ``incr`` on one instance
    is visible to the ``get`` on another -- the whole point of the test.
    """

    def __init__(self, store: dict[str, bytes]) -> None:
        self._store = store

    async def get(self, key: str) -> bytes | None:
        return self._store.get(key)

    async def incr(self, key: str) -> int:
        current = int(self._store.get(key, b"0") or b"0")
        current += 1
        self._store[key] = str(current).encode("ascii")
        return current


def _make_factory(store: dict[str, bytes]) -> Any:
    """Build an async-context-manager factory yielding a shared fake client."""
    fake_client = _FakeAsyncRedis(store)

    @asynccontextmanager
    async def _factory():  # noqa: ANN202
        yield fake_client

    return _factory


class _Schema(BaseModel):
    """Trivial schema with one settable str field."""

    label: str = "initial"


# ---------------------------------------------------------------------------
# Main test: two peer registries, cross-process invalidation via version key
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_peer_set_invalidates_local_cache(test_db) -> None:
    """After peer A ``set()``s a value, peer B's next ``get`` refetches from DB.

    Without the version-key mechanism, B would serve its cached "initial"
    value for the full cache_ttl window. With #56, the shared Redis counter
    bumps, B's cache entry version is older than the current version, entry
    is dropped, and B re-reads the freshly-written row from Postgres.
    """
    ns = f"testcfg{uuid4().hex[:8]}"
    shared_store: dict[str, bytes] = {}
    factory = _make_factory(shared_store)

    peer_a = ConfigRegistry(
        redis_async_ctx_factory=factory,
        version_poll_interval=0.0,
    )
    peer_b = ConfigRegistry(
        redis_async_ctx_factory=factory,
        version_poll_interval=0.0,
    )

    # Both peers see the same schema. Only the first ``register`` inserts the
    # default row; the second one is idempotent (existing row wins).
    await peer_a.register(ns, _Schema)
    await peer_b.register(ns, _Schema)

    # Prime B's cache with the initial value.
    initial_b = await peer_b.get(ns, "label")
    assert initial_b == "initial", (
        f"Expected initial default 'initial', got {initial_b!r}"
    )

    # A writes a new value. This bumps the shared Redis version counter.
    await peer_a.set(ns, "label", "updated_by_a")

    # B's next ``get`` MUST see the fresh value, not the cached "initial".
    # Pre-#56 this returned "initial" for up to cache_ttl seconds.
    refreshed_b = await peer_b.get(ns, "label")
    assert refreshed_b == "updated_by_a", (
        f"Cross-process invalidation failed: peer B saw stale {refreshed_b!r}"
    )

    # And the shared store proves the counter actually incremented (not just
    # that B happened to hit the DB by luck / cache-lock timing).
    version_bytes = shared_store.get("aila:config:invalidation_version")
    assert version_bytes is not None, "set() did not INCR the version key"
    assert int(version_bytes) >= 1, (
        f"Expected version >= 1 after one set(), got {int(version_bytes)}"
    )


# ---------------------------------------------------------------------------
# Graceful degradation: Redis unavailable -> falls back to TTL cache
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_get_survives_when_redis_factory_raises(test_db) -> None:
    """A raising Redis factory MUST NOT crash ``get`` -- fall back to TTL cache.

    A worker whose Redis broker is temporarily down must keep serving cached
    config, even if it means slightly-stale reads until TTL expiry. The
    factory raising is the closest we can get to "Redis is down" in a unit
    test without a live broker.
    """
    ns = f"testcfg{uuid4().hex[:8]}"

    def _raising_factory():  # noqa: ANN202
        raise RuntimeError("simulated Redis outage")

    peer = ConfigRegistry(
        redis_async_ctx_factory=_raising_factory,
        version_poll_interval=0.0,
    )
    await peer.register(ns, _Schema)

    # get MUST NOT raise despite the raising factory. Value comes from DB
    # (empty cache -> DB fetch -> defaulting logic in registry).
    value = await peer.get(ns, "label")
    assert value == "initial"

    # Second get uses the cached value (still no crash from the raising
    # factory). Version poll interval is 0 so we hit the factory every call.
    value_again = await peer.get(ns, "label")
    assert value_again == "initial"


# ---------------------------------------------------------------------------
# set() bumps the version even on a fresh registry (no prior get)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_set_bumps_version_key(test_db) -> None:
    """``set()`` MUST INCR the shared version counter after a successful DB write.

    Guards against a future refactor that accidentally moves the ``_bump``
    call inside a condition that skips it (e.g. into the ``no-op`` branch
    when the value is unchanged).
    """
    ns = f"testcfg{uuid4().hex[:8]}"
    shared_store: dict[str, bytes] = {}
    factory = _make_factory(shared_store)

    registry = ConfigRegistry(
        redis_async_ctx_factory=factory,
        version_poll_interval=0.0,
    )
    await registry.register(ns, _Schema)

    # No bump yet -- neither register nor a bare get should have incremented.
    assert shared_store.get("aila:config:invalidation_version") is None
    await registry.get(ns, "label")
    assert shared_store.get("aila:config:invalidation_version") is None

    # One set -> version becomes 1.
    await registry.set(ns, "label", "changed")
    v1 = int(shared_store["aila:config:invalidation_version"])
    assert v1 == 1, f"Expected version 1 after first set(), got {v1}"

    # Second set with a different value -> version becomes 2.
    await registry.set(ns, "label", "changed_again")
    v2 = int(shared_store["aila:config:invalidation_version"])
    assert v2 == 2, f"Expected version 2 after second set(), got {v2}"

    # Setting the SAME value is a no-op (idempotency skip in registry.set),
    # which means no DB write AND no version bump.
    await registry.set(ns, "label", "changed_again")
    v3 = int(shared_store["aila:config:invalidation_version"])
    assert v3 == 2, (
        f"Idempotent set MUST NOT bump version (got {v3}, expected 2)"
    )
