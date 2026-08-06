"""Distributed lock for automation runner occurrence coordination (#46).

Guarantees at-most-once execution of a given
``(schedule_id, occurrence_at)`` tuple across multiple runner processes
ticking the same automation schedule concurrently. The runner's
existing ``asyncio.Lock`` and Postgres ``SELECT ... FOR UPDATE SKIP
LOCKED`` (finding 46-3/46-6) prevent the same intra-process runner and
same-transaction row-lock race, but neither survives a second worker
process ticking the same schedule at the same wall-clock instant --
the SKIP LOCKED transaction closes as soon as the SELECT materialises,
so both processes may proceed to enqueue the same occurrence.

This module fills that gap with a Redis ``SET NX PX`` primitive keyed
on ``automation:lock:{schedule_id}:{occurrence_epoch}``. The primary
codebase precedent for cross-process coordination on ephemeral state
is Redis (arq queues, dead-letter tracking, health probes, event
emitter) rather than ``pg_advisory_lock``: the pg advisory lock is
used inside ``platform/services/knowledge.py`` for check-then-insert
serialisation within a single transaction, which is the wrong shape
for a submit path that may take longer than a healthy DB session
should stay open.

Degrade path (documented behaviour, no crash): when the Redis pool is
absent or unreachable the acquire raises ``LockBackendUnavailable``.
The runner catches that and falls back to the UNIQUE constraint on
``automation_run_records(schedule_id, occurrence_at)`` (migration
``105_automation_run_history``), which is the second-order distributed
claim: whichever process wins the INSERT owns the run and every peer
sees ``IntegrityError`` and skips. The run-history row is still
written either way so a missed or duplicated run is observable via
the ``automation_run_records`` table regardless of which layer served
as the barrier.
"""
from __future__ import annotations

__all__ = [
    "AutomationOccurrenceLock",
    "LockBackendUnavailableError",
    "acquire_occurrence_lock",
    "occurrence_lock_key",
    "occurrence_lock_scope",
    "release_occurrence_lock",
]

import logging
import os
import socket
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import UTC, datetime

from redis.exceptions import RedisError

from aila.platform.services.redis_pool import get_redis, pool_available

_log = logging.getLogger(__name__)

# 5 minutes bounds a stuck runner: any single automation occurrence that
# takes longer than this to submit is a bug, and letting the key expire
# is safer than leaving a wedged schedule locked forever. Callers may
# override per-call.
_LOCK_TTL_S: int = 300

_LOCK_KEY_PREFIX: str = "automation:lock"

# Compare-and-delete: only release the key if the stored token matches
# the caller's marker. Guarantees a process cannot release a lock a
# peer acquired after the TTL expired.
_RELEASE_LUA: str = (
    "if redis.call('GET', KEYS[1]) == ARGV[1] then "
    "  return redis.call('DEL', KEYS[1]) "
    "else return 0 end"
)

# Errors that mean "Redis is not available right now" rather than a
# programming bug. RedisError covers ConnectionError / TimeoutError /
# ResponseError from redis-py; OSError covers underlying socket faults;
# RuntimeError comes from ``get_redis`` when the pool has not been
# initialised and no URL is configured (a common test-harness shape).
# The runner catches ``LockBackendUnavailable`` and degrades to the
# ``automation_run_records`` unique constraint as the fallback claim.
_UNAVAILABLE: tuple[type[BaseException], ...] = (RedisError, OSError, RuntimeError)


class LockBackendUnavailableError(RuntimeError):
    """Raised when the Redis backend cannot be reached at all.

    The caller MUST degrade to the DB-level unique-constraint claim on
    ``automation_run_records(schedule_id, occurrence_at)``; a raise here
    is never a fatal condition for the tick loop.
    """


class AutomationOccurrenceLock:
    """Handle returned by ``acquire_occurrence_lock``.

    Carries the release token so a peer that inherits the key after
    TTL expiry cannot be released by a stale winner.
    """

    __slots__ = ("key", "token")

    def __init__(self, key: str, token: str) -> None:
        self.key = key
        self.token = token


def occurrence_lock_key(schedule_id: str, occurrence_at: datetime) -> str:
    """Return the Redis key for a schedule occurrence.

    Two runner processes ticking the same schedule at the same
    occurrence MUST compute the same key. The bucket is the UTC epoch
    seconds of ``occurrence_at`` so wall-clock skew between processes
    only matters if it flips the cron ``get_prev`` result -- which is
    the same window the runner's due-check already tolerates.
    """
    if occurrence_at.tzinfo is None:
        occurrence_at = occurrence_at.replace(tzinfo=UTC)
    epoch = int(occurrence_at.astimezone(UTC).timestamp())
    return f"{_LOCK_KEY_PREFIX}:{schedule_id}:{epoch}"


def _process_marker() -> str:
    """Diagnostic value stored under the lock; also matched on release."""
    return f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"


async def acquire_occurrence_lock(
    schedule_id: str,
    occurrence_at: datetime,
    *,
    ttl_s: int = _LOCK_TTL_S,
) -> AutomationOccurrenceLock | None:
    """Try to acquire the distributed lock for a schedule occurrence.

    Returns the handle on win, ``None`` if another process already holds
    the key. Raises ``LockBackendUnavailableError`` when Redis is
    unreachable so the runner can route to the DB fallback path; every
    other exception propagates unchanged (a genuine bug should not be
    masked as a graceful degrade).
    """
    key = occurrence_lock_key(schedule_id, occurrence_at)
    # Fast-path degrade: when the shared pool has not been initialised
    # (production wires this at api/app.py lifespan BEFORE the runner
    # supervisor starts, so a live-pool absent here means the caller
    # never initialised Redis at all), skip the lock and let the DB
    # unique-constraint on automation_run_records serve as the barrier.
    # This also avoids ``get_redis``' auto-init side effect polluting
    # test suites that never wired Redis on purpose.
    if not pool_available():
        raise LockBackendUnavailableError(
            "redis lock backend unavailable: pool not initialised"
        )
    token = _process_marker()
    try:
        async with get_redis() as client:
            # NX = only set if the key does not exist; PX = TTL in ms.
            # redis-py returns True on success, None when NX rejected.
            ok = await client.set(key, token, nx=True, px=int(ttl_s * 1000))
    except _UNAVAILABLE as exc:
        # Redis pool went away between the pool_available() check and
        # the SET (or the SET itself failed): the runner treats this
        # as "degrade to DB unique constraint" -- it is not an
        # operational error, it is the documented fallback.
        raise LockBackendUnavailableError(
            f"redis lock backend unavailable: {type(exc).__name__}: {exc}"
        ) from exc
    if ok:
        return AutomationOccurrenceLock(key=key, token=token)
    return None


async def release_occurrence_lock(handle: AutomationOccurrenceLock) -> None:
    """Best-effort compare-and-delete release.

    Never raises: if Redis is momentarily unavailable at release time
    the TTL will expire the key. Explicitly logs the degrade so an
    operator investigating a stuck lock can see the release attempt
    failed rather than silently swallowing.
    """
    try:
        async with get_redis() as client:
            await client.eval(_RELEASE_LUA, 1, handle.key, handle.token)
    except _UNAVAILABLE as exc:
        # Backend gone at release time; TTL is the safety net. Log so
        # an operator investigating a stuck lock still sees the trail
        # instead of a silent pass-swallow.
        _log.info(
            "release_occurrence_lock: redis unavailable, TTL will expire key=%s reason=%s",
            handle.key,
            type(exc).__name__,
        )


@asynccontextmanager
async def occurrence_lock_scope(
    schedule_id: str,
    occurrence_at: datetime,
    *,
    ttl_s: int = _LOCK_TTL_S,
) -> AsyncIterator[AutomationOccurrenceLock | None]:
    """Async context manager wrapper around acquire + release.

    Yields the handle on win, ``None`` when a peer holds the lock (the
    caller MUST skip the occurrence). Raises
    ``LockBackendUnavailableError`` when Redis is down so the caller
    can route to the DB unique-constraint fallback.
    """
    handle = await acquire_occurrence_lock(
        schedule_id, occurrence_at, ttl_s=ttl_s,
    )
    try:
        yield handle
    finally:
        if handle is not None:
            await release_occurrence_lock(handle)
