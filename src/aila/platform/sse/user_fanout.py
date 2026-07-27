"""Multi-subscriber SSE fan-out registry keyed by user id (issue #60-4).

The prior per-user SSE plumbing in ``aila.api.events`` stored ONE
``asyncio.Queue`` per user id and handed the same queue to every connection
for that user. Opening a second browser tab for the same user therefore
broke delivery in two ways:

- both tabs racing on the same queue meant each event went to only ONE tab
  (``Queue.get`` consumes), so half the tabs missed each event; and
- the first tab that closed called ``release_user_queue(user_id)`` which
  deleted the shared queue, leaving the still-open tab with an orphaned
  queue that no producer wrote to any more.

This module owns the platform-side fan-out primitive that replaces that
single-queue registry. Each ``subscribe(user_id)`` call returns a fresh
bounded queue registered under the user; ``emit(user_id, payload)``
fans out the payload to EVERY currently-subscribed queue for that user,
so each tab gets its own independent stream and all receive every event.
``unsubscribe(user_id, queue)`` removes just the caller's queue -- other
tabs stay live. When the last subscriber for a user drops, the user
entry is removed so long-disconnected users do not retain state.

Per-queue backpressure: each queue is bounded (default ``QUEUE_MAXSIZE``)
and ``emit`` drops -- with a warning -- when a specific tab's queue is
full. One slow tab CANNOT stall delivery to a sibling tab; every
subscriber has its own queue.

Threading model: all methods must be called from the same event loop
(asyncio primitives are not thread-safe). The internal ``asyncio.Lock``
serialises subscribe/unsubscribe against emit so a concurrent emit
never iterates a mutating list.
"""
from __future__ import annotations

import asyncio
import logging

__all__ = [
    "QUEUE_MAXSIZE",
    "UserFanoutRegistry",
]

_log = logging.getLogger(__name__)


QUEUE_MAXSIZE = 50


class UserFanoutRegistry:
    """Multi-subscriber fan-out registry: user id -> list of per-connection queues.

    Instantiated once per process (module callers keep a module-level
    singleton); every SSE connection ``subscribe`` s to get its own
    queue and ``unsubscribe`` s on disconnect. Producers call
    ``emit`` with the user id to reach every live connection for that
    user in one call. Cross-user isolation is total -- ``emit(u1, x)``
    never touches queues under ``u2``.
    """

    def __init__(self, queue_maxsize: int = QUEUE_MAXSIZE) -> None:
        if queue_maxsize <= 0:
            raise ValueError(
                f"queue_maxsize must be > 0 (got {queue_maxsize}); "
                "unbounded per-subscriber queues would leak memory on a stalled tab",
            )
        self._queue_maxsize = queue_maxsize
        # user_id -> list of live per-connection queues. list (not set) so the
        # subscription order is deterministic for tests and log messages, and
        # so a stale queue identity is easy to remove via list.remove.
        self._subscribers: dict[str, list[asyncio.Queue[str]]] = {}
        self._lock = asyncio.Lock()

    async def subscribe(self, user_id: str) -> asyncio.Queue[str]:
        """Register a new per-connection queue for ``user_id`` and return it.

        Every call returns a FRESH bounded queue; two tabs for the same
        user each get their own queue so they receive events
        independently. Callers MUST pair every ``subscribe`` with an
        ``unsubscribe`` (typically in a ``finally``) so a disconnected
        tab does not leak its queue for the process lifetime.
        """
        queue: asyncio.Queue[str] = asyncio.Queue(maxsize=self._queue_maxsize)
        async with self._lock:
            self._subscribers.setdefault(user_id, []).append(queue)
        return queue

    async def unsubscribe(self, user_id: str, queue: asyncio.Queue[str]) -> None:
        """Remove ``queue`` from ``user_id``'s subscriber list.

        Removing an unknown queue is a silent no-op so double-unsubscribe
        on the disconnect path is safe. When the last queue for a user
        is removed the user entry itself is deleted so an idle user does
        not retain registry state.
        """
        async with self._lock:
            queues = self._subscribers.get(user_id)
            if queues is None:
                return
            if queue in queues:
                queues.remove(queue)
            if not queues:
                self._subscribers.pop(user_id, None)

    async def emit(self, user_id: str, payload: str) -> int:
        """Deliver ``payload`` to every live subscriber queue for ``user_id``.

        Returns the number of queues the payload reached. A queue whose
        capacity is exhausted is skipped with a WARNING log so one slow
        tab does not backpressure delivery to sibling tabs and does not
        stall the caller. A user with no live subscribers is a silent
        no-op returning 0 -- producers do not need to know whether a
        tab is currently attached.
        """
        # Snapshot under the lock so a concurrent (un)subscribe cannot
        # mutate the list mid-iteration. ``put_nowait`` on each snapshot
        # entry is safe outside the lock because asyncio.Queue methods
        # are event-loop-atomic.
        async with self._lock:
            queues = list(self._subscribers.get(user_id, ()))
        delivered = 0
        for queue in queues:
            try:
                queue.put_nowait(payload)
            except asyncio.QueueFull:
                _log.warning(
                    "SSE fan-out: subscriber queue full for user %s "
                    "(maxsize=%d); dropping payload for this tab",
                    user_id,
                    self._queue_maxsize,
                )
                continue
            delivered += 1
        return delivered

    async def subscriber_count(self, user_id: str) -> int:
        """Return the number of live subscribers for ``user_id``.

        Test and telemetry hook; production code should not branch on
        this value.
        """
        async with self._lock:
            queues = self._subscribers.get(user_id)
            return 0 if queues is None else len(queues)

    async def user_count(self) -> int:
        """Return the number of distinct users with at least one live subscriber.

        Test and telemetry hook; the operator-visible SSE gauge lives at
        ``aila.api.metrics``.
        """
        async with self._lock:
            return len(self._subscribers)
