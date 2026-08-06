"""Platform event bus for SSE delivery.

Per-connection ``asyncio.Queue`` via a process-wide
:class:`aila.platform.sse.UserFanoutRegistry` keyed by user id, so multiple
browser tabs for one user each get an independent stream and every tab
receives every event. Bounded queues (``QUEUE_MAXSIZE``) prevent unbounded
memory growth when a tab stalls.

Usage::

    from aila.api.events import emit_platform_event

    await emit_platform_event(
        user_id="abc123",
        event_type="scan_complete",
        data={"run_id": "xyz", "status": "done"},
    )
"""
from __future__ import annotations

__all__ = [
    "QUEUE_MAXSIZE",
    "emit_platform_event",
    "subscribe_user",
    "unsubscribe_user",
]

import asyncio
import json
import logging
from datetime import UTC, datetime

from ..platform.sse import QUEUE_MAXSIZE, UserFanoutRegistry

_log = logging.getLogger(__name__)

# Process-wide fan-out registry: user_id -> live per-connection queues.
_registry = UserFanoutRegistry(queue_maxsize=QUEUE_MAXSIZE)


async def subscribe_user(user_id: str) -> asyncio.Queue[str]:
    """Register a fresh per-connection SSE queue for a user and return it.

    Each call returns an independent bounded queue, so a second browser tab
    for the same user gets its own queue and receives every event. Callers
    MUST pair this with :func:`unsubscribe_user` in a ``finally``.
    """
    return await _registry.subscribe(user_id)


async def unsubscribe_user(user_id: str, queue: asyncio.Queue[str]) -> None:
    """Remove a single connection's queue when its SSE stream closes.

    Sibling tabs for the same user stay live; the user entry is dropped only
    when its last subscriber disconnects.
    """
    await _registry.unsubscribe(user_id, queue)


async def emit_platform_event(
    user_id: str,
    event_type: str,
    data: dict,
) -> None:
    """Emit a platform event to every live SSE connection for a user.

    A tab whose bounded queue is full is skipped with a warning so one slow
    tab does not backpressure siblings or the caller. The notification is
    still persisted to the database separately via NotificationRecord.

    Args:
        user_id: The target user's ID.
        event_type: One of ``notification``, ``scan_complete``, ``finding_arrived``,
            ``sbd_complete``, ``system_unreachable``, ``ping``.
        data: Arbitrary JSON-serialisable dict with event-specific payload.
    """
    payload = json.dumps(
        {
            "type": event_type,
            "data": data,
            "user_id": user_id,
            "timestamp": datetime.now(UTC).isoformat(),
        }
    )
    await _registry.emit(user_id, payload)
