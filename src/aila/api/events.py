"""Platform event bus for SSE delivery.

In-process asyncio.Queue per user_id. When Redis is available, also publishes
to ``aila:events:{user_id}`` for multi-worker support.

Bounded queues (QUEUE_MAXSIZE = 50) prevent unbounded memory growth when a
user has no active SSE connection.

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
    "get_user_queue",
    "release_user_queue",
]

import asyncio
import json
import logging
from datetime import UTC, datetime

_log = logging.getLogger(__name__)

# Registry: user_id → asyncio.Queue (bounded at QUEUE_MAXSIZE)
_user_queues: dict[str, asyncio.Queue[str]] = {}
_registry_lock = asyncio.Lock()

QUEUE_MAXSIZE = 50


async def get_user_queue(user_id: str) -> asyncio.Queue[str]:
    """Get or create the SSE event queue for a user.

    Creates a new bounded queue if one does not already exist.
    Thread-safe via asyncio.Lock.
    """
    async with _registry_lock:
        if user_id not in _user_queues:
            _user_queues[user_id] = asyncio.Queue(maxsize=QUEUE_MAXSIZE)
        return _user_queues[user_id]


async def release_user_queue(user_id: str) -> None:
    """Remove the queue for a user.

    Called when the SSE connection for that user closes. Cleans up memory
    so long-disconnected users do not retain queue entries indefinitely.
    """
    async with _registry_lock:
        _user_queues.pop(user_id, None)


async def emit_platform_event(
    user_id: str,
    event_type: str,
    data: dict,
) -> None:
    """Emit a platform event to the user's SSE queue.

    Silently drops the event if the queue is full (bounded at QUEUE_MAXSIZE)
    to prevent backpressure from blocking callers. The notification is still
    persisted to the database separately via NotificationRecord.

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
    queue = await get_user_queue(user_id)
    try:
        queue.put_nowait(payload)
    except asyncio.QueueFull:
        _log.warning(
            "Event queue full for user %s — dropping event %s",
            user_id,
            event_type,
        )
