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

Event types delivered on ``GET /events/stream`` (the SSE ``event:`` line and
the JSON ``type`` key carry the same value):

``notification``
    A persisted NotificationRecord the user should see.
``scan_complete`` / ``finding_arrived`` / ``sbd_complete`` /
``system_unreachable``
    Vulnerability and system lifecycle notices.
``investigation.status_changed``
    An investigation's ``status`` column changed and the write committed.
    ``data`` is ``{module, investigation_id, status, previous_status}``
    (``previous_status`` is null for a newly created row). Produced by
    :func:`install_investigation_status_forwarder` from the
    ``entity.status_changed`` domain event, so writes made in worker
    processes arrive through the Redis domain-event bridge. Delivered to
    every active user of the investigation's team (primary team or team
    membership) and to god-tier admins (users without a team).
"""
from __future__ import annotations

__all__ = [
    "INVESTIGATION_STATUS_CHANGED",
    "QUEUE_MAXSIZE",
    "emit_platform_event",
    "install_investigation_status_forwarder",
    "investigation_status_recipients",
    "subscribe_user",
    "uninstall_investigation_status_forwarder",
    "unsubscribe_user",
]

import asyncio
import json
import logging
from concurrent.futures import Future
from datetime import UTC, datetime

from sqlalchemy import or_
from sqlmodel import select

from ..platform.events.bus import subscribe as bus_subscribe
from ..platform.events.bus import unsubscribe as bus_unsubscribe
from ..platform.events.domain_events import DomainEvent, EntityStatusChanged
from ..platform.sse import QUEUE_MAXSIZE, UserFanoutRegistry
from ..storage.database import async_session_scope
from ..storage.db_models import TeamMemberRecord, UserRecord

INVESTIGATION_STATUS_CHANGED = "investigation.status_changed"

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


async def investigation_status_recipients(team_id: str | None) -> list[str]:
    """Return the user ids that may see an investigation owned by ``team_id``.

    Active users whose primary team is ``team_id``, active members of that
    team via TeamMemberRecord, and god-tier admins (``team_id`` NULL,
    TEAM-06) who see every team's data. A NULL-team investigation reaches
    god-tier admins only.
    """
    scope = [UserRecord.team_id.is_(None)]  # type: ignore[union-attr]
    if team_id is not None:
        scope.append(UserRecord.team_id == team_id)
        scope.append(
            UserRecord.id.in_(  # type: ignore[attr-defined]
                select(TeamMemberRecord.user_id).where(TeamMemberRecord.team_id == team_id),
            ),
        )
    async with async_session_scope() as session:
        rows = await session.exec(
            select(UserRecord.id).where(UserRecord.is_active.is_(True), or_(*scope)),  # type: ignore[attr-defined]
        )
        return sorted(set(rows.all()))


async def _deliver_investigation_status(event: EntityStatusChanged) -> None:
    payload = event.payload
    data = {
        "module": payload.module_id,
        "investigation_id": payload.entity_id,
        "status": payload.status,
        "previous_status": payload.previous_status,
    }
    for user_id in await investigation_status_recipients(event.team_id):
        await emit_platform_event(user_id, INVESTIGATION_STATUS_CHANGED, data)


_forwarder_loop: asyncio.AbstractEventLoop | None = None


def _forward_investigation_status(event: DomainEvent) -> None:
    """DomainEventBus subscriber: push investigation status changes to SSE.

    Runs on whatever thread published (request handler, consumer task,
    worker thread), so delivery is handed to the API event loop that owns
    the SSE queues.
    """
    if not isinstance(event, EntityStatusChanged) or event.payload.entity_kind != "investigation":
        return
    loop = _forwarder_loop
    if loop is None or loop.is_closed():
        return
    future = asyncio.run_coroutine_threadsafe(_deliver_investigation_status(event), loop)

    def _log_failure(done: Future[None]) -> None:
        if not done.cancelled() and (exc := done.exception()) is not None:
            _log.warning(
                "investigation status push failed for %s: %s",
                event.payload.entity_id,
                exc,
            )

    future.add_done_callback(_log_failure)


def install_investigation_status_forwarder() -> None:
    """Subscribe the SSE forwarder to the domain event bus (idempotent).

    MUST be called from the API process's running event loop (the FastAPI
    lifespan hook); that loop owns every SSE subscriber queue.
    """
    global _forwarder_loop
    loop = asyncio.get_running_loop()
    if _forwarder_loop is None:
        bus_subscribe("sse_investigation_status", _forward_investigation_status)
    _forwarder_loop = loop


def uninstall_investigation_status_forwarder() -> None:
    """Detach the SSE forwarder (lifespan shutdown and test teardown)."""
    global _forwarder_loop
    bus_unsubscribe(_forward_investigation_status)
    _forwarder_loop = None
