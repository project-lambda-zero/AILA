"""Activity logging service for SbD NFR sessions.

Provides append-only activity log write and read operations.  All session
lifecycle events are recorded here so the frontend can render a chronological
audit timeline.

Design references: D-65 (activity log schema), D-66 (activity timeline read),
D-67 (INFO-level operation logging).

Each public function manages its own database session via UnitOfWork.
Private helpers (underscore-prefixed) accept a db session from the caller
for within-transaction atomicity (used by resolution_service).
"""

from __future__ import annotations

import json
import logging
from uuid import uuid4

from sqlmodel import select

from aila.platform.contracts._common import utc_now
from aila.platform.uow import UnitOfWork

from ..contracts.stats import ActivityResponse
from ..db_models import SbdNfrActivityRecord

_log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Event type constants (D-65)
# ---------------------------------------------------------------------------

EVENT_SESSION_CREATED = "session.created"
EVENT_SESSION_CLONED = "session.cloned"
EVENT_LINK_ACCESSED = "link.accessed"
EVENT_ANSWERS_SAVED = "answers.saved"
EVENT_SESSION_COMPLETED = "session.completed"
EVENT_SESSION_ASSIGNED = "session.assigned"
EVENT_SESSION_DELETED = "session.deleted"
EVENT_RESOLUTION_STARTED = "resolution.started"
EVENT_RESOLUTION_COMPLETED = "resolution.completed"
EVENT_RESOLUTION_FAILED = "resolution.failed"

__all__ = [
    "EVENT_SESSION_CREATED",
    "EVENT_SESSION_CLONED",
    "EVENT_LINK_ACCESSED",
    "EVENT_ANSWERS_SAVED",
    "EVENT_SESSION_COMPLETED",
    "EVENT_SESSION_ASSIGNED",
    "EVENT_SESSION_DELETED",
    "EVENT_RESOLUTION_STARTED",
    "EVENT_RESOLUTION_COMPLETED",
    "EVENT_RESOLUTION_FAILED",
    "log_activity",
    "get_session_activity",
]


async def _log_activity_with_db(
    db: object,
    session_id: str,
    event_type: str,
    actor_name: str | None = None,
    actor_email: str | None = None,
    detail: dict | None = None,
) -> None:
    """Insert a new SbdNfrActivityRecord using an existing db session (private helper).

    Used by resolution_service which manages its own UnitOfWork and needs
    activity logging within the same transaction.

    Activity records are append-only; this function never modifies existing rows.
    """
    detail_payload = detail or {}
    record = SbdNfrActivityRecord(
        id=str(uuid4()),
        session_id=session_id,
        event_type=event_type,
        actor_name=actor_name,
        actor_email=actor_email,
        detail_json=json.dumps(detail_payload),
        created_at=utc_now(),
    )
    db.add(record)
    await db.flush()
    _log.info(
        "sbd_nfr: activity logged session_id=%s event_type=%s",
        session_id,
        event_type,
    )


async def log_activity(
    db: object,
    session_id: str,
    event_type: str,
    actor_name: str | None = None,
    actor_email: str | None = None,
    detail: dict | None = None,
) -> None:
    """Insert a new SbdNfrActivityRecord for the given session.

    Activity records are append-only; this function never modifies existing rows.
    The detail dict is JSON-serialized into the detail_json column.

    Per D-67: logs at INFO level for all write operations.

    NOTE: This function retains its db parameter because resolution_service
    calls it within its own UnitOfWork transaction for atomicity.  Callers
    that do not have a db session should use the sessionless variant or
    open their own UnitOfWork.

    Args:
        db: Active async session (must not be closed by this function).
        session_id: The session this event belongs to.
        event_type: One of the EVENT_* constants in this module.
        actor_name: Display name of the person who triggered the event.
        actor_email: Email of the actor.
        detail: Optional dict of event-specific metadata.
    """
    await _log_activity_with_db(
        db,
        session_id=session_id,
        event_type=event_type,
        actor_name=actor_name,
        actor_email=actor_email,
        detail=detail,
    )


async def get_session_activity(
    db: object,
    session_id: str,
) -> list[ActivityResponse]:
    """Return the chronological activity log for a session (D-66).

    Events are ordered by created_at ascending so the timeline reads
    oldest-first.  Returns an empty list when the session has no recorded
    activity.

    NOTE: This function retains its db parameter because api_router passes
    a session obtained from _verify_session_read_access's UnitOfWork context.

    Args:
        db: Active async session.
        session_id: The session to fetch activity for.

    Returns:
        List of ActivityResponse sorted by created_at ascending.
    """
    records = (await db.exec(
        select(SbdNfrActivityRecord)
        .where(SbdNfrActivityRecord.session_id == session_id)
        .order_by(SbdNfrActivityRecord.created_at)
    )).all()

    result: list[ActivityResponse] = []
    for row in records:
        try:
            detail_dict: dict = json.loads(row.detail_json) if row.detail_json else {}
        except (json.JSONDecodeError, TypeError):
            detail_dict = {}
        result.append(
            ActivityResponse(
                event_type=row.event_type,
                actor_name=row.actor_name,
                actor_email=row.actor_email,
                detail=detail_dict,
                created_at=row.created_at,
            )
        )
    return result
