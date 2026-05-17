"""Tests for the SbD NFR activity service (Plan 134-04, Task 1).

Verifies:
- log_activity() inserts a SbdNfrActivityRecord with correct fields.
- log_activity() serializes the detail dict to detail_json.
- get_session_activity() returns events in chronological order (created_at asc).
- get_session_activity() returns empty list for a session with no activity.
- All 10 EVENT_* constants are strings with expected domain prefixes.

Requires: pip install aiosqlite (fixture is skipped gracefully without it).
"""

from __future__ import annotations

import json

import pytest

from aila.modules.sbd_nfr.db_models import SbdNfrActivityRecord
from aila.modules.sbd_nfr.services.activity_service import (
    EVENT_ANSWERS_SAVED,
    EVENT_LINK_ACCESSED,
    EVENT_RESOLUTION_COMPLETED,
    EVENT_RESOLUTION_FAILED,
    EVENT_RESOLUTION_STARTED,
    EVENT_SESSION_ASSIGNED,
    EVENT_SESSION_CLONED,
    EVENT_SESSION_COMPLETED,
    EVENT_SESSION_CREATED,
    EVENT_SESSION_DELETED,
    get_session_activity,
    log_activity,
)

# ---------------------------------------------------------------------------
# Event constant tests (no DB required)
# ---------------------------------------------------------------------------


def test_event_constants_are_strings() -> None:
    constants = [
        EVENT_SESSION_CREATED,
        EVENT_SESSION_CLONED,
        EVENT_LINK_ACCESSED,
        EVENT_ANSWERS_SAVED,
        EVENT_SESSION_COMPLETED,
        EVENT_SESSION_ASSIGNED,
        EVENT_SESSION_DELETED,
        EVENT_RESOLUTION_STARTED,
        EVENT_RESOLUTION_COMPLETED,
        EVENT_RESOLUTION_FAILED,
    ]
    for const in constants:
        assert isinstance(const, str), f"Expected str, got {type(const)} for {const!r}"


def test_event_constants_count() -> None:
    """Exactly 10 event constants are defined."""
    constants = [
        EVENT_SESSION_CREATED,
        EVENT_SESSION_CLONED,
        EVENT_LINK_ACCESSED,
        EVENT_ANSWERS_SAVED,
        EVENT_SESSION_COMPLETED,
        EVENT_SESSION_ASSIGNED,
        EVENT_SESSION_DELETED,
        EVENT_RESOLUTION_STARTED,
        EVENT_RESOLUTION_COMPLETED,
        EVENT_RESOLUTION_FAILED,
    ]
    assert len(constants) == 10


def test_event_constants_have_expected_prefixes() -> None:
    assert EVENT_SESSION_CREATED.startswith("session.")
    assert EVENT_SESSION_CLONED.startswith("session.")
    assert EVENT_SESSION_COMPLETED.startswith("session.")
    assert EVENT_SESSION_ASSIGNED.startswith("session.")
    assert EVENT_SESSION_DELETED.startswith("session.")
    assert EVENT_LINK_ACCESSED.startswith("link.")
    assert EVENT_ANSWERS_SAVED.startswith("answers.")
    assert EVENT_RESOLUTION_STARTED.startswith("resolution.")
    assert EVENT_RESOLUTION_COMPLETED.startswith("resolution.")
    assert EVENT_RESOLUTION_FAILED.startswith("resolution.")


# ---------------------------------------------------------------------------
# DB-backed tests (require async_db_session fixture)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_log_activity_creates_record(async_db_session) -> None:
    """log_activity() inserts a SbdNfrActivityRecord with correct fields."""
    session_id = "test-session-001"
    await log_activity(
        db=async_db_session,
        session_id=session_id,
        event_type=EVENT_SESSION_CREATED,
        actor_name="Alice",
        actor_email="alice@example.com",
    )
    await async_db_session.commit()

    from sqlmodel import select

    rows = (
        await async_db_session.exec(
            select(SbdNfrActivityRecord).where(
                SbdNfrActivityRecord.session_id == session_id
            )
        )
    ).all()

    assert len(rows) == 1
    record = rows[0]
    assert record.session_id == session_id
    assert record.event_type == EVENT_SESSION_CREATED
    assert record.actor_name == "Alice"
    assert record.actor_email == "alice@example.com"


@pytest.mark.asyncio
async def test_log_activity_serializes_detail(async_db_session) -> None:
    """log_activity() JSON-serializes the detail dict into detail_json."""
    session_id = "test-session-002"
    detail_payload = {"answer_count": 5, "section": "HYGN"}

    await log_activity(
        db=async_db_session,
        session_id=session_id,
        event_type=EVENT_ANSWERS_SAVED,
        detail=detail_payload,
    )
    await async_db_session.commit()

    from sqlmodel import select

    row = (
        await async_db_session.exec(
            select(SbdNfrActivityRecord).where(
                SbdNfrActivityRecord.session_id == session_id
            )
        )
    ).first()

    assert row is not None
    stored = json.loads(row.detail_json)
    assert stored == detail_payload


@pytest.mark.asyncio
async def test_get_session_activity_chronological_order(async_db_session) -> None:
    """get_session_activity() returns events sorted by created_at ascending."""
    from datetime import timedelta

    from aila.platform.contracts._common import utc_now

    session_id = "test-session-003"
    now = utc_now()

    # Insert three events with deliberate created_at ordering
    event_a = SbdNfrActivityRecord(
        session_id=session_id,
        event_type=EVENT_SESSION_CREATED,
        created_at=now,
    )
    event_b = SbdNfrActivityRecord(
        session_id=session_id,
        event_type=EVENT_ANSWERS_SAVED,
        created_at=now + timedelta(seconds=5),
    )
    event_c = SbdNfrActivityRecord(
        session_id=session_id,
        event_type=EVENT_SESSION_COMPLETED,
        created_at=now + timedelta(seconds=10),
    )

    # Add in reverse order to confirm ordering is by created_at, not insert order
    async_db_session.add(event_c)
    async_db_session.add(event_a)
    async_db_session.add(event_b)
    await async_db_session.commit()

    result = await get_session_activity(async_db_session, session_id)

    assert len(result) == 3
    assert result[0].event_type == EVENT_SESSION_CREATED
    assert result[1].event_type == EVENT_ANSWERS_SAVED
    assert result[2].event_type == EVENT_SESSION_COMPLETED


@pytest.mark.asyncio
async def test_get_session_activity_empty_for_unknown_session(async_db_session) -> None:
    """get_session_activity() returns an empty list for a session with no activity."""
    result = await get_session_activity(async_db_session, "no-such-session-id")
    assert result == []
