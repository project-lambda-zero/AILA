"""#114 -- automation schedule update/delete must not leak existence.

Before the fix ``update_schedule`` and ``delete_schedule`` loaded the row via
``session.get()`` (identity-map fast path bypasses the do_orm_execute team
filter) and raised 403 on team mismatch. That combination is a cross-tenant
existence oracle: a caller could distinguish "row owned by another team"
(403) from "does not exist" (404).

The handlers now:
  * scope the SELECT by team_id when the caller is team-scoped, and
  * raise 404 on either miss.

God-tier admins (team_id=None) skip the where-clause and continue to see
every team's rows.

Handlers are invoked directly with an explicit AuthContext; the router's
``require_user_or_api_key`` and ``limiter`` decorators are not resolved on
direct invocation, but the body's SELECT + 404 semantics are exactly what
this suite exercises.
"""
from __future__ import annotations

from uuid import uuid4

import pytest
from fastapi import HTTPException, Request
from sqlmodel import select

from aila.api.auth import AuthContext
from aila.api.routers.automation import delete_schedule, update_schedule
from aila.api.schemas.automation import AutomationScheduleUpdate
from aila.platform.automation.models import AutomationScheduleRecord
from aila.storage.database import async_session_scope


def _auth(team_id: str | None, role: str = "operator") -> AuthContext:
    return AuthContext(user_id=f"u-{team_id}", role=role, auth_type="user", team_id=team_id)


def _fake_request() -> Request:
    """A minimal ASGI scope for handlers that accept ``request: Request``.

    The direct-invocation path never touches the slowapi limiter, so the
    scope only needs the fields FastAPI's Request wrapper reads on
    construction.
    """
    return Request(
        {
            "type": "http",
            "method": "POST",
            "path": "/",
            "headers": [],
            "query_string": b"",
            "client": ("127.0.0.1", 0),
        }
    )


async def _insert_schedule(*, team_id: str) -> str:
    """Insert one AutomationScheduleRecord owned by team_id and return its id."""
    suffix = uuid4().hex[:8]
    schedule_id = f"sched-{team_id}-{suffix}"
    async with async_session_scope() as session:
        rec = AutomationScheduleRecord(
            id=schedule_id,
            action_id="tests.action",
            target_name=f"target-{suffix}",
            cron_expression="* * * * *",
            action_kwargs_json="{}",
            enabled=True,
            created_by="tests",
        )
        rec.team_id = team_id  # type: ignore[attr-defined]
        session.add(rec)
        await session.commit()
    return schedule_id


async def _row_exists(schedule_id: str) -> bool:
    """Read the row via an admin session (no team filter) to check existence."""
    async with async_session_scope() as session:
        row = (await session.exec(
            select(AutomationScheduleRecord).where(
                AutomationScheduleRecord.id == schedule_id
            )
        )).first()
        return row is not None


@pytest.mark.usefixtures("test_db")
async def test_update_cross_team_returns_404_not_403() -> None:
    schedule_id = await _insert_schedule(team_id="team-a")
    # team-b caller must observe a 404 -- identical to "does not exist".
    with pytest.raises(HTTPException) as excinfo:
        await update_schedule(
            request=_fake_request(),
            schedule_id=schedule_id,
            body=AutomationScheduleUpdate(enabled=False),
            auth=_auth("team-b"),
        )
    assert excinfo.value.status_code == 404
    # The row must still exist -- the guard rejected before mutation.
    assert await _row_exists(schedule_id)


@pytest.mark.usefixtures("test_db")
async def test_delete_cross_team_returns_404_not_403() -> None:
    schedule_id = await _insert_schedule(team_id="team-a")
    with pytest.raises(HTTPException) as excinfo:
        await delete_schedule(
            request=_fake_request(),
            schedule_id=schedule_id,
            auth=_auth("team-b"),
        )
    assert excinfo.value.status_code == 404
    assert await _row_exists(schedule_id), "cross-team delete must not touch the row"


@pytest.mark.usefixtures("test_db")
async def test_update_missing_id_returns_404() -> None:
    with pytest.raises(HTTPException) as excinfo:
        await update_schedule(
            request=_fake_request(),
            schedule_id="does-not-exist",
            body=AutomationScheduleUpdate(enabled=False),
            auth=_auth("team-b"),
        )
    assert excinfo.value.status_code == 404


@pytest.mark.usefixtures("test_db")
async def test_delete_owning_team_succeeds() -> None:
    schedule_id = await _insert_schedule(team_id="team-a")
    await delete_schedule(
        request=_fake_request(),
        schedule_id=schedule_id,
        auth=_auth("team-a"),
    )
    assert not await _row_exists(schedule_id)


@pytest.mark.usefixtures("test_db")
async def test_delete_admin_sees_every_team() -> None:
    """God-tier admin (team_id=None) can delete any team's schedule."""
    schedule_id = await _insert_schedule(team_id="team-a")
    await delete_schedule(
        request=_fake_request(),
        schedule_id=schedule_id,
        auth=_auth(None, role="admin"),
    )
    assert not await _row_exists(schedule_id)
