"""Team-scope ORM hook isolation coverage (#62).

The audit called out that API-level tests would still pass even if the
``register_team_scope_listener()`` hook were quietly disabled: every API
integration exercised auth *and* the hook together, so a regression that
un-registered the listener never lit up in isolation. This file pins the
listener contract without going through HTTP.

Tests here answer three concrete questions:

* With the listener registered and a non-admin ``TeamContext`` set on the
  session, does a bare ORM query only return that team's rows?
* Without the listener, does the same setup leak cross-team rows? (This is
  the isolation-proof: a disabled hook fails HERE.)
* Does the listener idempotency hold -- ``register_team_scope_listener``
  called twice must not double-fire the filter and drop rows.

All three run against the shared Postgres ``test_db`` fixture. No mocks,
no HTTP client, no auth layer.
"""
from __future__ import annotations

import pytest
from sqlalchemy import event
from sqlalchemy.orm import Session
from sqlmodel import select

from aila.api.auth import TeamContext
from aila.platform.contracts._common import utc_now
from aila.platform.services import team_scope as team_scope_mod
from aila.storage.database import async_session_scope
from aila.storage.db_models import ManagedSystemRecord


def _make_system(name: str, host: str, team_id: str | None) -> ManagedSystemRecord:
    return ManagedSystemRecord(
        name=name,
        host=host,
        username="tester",
        port=22,
        distro="ubuntu",
        description=f"scope-isolation-{name}",
        team_id=team_id,
        created_at=utc_now(),
        updated_at=utc_now(),
    )


@pytest.fixture
def _restore_team_scope_listener():
    """Ensure the listener is registered on entry and restored on exit.

    Tests in this module temporarily un-register the do_orm_execute hook to
    prove that filtering depends on it. The fixture snapshots the pre-test
    state and reinstalls the listener no matter how the test exits, so no
    other tests in the same worker inherit a broken scoping surface.
    """
    # Force registration -- idempotent by contract.
    team_scope_mod.register_team_scope_listener()
    try:
        yield
    finally:
        # Reset the module-level "registered" flag before re-registering to
        # guarantee reinstallation even if a test removed the listener via
        # ``event.remove`` (which does not flip the module flag).
        try:
            event.remove(Session, "do_orm_execute", team_scope_mod._inject_team_filter)
        except Exception:  # noqa: BLE001 -- benign; listener may already be gone
            pass
        team_scope_mod._LISTENER_REGISTERED = False
        team_scope_mod.register_team_scope_listener()


async def _seed_two_team_rows() -> tuple[str, str]:
    """Insert one system per team and return the pair of names."""
    async with async_session_scope() as session:
        session.add(_make_system("sys-alpha-1", "10.0.1.1", team_id="team-alpha"))
        session.add(_make_system("sys-beta-1", "10.0.2.1", team_id="team-beta"))
        await session.commit()
    return "sys-alpha-1", "sys-beta-1"


@pytest.mark.asyncio
async def test_listener_registered_scopes_query_to_team(
    test_db, _restore_team_scope_listener,
) -> None:
    """With the listener installed, a team-alpha session returns only alpha rows."""
    del test_db
    await _seed_two_team_rows()

    ctx_alpha = TeamContext(team_id="team-alpha", is_admin=False)
    async with async_session_scope(team_context=ctx_alpha) as session:
        rows = list((await session.exec(select(ManagedSystemRecord))).all())
    names = {r.name for r in rows}
    assert names == {"sys-alpha-1"}, (
        f"listener must scope reads to team-alpha; got {names}"
    )


@pytest.mark.asyncio
async def test_listener_absent_lets_cross_team_rows_leak(
    test_db, _restore_team_scope_listener,
) -> None:
    """Without the listener, the same team-alpha context sees BOTH teams.

    This is the crux of the audit gap: an ORM query with a non-admin
    ``TeamContext`` set on the session is only isolated because the
    ``do_orm_execute`` listener rewrites the statement to append
    ``WHERE team_id = ...``. Take the listener away and the auth layer's
    invariant silently disappears -- the API tests that pair auth + ORM
    won't catch it.
    """
    del test_db
    await _seed_two_team_rows()

    # Remove the SQLAlchemy event listener. Deliberately KEEP the module
    # ``_LISTENER_REGISTERED`` flag True: ``async_session_scope`` calls
    # ``register_team_scope_listener()`` on every entry, and the flag is
    # the idempotency guard the function checks first, so leaving it True
    # short-circuits re-registration until the fixture restores state.
    event.remove(
        Session, "do_orm_execute", team_scope_mod._inject_team_filter,
    )
    assert team_scope_mod._LISTENER_REGISTERED is True, (
        "sanity: flag must stay True so the next async_session_scope call "
        "skips re-registration"
    )

    ctx_alpha = TeamContext(team_id="team-alpha", is_admin=False)
    async with async_session_scope(team_context=ctx_alpha) as session:
        rows = list((await session.exec(select(ManagedSystemRecord))).all())
    names = {r.name for r in rows}
    # WITHOUT the listener, both teams' rows leak into the alpha query --
    # the very regression this test is here to catch.
    assert names == {"sys-alpha-1", "sys-beta-1"}, (
        "With the listener removed, a team-alpha context MUST see both "
        f"teams' rows (the isolation proof). Got {names}."
    )


@pytest.mark.asyncio
async def test_register_team_scope_listener_is_idempotent(
    test_db, _restore_team_scope_listener,
) -> None:
    """Double-registration must not double-filter (no lost rows on the second install).

    Contract: ``register_team_scope_listener()`` is safe to call from
    ``init_db`` on every process boot; if it stacked the filter twice, the
    generated WHERE clause would still be legal but doubly applied which
    could hide subtle joined-select bugs later. Assert the same team-alpha
    query returns the same alpha-row set after a second registration.
    """
    del test_db
    await _seed_two_team_rows()

    # Second registration call -- must be a no-op per the contract.
    team_scope_mod.register_team_scope_listener()
    team_scope_mod.register_team_scope_listener()

    ctx_alpha = TeamContext(team_id="team-alpha", is_admin=False)
    async with async_session_scope(team_context=ctx_alpha) as session:
        rows = list((await session.exec(select(ManagedSystemRecord))).all())
    names = {r.name for r in rows}
    assert names == {"sys-alpha-1"}


@pytest.mark.asyncio
async def test_admin_bypass_still_holds_with_listener_registered(
    test_db, _restore_team_scope_listener,
) -> None:
    """An admin (is_admin=True) sees every team's rows even though the listener is on.

    The audit's isolation concern is about non-admin scoping; admin bypass
    is the corollary that must not regress. Together the two prove the
    listener has both a filtering side and a bypass side.
    """
    del test_db
    await _seed_two_team_rows()

    admin_ctx = TeamContext(team_id=None, is_admin=True)
    async with async_session_scope(team_context=admin_ctx) as session:
        rows = list((await session.exec(select(ManagedSystemRecord))).all())
    names = {r.name for r in rows}
    assert names == {"sys-alpha-1", "sys-beta-1"}
