"""#52-3.2 audit-after-commit atomicity tests.

Design ref: ``.run/designs/DESIGN_audit_journal.md`` sec 3.2.

Proves the audit row and the business change share the same
transaction at the systems.py delete_system site. Two scenarios:

1. Happy path -- after DELETE /systems/{id} both the business row is
   gone AND an AuditEventRecord row exists. Post-#52-3.2 both writes
   commit in a single transaction.
2. Failure path -- patch record_audit_event in the router module to
   raise BEFORE the commit; the pre-staged session.delete MUST roll
   back with it. The pre-fix flow committed the delete first and the
   audit row second, so this rollback was impossible; the test now
   guards against regression to that split.

The systems delete site was picked for the acceptance test because
it is the shortest handler with an in-scope audit-after-commit
finding, and its 204-No-Content contract makes the row-present /
row-absent assertions unambiguous.
"""

from __future__ import annotations

import types
from uuid import uuid4

import pytest
from sqlmodel import select

from aila.api.auth import AuthContext
from aila.api.constants import AUDIT_ACTION_SYSTEM_DELETE
from aila.api.routers.systems import router as systems_router
from aila.storage.database import async_session_scope
from aila.storage.db_models import AuditEventRecord, ManagedSystemRecord

__all__: list[str] = []

pytestmark = pytest.mark.asyncio


def _req() -> object:
    """Minimal request stub -- delete_system does not touch app.state."""
    return types.SimpleNamespace(
        app=types.SimpleNamespace(state=types.SimpleNamespace(platform=None))
    )


def _auth(team_id: str, role: str = "operator") -> AuthContext:
    """Build an AuthContext for a given team. delete_system requires
    operator+ per D-07; the require_role dependency is not resolved on
    direct endpoint invocation, so the AuthContext is passed explicitly."""
    return AuthContext(
        user_id="u-" + team_id, role=role, auth_type="user", team_id=team_id
    )


def _endpoint(router: object, path: str, method: str):
    """Locate a route's underlying async endpoint callable by path+method."""
    for route in router.routes:
        if getattr(route, "path", None) == path and method in getattr(
            route, "methods", set()
        ):
            return route.endpoint
    raise AssertionError(f"route {method} {path} not registered")


async def _seed_system(team_id: str) -> tuple[int, str]:
    """Insert one ManagedSystemRecord for ``team_id``. Returns (id, name).

    Team is included so the do_orm_execute filter accepts subsequent reads
    from the same team. Name uses a uuid suffix for the unique-name index.
    """
    suffix = uuid4().hex[:8]
    name = f"sys-audit-{suffix}"
    async with async_session_scope() as session:
        record = ManagedSystemRecord(
            team_id=team_id,
            name=name,
            host="10.0.0.1",
            username="u",
        )
        session.add(record)
        await session.commit()
        await session.refresh(record)
        return record.id, record.name


async def _audit_events_for_delete_target(target: str) -> list[AuditEventRecord]:
    """Return every ``system_delete`` audit row whose target is ``target``."""
    async with async_session_scope() as session:
        stmt = select(AuditEventRecord).where(
            AuditEventRecord.action == AUDIT_ACTION_SYSTEM_DELETE,
            AuditEventRecord.target == target,
        )
        return list((await session.exec(stmt)).all())


async def test_delete_system_audit_and_row_share_transaction(test_db) -> None:
    """Happy path: after DELETE /systems/{id} the row is gone AND an
    AuditEventRecord for that target exists. Post-#52-3.2 both writes
    commit atomically in a single transaction."""
    team = f"team-{uuid4().hex[:8]}"
    system_id, system_name = await _seed_system(team)

    delete_system = _endpoint(systems_router, "/systems/{system_id}", "DELETE")
    result = await delete_system(
        request=_req(), system_id=system_id, auth=_auth(team)
    )
    assert result is None  # 204 No Content

    async with async_session_scope() as session:
        remaining = await session.get(ManagedSystemRecord, system_id)
    assert remaining is None, "delete_system must have removed the row"

    events = await _audit_events_for_delete_target(system_name)
    assert len(events) == 1, (
        "delete_system must record exactly one system_delete audit event; "
        f"got {len(events)}"
    )
    ev = events[0]
    assert ev.stage == "system"
    assert ev.action == AUDIT_ACTION_SYSTEM_DELETE
    assert ev.target == system_name
    assert ev.run_id == str(system_id)


async def test_delete_system_audit_failure_rolls_back_row(
    test_db, monkeypatch
) -> None:
    """Failure path: if record_audit_event raises inside the handler, the
    session.delete MUST roll back with it.

    Pre-#52-3.2 the handler committed the delete BEFORE record_audit_event
    ran; a raise there could not touch the already-committed delete, so
    the row was gone with no audit trail. Post-fix the audit call runs
    inside the same transaction as the delete, so any raise before the
    single commit rolls both back together.

    The patch swaps record_audit_event at its import site inside the
    systems router module; the same-name symbol in
    ``aila.platform.services.audit`` is untouched, so unrelated callers
    still see the real writer.
    """
    team = f"team-{uuid4().hex[:8]}"
    system_id, system_name = await _seed_system(team)

    def _raise(*_args, **_kwargs) -> None:
        raise RuntimeError("simulated audit-write failure (#52-3.2 test)")

    monkeypatch.setattr("aila.api.routers.systems.record_audit_event", _raise)

    delete_system = _endpoint(systems_router, "/systems/{system_id}", "DELETE")
    with pytest.raises(RuntimeError, match="simulated audit-write failure"):
        await delete_system(
            request=_req(), system_id=system_id, auth=_auth(team)
        )

    async with async_session_scope() as session:
        row = await session.get(ManagedSystemRecord, system_id)
    assert row is not None, (
        "delete_system must NOT have removed the row when the audit write "
        "raised inside the same transaction -- #52-3.2 atomicity broken"
    )

    events = await _audit_events_for_delete_target(system_name)
    assert events == [], (
        "no audit row must survive a rolled-back delete -- "
        f"found {len(events)} for target {system_name!r}"
    )
