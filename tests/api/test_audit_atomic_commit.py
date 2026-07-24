"""#52-3.2 audit-after-commit atomicity tests.

Design ref: ``.run/designs/DESIGN_audit_journal.md`` sec 3.2.

Proves the audit row and the business change share the same
transaction at each site that used to split them across two commits.
Two scenarios per site:

1. Happy path -- after the request handler runs, the business row
   is in its post-change state AND an AuditEventRecord row exists.
   Post-#52-3.2 both writes commit in a single transaction.
2. Failure path -- patch record_audit_event in the router module to
   raise BEFORE the commit; the pre-staged business write MUST roll
   back with it. The pre-fix flow committed the business change
   first and the audit row second, so this rollback was impossible;
   the test now guards against regression to that split.

Sites covered:
  * ``systems.delete_system`` -- shortest handler with an in-scope
    finding; its 204-No-Content contract makes row-present /
    row-absent assertions unambiguous.
  * ``auth.create_api_key`` -- extends coverage to the follow-up
    site fixed alongside ``update_system``/``delete_system``/
    ``_add_user_msg``. ApiKeyRecord.id is populated at construction
    (uuid default_factory) so the audit payload can reference it
    before commit -- no flush needed there, unlike the sequence-PK
    ManagedSystemRecord path in ``create_system``.
"""

from __future__ import annotations

import types
from uuid import uuid4

import pytest
from sqlmodel import select

from aila.api.auth import AuthContext
from aila.api.constants import (
    AUDIT_ACTION_CREATE_API_KEY,
    AUDIT_ACTION_SYSTEM_DELETE,
)
from aila.api.routers.auth import router as auth_router
from aila.api.routers.systems import router as systems_router
from aila.api.schemas.auth import ApiKeyCreateRequest
from aila.storage.database import async_session_scope
from aila.storage.db_models import (
    ApiKeyRecord,
    AuditEventRecord,
    ManagedSystemRecord,
)

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


# --------------------------------------------------------------------------
# auth.create_api_key -- follow-up site for #52-3.2. Same commit/audit/
# commit anti-pattern as revoke_api_key; a crash between the two commits
# used to persist the key with no audit trail. Post-fix both writes share
# one transaction.
# --------------------------------------------------------------------------


def _admin(team_id: str | None = None) -> AuthContext:
    """Build an AuthContext for the admin role. create_api_key requires
    admin+ per D-09; the require_role dependency is not resolved on
    direct endpoint invocation, so the AuthContext is passed explicitly.
    team_id defaults to None (admin/god-tier, TEAM-06)."""
    return AuthContext(
        user_id="u-admin-" + uuid4().hex[:8],
        role="admin",
        auth_type="user",
        team_id=team_id,
    )


async def _audit_events_for_create_target(target: str) -> list[AuditEventRecord]:
    """Return every ``create_api_key`` audit row whose target is ``target``."""
    async with async_session_scope() as session:
        stmt = select(AuditEventRecord).where(
            AuditEventRecord.action == AUDIT_ACTION_CREATE_API_KEY,
            AuditEventRecord.target == target,
        )
        return list((await session.exec(stmt)).all())


async def test_create_api_key_audit_and_row_share_transaction(test_db) -> None:
    """Happy path: after POST /auth/keys the ApiKeyRecord is persisted
    AND a matching create_api_key audit row exists. Post-#52-3.2 both
    writes commit atomically in a single transaction."""
    admin = _admin()
    create_api_key = _endpoint(auth_router, "/auth/keys", "POST")
    body = ApiKeyCreateRequest(role="reader", label="atomic-happy")

    response = await create_api_key(request=_req(), body=body, admin=admin)

    assert response.key_id
    assert response.raw_key.startswith("aila_sk_")

    async with async_session_scope() as session:
        row = await session.get(ApiKeyRecord, response.key_id)
    assert row is not None, "create_api_key must have persisted the row"
    assert row.role == "reader"
    assert row.label == "atomic-happy"

    events = await _audit_events_for_create_target(response.key_prefix)
    assert len(events) == 1, (
        "create_api_key must record exactly one create_api_key audit "
        f"event; got {len(events)}"
    )
    ev = events[0]
    assert ev.stage == "auth"
    assert ev.action == AUDIT_ACTION_CREATE_API_KEY
    assert ev.target == response.key_prefix
    assert ev.run_id == response.key_id
    assert ev.user_id == admin.user_id


async def test_create_api_key_audit_failure_rolls_back_row(
    test_db, monkeypatch
) -> None:
    """Failure path: if record_audit_event raises inside the handler,
    the pre-staged ApiKeyRecord insert MUST roll back with it.

    Pre-#52-3.2 the handler committed the record insert BEFORE
    record_audit_event ran; a raise there could not touch the
    already-committed row, so the key was persisted with no audit
    trail. Post-fix the audit call runs inside the same transaction
    as the record insert, so any raise before the single commit
    rolls both back together.

    The patch swaps record_audit_event at its import site inside the
    auth router module; the same-name symbol in
    ``aila.platform.services.audit`` is untouched, so unrelated
    callers still see the real writer.
    """
    admin = _admin()
    create_api_key = _endpoint(auth_router, "/auth/keys", "POST")
    body = ApiKeyCreateRequest(role="reader", label="atomic-fail")

    def _raise(*_args, **_kwargs) -> None:
        raise RuntimeError("simulated audit-write failure (#52-3.2 test)")

    monkeypatch.setattr("aila.api.routers.auth.record_audit_event", _raise)

    with pytest.raises(RuntimeError, match="simulated audit-write failure"):
        await create_api_key(request=_req(), body=body, admin=admin)

    async with async_session_scope() as session:
        stmt = select(ApiKeyRecord).where(ApiKeyRecord.label == "atomic-fail")
        rows = list((await session.exec(stmt)).all())
    assert rows == [], (
        "create_api_key must NOT have persisted the row when the audit "
        "write raised inside the same transaction -- #52-3.2 atomicity "
        f"broken (found {len(rows)} row(s) with label 'atomic-fail')"
    )

    async with async_session_scope() as session:
        stmt = select(AuditEventRecord).where(
            AuditEventRecord.action == AUDIT_ACTION_CREATE_API_KEY,
            AuditEventRecord.details_json.contains('"atomic-fail"'),
        )
        events = list((await session.exec(stmt)).all())
    assert events == [], (
        "no audit row must survive a rolled-back create -- "
        f"found {len(events)} with label 'atomic-fail'"
    )
