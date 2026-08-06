"""RFC-11 Tier C -- unit tests for the zero-trust catalog gate.

Covers the trust-gate layer added by migration 118 on the existing
:class:`McpInstanceCatalog` from RFC-11 step 1: every new row defaults
to :attr:`McpApprovalState.PENDING`, the ``approved_only=True`` filter
on both :meth:`McpInstanceCatalog.list_instances` and
:meth:`McpInstanceCatalog.get_by_scope_and_name` hides non-approved
rows from the resolve path, and both state transitions
(``approve_instance`` / ``revoke_instance``) write one
:class:`McpApprovalChangeRecord` row apiece.

These tests hit the catalog layer directly through the test DB
fixture; no live MCP server is contacted (the router's ``/approve``
endpoint fetches the schema itself and is exercised by the API test
suite, not here).
"""
from __future__ import annotations

from uuid import uuid4

import pytest
from sqlmodel import select

# Top-level imports so SQLModel.metadata registers the new tables BEFORE
# the session-scoped test_db fixture calls create_all.
from aila.platform.mcp.instance_catalog import (
    TRANSPORT_HTTP,
    McpApprovalChangeRecord,
    McpApprovalState,
    McpInstanceCatalog,
    McpServerInstance,
)
from aila.storage.database import async_session_scope

__all__: list[str] = []


def _fresh_scope() -> str:
    """Per-test module_scope so parallel runs never collide on the unique key."""
    return f"rfc11trust-{uuid4().hex[:8]}"


@pytest.mark.asyncio
async def test_new_row_defaults_to_pending(test_db) -> None:
    """A freshly inserted row lands in PENDING, drift columns unset."""
    del test_db
    catalog = McpInstanceCatalog()
    scope = _fresh_scope()

    row = await catalog.add_instance(
        name="audit_mcp",
        transport=TRANSPORT_HTTP,
        endpoint="http://10.9.8.7:18822",
        module_scope=scope,
    )
    assert row.approval_state == McpApprovalState.PENDING.value
    assert row.approved_hash is None
    assert row.schema_hash is None
    assert row.server_card_json is None
    assert row.team_id is None

    projected = catalog.instance_to_dict(row)
    assert projected["approval_state"] == "pending"
    assert projected["approved_hash"] is None
    assert projected["schema_hash"] is None
    assert projected["has_server_card"] is False
    assert projected["team_id"] is None


@pytest.mark.asyncio
async def test_list_instances_approved_only_filters_pending(test_db) -> None:
    """list_instances(approved_only=True) hides pending rows, shows approved ones."""
    del test_db
    catalog = McpInstanceCatalog()
    scope = _fresh_scope()

    pending = await catalog.add_instance(
        name="audit_mcp",
        transport=TRANSPORT_HTTP,
        endpoint="http://10.9.8.7:18822",
        module_scope=scope,
    )
    approved = await catalog.add_instance(
        name="ida_headless",
        transport=TRANSPORT_HTTP,
        endpoint="http://10.9.8.7:18821",
        module_scope=scope,
    )
    await catalog.approve_instance(
        approved.id,
        schema_hash="a" * 64,
        approver="admin-user",
    )

    all_rows = await catalog.list_instances(module_scope=scope)
    assert {r.id for r in all_rows} == {pending.id, approved.id}

    approved_rows = await catalog.list_instances(
        module_scope=scope, approved_only=True,
    )
    assert [r.id for r in approved_rows] == [approved.id]

    # Revoking the approved row also drops it from the approved_only view.
    await catalog.revoke_instance(
        approved.id, approver="admin-user", reason="schema drift",
    )
    approved_after_revoke = await catalog.list_instances(
        module_scope=scope, approved_only=True,
    )
    assert approved_after_revoke == []


@pytest.mark.asyncio
async def test_approve_instance_flips_state_and_writes_change_record(test_db) -> None:
    """approve_instance stamps hash + card and writes one audit row."""
    del test_db
    catalog = McpInstanceCatalog()
    scope = _fresh_scope()

    row = await catalog.add_instance(
        name="audit_mcp",
        transport=TRANSPORT_HTTP,
        endpoint="http://10.9.8.7:18822",
        module_scope=scope,
    )
    assert row.approval_state == McpApprovalState.PENDING.value

    fake_hash = "b" * 64
    fake_card = '{"tools":[{"name":"noop"}]}'
    approved = await catalog.approve_instance(
        row.id,
        schema_hash=fake_hash,
        approver="admin-user",
        server_card_json=fake_card,
    )
    assert approved is not None
    assert approved.approval_state == McpApprovalState.APPROVED.value
    assert approved.approved_hash == fake_hash
    assert approved.schema_hash == fake_hash
    assert approved.server_card_json == fake_card
    assert approved.updated_at is not None

    # Exactly one change record with from=pending -> to=approved.
    async with async_session_scope() as session:
        rows = (await session.exec(
            select(McpApprovalChangeRecord).where(
                McpApprovalChangeRecord.instance_id == row.id,
            ),
        )).all()
    assert len(rows) == 1
    change = rows[0]
    assert change.from_state == McpApprovalState.PENDING.value
    assert change.to_state == McpApprovalState.APPROVED.value
    assert change.approver == "admin-user"
    assert change.schema_hash == fake_hash
    assert change.reason is None

    # Unknown id returns None.
    missing = await catalog.approve_instance(
        "does-not-exist",
        schema_hash=fake_hash,
        approver="admin-user",
    )
    assert missing is None


@pytest.mark.asyncio
async def test_revoke_instance_flips_state_and_writes_change_record(test_db) -> None:
    """revoke_instance flips APPROVED->REVOKED and records the reason."""
    del test_db
    catalog = McpInstanceCatalog()
    scope = _fresh_scope()

    row = await catalog.add_instance(
        name="audit_mcp",
        transport=TRANSPORT_HTTP,
        endpoint="http://10.9.8.7:18822",
        module_scope=scope,
    )
    approved_hash = "c" * 64
    await catalog.approve_instance(
        row.id, schema_hash=approved_hash, approver="admin-user",
    )

    revoked = await catalog.revoke_instance(
        row.id, approver="admin-user", reason="operator revoke test",
    )
    assert revoked is not None
    assert revoked.approval_state == McpApprovalState.REVOKED.value
    # approved_hash is preserved so a later re-approve can compare pins.
    assert revoked.approved_hash == approved_hash

    async with async_session_scope() as session:
        rows = (await session.exec(
            select(McpApprovalChangeRecord).where(
                McpApprovalChangeRecord.instance_id == row.id,
            ).order_by(McpApprovalChangeRecord.created_at),
        )).all()
    # One approve row + one revoke row.
    assert [r.to_state for r in rows] == [
        McpApprovalState.APPROVED.value,
        McpApprovalState.REVOKED.value,
    ]
    revoke_change = rows[-1]
    assert revoke_change.from_state == McpApprovalState.APPROVED.value
    assert revoke_change.approver == "admin-user"
    assert revoke_change.reason == "operator revoke test"
    assert revoke_change.schema_hash is None

    missing = await catalog.revoke_instance(
        "does-not-exist", approver="admin-user", reason="whatever",
    )
    assert missing is None


@pytest.mark.asyncio
async def test_get_by_scope_and_name_approved_only_hides_pending(test_db) -> None:
    """get_by_scope_and_name(approved_only=True) returns None for a pending row."""
    del test_db
    catalog = McpInstanceCatalog()
    scope = _fresh_scope()

    await catalog.add_instance(
        name="audit_mcp",
        transport=TRANSPORT_HTTP,
        endpoint="http://10.9.8.7:18822",
        module_scope=scope,
    )

    # Without the gate the row is visible (byte-identical to pre-Tier-C).
    always = await catalog.get_by_scope_and_name(scope, "audit_mcp")
    assert always is not None
    assert always.approval_state == McpApprovalState.PENDING.value

    # With approved_only=True the row is invisible -- the resolve path
    # falls back to the code-embedded default.
    gated = await catalog.get_by_scope_and_name(
        scope, "audit_mcp", approved_only=True,
    )
    assert gated is None

    # After approving the row the gated lookup returns it.
    await catalog.approve_instance(
        always.id, schema_hash="d" * 64, approver="admin-user",
    )
    gated_after = await catalog.get_by_scope_and_name(
        scope, "audit_mcp", approved_only=True,
    )
    assert gated_after is not None
    assert gated_after.id == always.id

    # Revoking hides it again.
    await catalog.revoke_instance(
        always.id, approver="admin-user", reason="drift",
    )
    gated_after_revoke = await catalog.get_by_scope_and_name(
        scope, "audit_mcp", approved_only=True,
    )
    assert gated_after_revoke is None


@pytest.mark.asyncio
async def test_record_schema_hash_updates_drift_column_only(test_db) -> None:
    """record_schema_hash updates schema_hash without changing state or pin."""
    del test_db
    catalog = McpInstanceCatalog()
    scope = _fresh_scope()

    row = await catalog.add_instance(
        name="audit_mcp",
        transport=TRANSPORT_HTTP,
        endpoint="http://10.9.8.7:18822",
        module_scope=scope,
    )
    approved_hash = "e" * 64
    await catalog.approve_instance(
        row.id, schema_hash=approved_hash, approver="admin-user",
    )

    drift_hash = "f" * 64
    updated = await catalog.record_schema_hash(row.id, drift_hash)
    assert updated is not None
    assert updated.approval_state == McpApprovalState.APPROVED.value
    assert updated.approved_hash == approved_hash  # pin unchanged
    assert updated.schema_hash == drift_hash

    # No new change-log row was written for the observation.
    async with async_session_scope() as session:
        rows = (await session.exec(
            select(McpApprovalChangeRecord).where(
                McpApprovalChangeRecord.instance_id == row.id,
            ),
        )).all()
    assert [r.to_state for r in rows] == [McpApprovalState.APPROVED.value]


@pytest.mark.asyncio
async def test_row_from_add_defaults_to_pending_projection(test_db) -> None:
    """Round-trip the row through the projection to confirm surface fields."""
    del test_db
    catalog = McpInstanceCatalog()
    scope = _fresh_scope()

    row = await catalog.add_instance(
        name="audit_mcp",
        transport=TRANSPORT_HTTP,
        endpoint="http://10.9.8.7:18822",
        module_scope=scope,
        team_id="team-alpha",
    )
    assert row.team_id == "team-alpha"

    # Reload from DB to make sure the persisted row also carries the pending
    # default -- guards against a client-side model default masking a
    # missing server_default in the migration.
    async with async_session_scope() as session:
        reloaded = await session.get(McpServerInstance, row.id)
    assert reloaded is not None
    assert reloaded.approval_state == McpApprovalState.PENDING.value
    assert reloaded.team_id == "team-alpha"

    projected = catalog.instance_to_dict(reloaded)
    assert projected["team_id"] == "team-alpha"
    assert projected["approval_state"] == "pending"
