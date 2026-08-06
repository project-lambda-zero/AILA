"""#63 -- ``refresh_target_source`` MUST persist a re-keyed audit-mcp index.

The endpoint calls audit-mcp's ``refresh_index`` and, when the tool
returns a new ``index_id`` (drop+start_index can re-key when the
deterministic path key changes), writes it back into the target's
``mcp_handles_json`` inside a ``UnitOfWork``. The audit's confirmed
silent-data-loss channel was: the write was ``session.add``ed but never
``await uow.commit``ed -- ``UnitOfWork.__aexit__`` rolls back on close,
so the operator saw ``index_id: new`` in the response while the DB kept
the stale value.

These tests exercise the exact persistence pattern the endpoint runs and
prove the new id is visible in a fresh session. A second test proves the
``UnitOfWork`` backstop (C4) still turns a forgotten commit into a named
``UnitOfWorkNotCommittedError`` -- a second line of defense against the
same channel reopening.
"""
from __future__ import annotations

import json

import pytest
from sqlmodel import select

from aila.modules.vr.db_models import VRTargetRecord
from aila.modules.vr.db_models.workspace import VRWorkspaceRecord
from aila.platform.uow import UnitOfWork, UnitOfWorkNotCommittedError

_TEAM = "team-refresh-63"


async def _seed_target(index_id: str) -> str:
    """Insert one workspace + one source_repo target carrying ``index_id``."""
    async with UnitOfWork() as uow:
        ws = VRWorkspaceRecord(
            name="refresh-63",
            slug="refresh-63",
            description="",
            theme="custom",
            team_id=_TEAM,
        )
        uow.session.add(ws)
        await uow.session.flush()

        target = VRTargetRecord(
            workspace_id=ws.id,
            team_id=_TEAM,
            display_name="refresh-target",
            kind="source_repo",
            descriptor_json=json.dumps({"repo_url": "https://example.invalid/x.git"}),
            primary_language=None,
            secondary_languages_json="[]",
            tags_json="[]",
            mcp_handles_json=json.dumps({"audit_mcp_index_id": index_id}),
            status="active",
            capability_profile_json="{}",
        )
        uow.session.add(target)
        await uow.session.commit()
        await uow.session.refresh(target)
        return target.id


@pytest.mark.asyncio
async def test_refresh_persists_new_index_id_across_sessions(test_db) -> None:
    """The endpoint's inner UoW block MUST persist the new id.

    Mirrors ``refresh_target_source`` at ``modules/vr/api_router.py`` where
    it reads the target, mutates ``mcp_handles_json['audit_mcp_index_id']``,
    ``session.add``s the row, then ``await uow.commit``s. A fresh
    ``UnitOfWork`` MUST observe the new id.
    """
    target_id = await _seed_target(index_id="idx-old")
    new_index_id = "idx-new-63"

    # ---- Mirror of api_router.refresh_target_source persistence block ----
    async with UnitOfWork() as uow:
        row = (await uow.session.exec(
            select(VRTargetRecord).where(VRTargetRecord.id == target_id)
        )).first()
        assert row is not None
        try:
            handles = json.loads(row.mcp_handles_json or "{}")
        except (ValueError, TypeError):
            handles = {}
        handles["audit_mcp_index_id"] = new_index_id
        row.mcp_handles_json = json.dumps(handles)
        uow.session.add(row)
        await uow.commit()
    # ----------------------------------------------------------------------

    # Verify in a fresh session (fresh UnitOfWork == fresh AsyncSession).
    async with UnitOfWork() as uow:
        reloaded = (await uow.session.exec(
            select(VRTargetRecord).where(VRTargetRecord.id == target_id)
        )).first()
    assert reloaded is not None
    persisted_handles = json.loads(reloaded.mcp_handles_json or "{}")
    assert persisted_handles.get("audit_mcp_index_id") == new_index_id, (
        "refresh_target_source persistence lost the new index id -- "
        "the caller-owned commit did not fire (see #63)."
    )


@pytest.mark.asyncio
async def test_forgotten_commit_raises_uow_backstop(test_db) -> None:
    """Backstop guard for the same channel.

    If a future edit removes the ``await uow.commit()`` from the endpoint's
    persistence block, ``UnitOfWork.__aexit__`` raises
    ``UnitOfWorkNotCommittedError`` on the clean exit rather than silently
    rolling back. This test exercises that guard against the same target
    table so a regression cannot land silently.
    """
    target_id = await _seed_target(index_id="idx-preexisting")

    with pytest.raises(UnitOfWorkNotCommittedError):
        async with UnitOfWork() as uow:
            row = (await uow.session.exec(
                select(VRTargetRecord).where(VRTargetRecord.id == target_id)
            )).first()
            assert row is not None
            handles = json.loads(row.mcp_handles_json or "{}")
            handles["audit_mcp_index_id"] = "idx-should-be-lost"
            row.mcp_handles_json = json.dumps(handles)
            uow.session.add(row)
            # Deliberately omit ``await uow.commit()`` -- backstop MUST fire.

    # Row still carries the pre-existing id because the rollback beat the
    # backstop to the DB.
    async with UnitOfWork() as uow:
        reloaded = (await uow.session.exec(
            select(VRTargetRecord).where(VRTargetRecord.id == target_id)
        )).first()
    assert reloaded is not None
    handles = json.loads(reloaded.mcp_handles_json or "{}")
    assert handles.get("audit_mcp_index_id") == "idx-preexisting"
