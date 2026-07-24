"""Characterization (golden-master) tests for the VR ToolExecutor.

Captures the CURRENT observable behavior of the pre-dispatch gating in
`vr.agents.tool_executor.ToolExecutor.execute()` so the RFC-03 Phase 4b
extraction into a platform ToolExecutorBase can be proven
behavior-preserving. These paths short-circuit before the bridge call, so
the fake bridge's `forward` must never be awaited. There were no unit tests
exercising execute() before this file.
"""
from __future__ import annotations

from uuid import uuid4

import pytest
from sqlmodel import select

from aila.modules.vr.agents.tool_executor import ToolExecutor
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationMessageRecord,
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.storage.database import session_scope


class _FakeBridge:
    """Records forward() calls so tests can assert the bridge was or was not hit."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, dict]] = []

    async def forward(self, *, action: str, **kwargs) -> dict:
        self.calls.append((action, kwargs))
        return {"status": "ok"}


def _seed() -> tuple[str, str]:
    """Seed the FK chain; return (investigation_id, branch_id)."""
    suffix = uuid4().hex[:8]
    ws_id = f"ws-{suffix}"
    tgt_id = f"tgt-{suffix}"
    inv_id = f"inv-{suffix}"
    branch_id = f"br-{suffix}"
    with session_scope() as sess:
        sess.add(VRWorkspaceRecord(id=ws_id, name="ws", slug=ws_id))
        sess.flush()
        sess.add(VRTargetRecord(
            id=tgt_id, workspace_id=ws_id, display_name="tgt", kind="native_binary",
        ))
        sess.flush()
        sess.add(VRInvestigationRecord(
            id=inv_id, target_id=tgt_id, title="seed", kind="discovery",
            strategy_family="vulnerability_research.discovery_research",
        ))
        sess.flush()
        sess.add(VRInvestigationBranchRecord(id=branch_id, investigation_id=inv_id))
        sess.commit()
    return inv_id, branch_id


def _make_executor() -> tuple[ToolExecutor, _FakeBridge, _FakeBridge, _FakeBridge]:
    ida, audit, android = _FakeBridge(), _FakeBridge(), _FakeBridge()
    return ToolExecutor(ida=ida, audit_mcp=audit, android_mcp=android), ida, audit, android


def _count_messages(branch_id: str) -> int:
    with session_scope() as sess:
        rows = sess.exec(
            select(VRInvestigationMessageRecord).where(
                VRInvestigationMessageRecord.branch_id == branch_id,
            )
        ).all()
        return len(rows)


@pytest.mark.asyncio
async def test_malformed_command_errors_and_skips_bridge(test_db) -> None:
    del test_db
    inv_id, branch_id = _seed()
    executor, ida, audit, android = _make_executor()

    result = await executor.execute(
        investigation_id=inv_id, branch_id=branch_id,
        command_raw="this is not valid json", at_turn=1,
    )

    assert result.success is False
    assert result.server_id == ""
    assert result.tool_name == ""
    assert result.message_id is not None
    assert ida.calls == [] and audit.calls == [] and android.calls == []
    assert _count_messages(branch_id) == 1


@pytest.mark.asyncio
async def test_tool_without_server_prefix_errors_and_skips_bridge(test_db) -> None:
    del test_db
    inv_id, branch_id = _seed()
    executor, ida, audit, android = _make_executor()

    result = await executor.execute(
        investigation_id=inv_id, branch_id=branch_id,
        command_raw='{"tool": "noserver", "args": {}}', at_turn=1,
    )

    assert result.success is False
    assert result.tool_name == ""
    assert ida.calls == [] and audit.calls == [] and android.calls == []


@pytest.mark.asyncio
async def test_unknown_tool_no_adapter_errors_and_skips_bridge(test_db) -> None:
    del test_db
    inv_id, branch_id = _seed()
    executor, ida, audit, android = _make_executor()

    result = await executor.execute(
        investigation_id=inv_id, branch_id=branch_id,
        command_raw='{"tool": "ida_headless.__definitely_not_a_real_tool__", "args": {}}',
        at_turn=1,
    )

    assert result.success is False
    assert result.server_id == "ida_headless"
    assert result.tool_name == "__definitely_not_a_real_tool__"
    assert result.message_id is not None
    assert ida.calls == [] and audit.calls == [] and android.calls == []
