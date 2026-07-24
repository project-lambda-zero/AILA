"""Characterization (golden-master) tests for the VR ToolExecutor.

Captures the CURRENT observable behavior of the pre-dispatch gating in
`vr.agents.tool_executor.ToolExecutor.execute()` so the RFC-03 Phase 4b
extraction into a platform ToolExecutorBase can be proven
behavior-preserving. These paths short-circuit before the bridge call, so
the fake bridge's `forward` must never be awaited. There were no unit tests
exercising execute() before this file.
"""
from __future__ import annotations

import json
from datetime import timedelta
from uuid import uuid4

import pytest
from sqlmodel import select

from aila.modules.vr.agents.tool_executor import ToolExecutor
from aila.modules.vr.contracts import PayloadKind, SenderKind
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationMessageRecord,
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.platform.contracts import utc_now
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


# --------------------------------------------------------------------------
# Direct coverage of the helpers extracted to ToolExecutorHelpersBase
# (RFC-03 Phase 4b). These pin the lifted circuit-breaker counters and the
# combined result+observables write against the injected VR record types.
# --------------------------------------------------------------------------


def _add_msg(sess, inv_id: str, branch_id: str, kind: str, payload: dict, order: int) -> None:
    sess.add(VRInvestigationMessageRecord(
        investigation_id=inv_id,
        branch_id=branch_id,
        sender_kind=SenderKind.ENGINE.value,
        sender_id="tool_executor",
        payload_kind=kind,
        payload_json=json.dumps(payload),
        at_turn=order,
        evidence_refs_json="[]",
        created_at=utc_now() + timedelta(seconds=order),
    ))


@pytest.mark.asyncio
async def test_count_prior_failures_pairs_toolcall_and_error(test_db) -> None:
    """Two matching (tool_call -> same-args error) pairs count as two; a
    pair with different args does not count."""
    del test_db
    _inv, branch_id = _seed()
    executor, *_ = _make_executor()
    cmd = json.dumps({"tool": "audit_mcp.read_function", "args": {"name": "foo"}})
    other = json.dumps({"tool": "audit_mcp.read_function", "args": {"name": "bar"}})
    err = {"is_error": True, "text": "audit_mcp.read_function returned error: boom"}
    with session_scope() as sess:
        _add_msg(sess, _inv, branch_id, PayloadKind.TOOL_CALL.value, {"command": cmd}, 1)
        _add_msg(sess, _inv, branch_id, PayloadKind.TEXT.value, err, 2)
        _add_msg(sess, _inv, branch_id, PayloadKind.TOOL_CALL.value, {"command": cmd}, 3)
        _add_msg(sess, _inv, branch_id, PayloadKind.TEXT.value, err, 4)
        _add_msg(sess, _inv, branch_id, PayloadKind.TOOL_CALL.value, {"command": other}, 5)
        _add_msg(sess, _inv, branch_id, PayloadKind.TEXT.value, err, 6)
        sess.commit()
    count = await executor._count_prior_failures(
        branch_id, "audit_mcp", "read_function", {"name": "foo"},
    )
    assert count == 2


@pytest.mark.asyncio
async def test_count_total_malformed_counts_marker_errors(test_db) -> None:
    """Malformed-marker error messages are counted across the window; a
    non-malformed error is not."""
    del test_db
    _inv, branch_id = _seed()
    executor, *_ = _make_executor()
    with session_scope() as sess:
        _add_msg(sess, _inv, branch_id, PayloadKind.TEXT.value,
                 {"is_error": True, "text": "Malformed tool_run command -- expected"}, 1)
        _add_msg(sess, _inv, branch_id, PayloadKind.TEXT.value,
                 {"is_error": True, "text": "Malformed tool_run command -- expected"}, 2)
        _add_msg(sess, _inv, branch_id, PayloadKind.TEXT.value,
                 {"is_error": True, "text": "audit_mcp.read_function returned error"}, 3)
        sess.commit()
    assert await executor._count_total_malformed(branch_id) == 2


@pytest.mark.asyncio
async def test_persist_result_and_observables_writes_and_merges(test_db) -> None:
    """The combined write persists a result message AND merges the
    observables delta into the branch case_state in one call."""
    del test_db
    inv_id, branch_id = _seed()
    executor, *_ = _make_executor()
    msg_id = await executor._persist_result_and_observables(
        inv_id, branch_id,
        payload_kind=PayloadKind.TEXT,
        payload={"text": "result body"},
        observables_delta={"finding.candidate": "strcpy"},
        at_turn=7,
    )
    assert msg_id
    with session_scope() as sess:
        msg = sess.get(VRInvestigationMessageRecord, msg_id)
        assert msg is not None and msg.branch_id == branch_id
        branch = sess.get(VRInvestigationBranchRecord, branch_id)
        state = json.loads(branch.case_state_json or "{}")
        assert state["observables"]["finding.candidate"] == "strcpy"


def test_apply_observables_delta_merges_and_caps() -> None:
    """Pure helper: merges a delta, and caps at _MAX_OBSERVABLES while
    always retaining _directive.* keys."""
    merged = ToolExecutor._apply_observables_delta(None, {"a": 1, "b": 2})
    assert json.loads(merged)["observables"] == {"a": 1, "b": 2}
    # Overflow: seed one directive + many plain keys past the cap.
    cap = ToolExecutor._MAX_OBSERVABLES
    big = {"_directive.keep": "x"}
    big.update({f"k{i}": i for i in range(cap + 50)})
    capped = json.loads(
        ToolExecutor._apply_observables_delta(
            json.dumps({"observables": {}}), big,
        )
    )["observables"]
    assert len(capped) <= cap
    assert "_directive.keep" in capped
