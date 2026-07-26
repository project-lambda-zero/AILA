"""Tests for the agent ledger-write action + ledger render (RFC-13 Phase 2).

Exercises the turn-runner helpers directly (``_post_ledger_writes``,
``_load_ledger_board``) against the shared ``aila_test`` schema, plus the
render section in ``render_case_model`` (no DB).
"""
from __future__ import annotations

from types import SimpleNamespace

from aila.platform.agents.turn_runner import (
    _MAX_LEDGER_WRITES_PER_TURN,
    AgentTurnRunnerBase,
)
from aila.platform.contracts.reasoning import (
    LedgerWrite,
    ReasoningCaseState,
    ReasoningTurnDecision,
)
from aila.platform.services.ledger import LedgerService, make_discovery_condition
from aila.platform.services.oracle import Oracle
from aila.platform.services.reasoning import CyberReasoningEngine
from aila.platform.uow import UnitOfWork


async def test_ledger_write_appends_one_row(test_db) -> None:
    del test_db
    inv, branch = "inv-lw", "branch-lw"
    me = SimpleNamespace(investigation_id=inv, branch_id=branch)
    decision = ReasoningTurnDecision(
        reasoning="found packing",
        ledger_writes=[LedgerWrite(kind="discovery", payload={"packed": True})],
    )
    async with UnitOfWork() as uow:
        await AgentTurnRunnerBase._post_ledger_writes(me, decision, 3, uow.session, ReasoningCaseState())
        await uow.session.commit()
    rows = await LedgerService().read_general(inv)
    assert len(rows) == 1
    assert rows[0]["kind"] == "discovery"
    assert rows[0]["payload"] == {"packed": True}
    assert rows[0]["author_branch_id"] == branch


async def test_ledger_write_retry_does_not_double_append(test_db) -> None:
    del test_db
    inv, branch = "inv-lw-retry", "branch-lw-retry"
    me = SimpleNamespace(investigation_id=inv, branch_id=branch)
    decision = ReasoningTurnDecision(
        reasoning="x",
        ledger_writes=[LedgerWrite(kind="discovery", payload={"packed": True})],
    )
    # Same turn processed twice (an ARQ retry) writes exactly one row.
    async with UnitOfWork() as uow:
        await AgentTurnRunnerBase._post_ledger_writes(me, decision, 3, uow.session, ReasoningCaseState())
        await uow.session.commit()
    async with UnitOfWork() as uow:
        await AgentTurnRunnerBase._post_ledger_writes(me, decision, 3, uow.session, ReasoningCaseState())
        await uow.session.commit()
    rows = await LedgerService().read_general(inv)
    assert len(rows) == 1


async def test_ledger_write_per_turn_cap(test_db) -> None:
    del test_db
    inv, branch = "inv-lw-cap", "branch-lw-cap"
    me = SimpleNamespace(investigation_id=inv, branch_id=branch)
    writes = [LedgerWrite(kind="note", payload={"i": i}) for i in range(10)]
    decision = ReasoningTurnDecision(reasoning="x", ledger_writes=writes)
    async with UnitOfWork() as uow:
        await AgentTurnRunnerBase._post_ledger_writes(me, decision, 1, uow.session, ReasoningCaseState())
        await uow.session.commit()
    rows = await LedgerService().read_general(inv)
    assert len(rows) == _MAX_LEDGER_WRITES_PER_TURN


async def test_ledger_write_empty_list_is_noop(test_db) -> None:
    del test_db
    inv, branch = "inv-lw-empty", "branch-lw-empty"
    me = SimpleNamespace(investigation_id=inv, branch_id=branch)
    decision = ReasoningTurnDecision(reasoning="x")
    async with UnitOfWork() as uow:
        await AgentTurnRunnerBase._post_ledger_writes(me, decision, 1, uow.session, ReasoningCaseState())
    rows = await LedgerService().read_general(inv)
    assert rows == []


async def test_ledger_board_renders_recent_and_bounds(test_db) -> None:
    del test_db
    inv, branch = "inv-board", "branch-board"
    svc = LedgerService()
    for i in range(20):
        await svc.append_general(inv, branch, "discovery", {"idx": i})
    me = SimpleNamespace(investigation_id=inv, branch_id=branch)
    board = await AgentTurnRunnerBase._load_ledger_board(me)
    assert "Investigation ledger (shared, 20 entries" in board
    assert "showing last 15" in board
    # The newest entry renders; the oldest is trimmed by the recency bound.
    assert '"idx": 19' in board
    assert '"idx": 0}' not in board
    entry_lines = [
        line for line in board.splitlines() if line.strip().startswith("#")
    ]
    assert len(entry_lines) == 15


async def test_ledger_board_empty_is_blank(test_db) -> None:
    del test_db
    me = SimpleNamespace(investigation_id="inv-board-empty", branch_id="b")
    board = await AgentTurnRunnerBase._load_ledger_board(me)
    assert board == ""


async def test_discovery_condition_reads_real_discovery(test_db) -> None:
    del test_db
    inv = "inv-cond"
    condition = make_discovery_condition("discovery")
    ok, _reason = await condition({"investigation_id": inv})
    assert ok is False
    await LedgerService().append_general(inv, "b1", "discovery", {"packed": True})
    ok2, reason2 = await condition({"investigation_id": inv})
    assert ok2 is True
    assert "discovery" in reason2


async def test_discovery_condition_confirmed_only(test_db) -> None:
    del test_db
    inv = "inv-cond-confirmed"
    svc = LedgerService()
    discovery_id = await svc.append_general(inv, "b1", "discovery", {"packed": True})
    condition = make_discovery_condition("discovery", confirmed_only=True)
    ok, _reason = await condition({"investigation_id": inv})
    assert ok is False  # present but not quorum-confirmed
    await svc.append_general(
        inv, "b2", "decision", {"approved": True, "target": discovery_id},
    )
    ok2, reason2 = await condition({"investigation_id": inv})
    assert ok2 is True
    assert "confirmed" in reason2


def test_render_case_model_surfaces_ledger_board() -> None:
    engine = CyberReasoningEngine(None)
    digest = (
        "Investigation ledger (shared, 1 entries):\n"
        '  #1 [discovery] by b1: {"packed": true}'
    )
    case_state = ReasoningCaseState(observables={"_ledger.board": digest})
    rendered = engine.render_case_model(case_state)
    assert "Investigation ledger (shared, 1 entries)" in rendered
    assert "packed" in rendered
    # The reserved key itself is never rendered as a raw scratchpad line.
    assert "_ledger.board" not in rendered


async def test_trust_drives_confirmed_gating(test_db) -> None:
    del test_db
    inv = "inv-trust"
    svc = LedgerService()
    discovery = await svc.append_general(inv, "b1", "discovery", {"x": 1})
    condition = make_discovery_condition("discovery")  # no baked confirmed_only
    # Advisory trust: any discovery activates.
    ok_adv, _r = await condition(
        {"investigation_id": inv, "_dispatch_phase_trust": "advisory"},
    )
    assert ok_adv is True
    # Confirmed trust: an unconfirmed discovery does not activate.
    ok_unconf, _r = await condition(
        {"investigation_id": inv, "_dispatch_phase_trust": "confirmed"},
    )
    assert ok_unconf is False
    # Once confirmed, the confirmed-trust phase activates.
    await svc.append_general(inv, "b2", "decision", {"approved": True, "target": discovery})
    ok_conf, _r = await condition(
        {"investigation_id": inv, "_dispatch_phase_trust": "confirmed"},
    )
    assert ok_conf is True


async def test_agent_approval_records_decision(test_db) -> None:
    del test_db
    inv = "inv-approve"
    request = await LedgerService().append_general(
        inv, "b1", "request", {"intent": "replan"},
    )
    me = SimpleNamespace(investigation_id=inv, branch_id="b2")
    decision = ReasoningTurnDecision(reasoning="x", ledger_approvals=[request])
    async with UnitOfWork() as uow:
        await AgentTurnRunnerBase._post_ledger_approvals(me, decision, uow.session)
        await uow.session.commit()
    assert await Oracle().is_ratified(inv, request) is True


async def test_agent_self_approval_skipped(test_db) -> None:
    del test_db
    inv = "inv-selfapprove"
    request = await LedgerService().append_general(
        inv, "b1", "request", {"intent": "replan"},
    )
    me = SimpleNamespace(investigation_id=inv, branch_id="b1")  # author approves own
    decision = ReasoningTurnDecision(reasoning="x", ledger_approvals=[request])
    async with UnitOfWork() as uow:
        await AgentTurnRunnerBase._post_ledger_approvals(me, decision, uow.session)
        await uow.session.commit()
    assert await Oracle().is_ratified(inv, request) is False  # distinct-approver rule
