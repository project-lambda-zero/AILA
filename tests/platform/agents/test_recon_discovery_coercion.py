"""Recon note->discovery coercion activates the discovery-gated audit phases.

Regression guard for the dispatch-hub convergence fix: recon agents post
findings as ledger ``note`` entries, but every audit phase gates on
``make_discovery_condition("discovery")`` (exact kind equality). Without
coercion the phase graph never advances past recon. ``_post_ledger_writes``
now records a recon-phase ``note`` as a ``discovery`` so the audit phases
can activate; outside recon the kind is left untouched.

Provider-independent -- proves the convergence wiring without a live LLM.
"""
from __future__ import annotations

from types import SimpleNamespace

from aila.platform.agents.turn_runner import AgentTurnRunnerBase
from aila.platform.contracts.reasoning import (
    Hypothesis,
    LedgerWrite,
    ReasoningCaseState,
    ReasoningTurnDecision,
)
from aila.platform.services.ledger import LedgerService, make_discovery_condition
from aila.platform.uow import UnitOfWork

_RECON = ReasoningCaseState(
    observables={"_directive.phase_mission": "RECON PHASE. Objective: scope the target."},
)
_AUDIT = ReasoningCaseState(
    observables={"_directive.phase_mission": "SOURCE AUDIT PHASE. Objective: audit."},
)


async def test_recon_note_is_coerced_to_discovery(test_db) -> None:
    del test_db
    inv, branch = "inv-recon-coerce", "b-recon"
    me = SimpleNamespace(investigation_id=inv, branch_id=branch)
    decision = ReasoningTurnDecision(
        reasoning="scoped surfaces",
        ledger_writes=[LedgerWrite(kind="note", payload={"surface": "cli main()"})],
    )
    async with UnitOfWork() as uow:
        await AgentTurnRunnerBase._post_ledger_writes(me, decision, 1, uow.session, _RECON)
        await uow.session.commit()
    rows = await LedgerService().read_general(inv)
    assert len(rows) == 1
    assert rows[0]["kind"] == "discovery"


async def test_note_outside_recon_is_untouched(test_db) -> None:
    del test_db
    inv, branch = "inv-audit-note", "b-audit"
    me = SimpleNamespace(investigation_id=inv, branch_id=branch)
    decision = ReasoningTurnDecision(
        reasoning="x",
        ledger_writes=[LedgerWrite(kind="note", payload={"n": 1})],
    )
    async with UnitOfWork() as uow:
        await AgentTurnRunnerBase._post_ledger_writes(me, decision, 1, uow.session, _AUDIT)
        await uow.session.commit()
    rows = await LedgerService().read_general(inv)
    assert len(rows) == 1
    assert rows[0]["kind"] == "note"


async def test_request_in_recon_is_untouched(test_db) -> None:
    del test_db
    inv, branch = "inv-recon-req", "b-req"
    me = SimpleNamespace(investigation_id=inv, branch_id=branch)
    decision = ReasoningTurnDecision(
        reasoning="x",
        ledger_writes=[LedgerWrite(kind="request", payload={"intent": "replan"})],
    )
    async with UnitOfWork() as uow:
        await AgentTurnRunnerBase._post_ledger_writes(me, decision, 1, uow.session, _RECON)
        await uow.session.commit()
    rows = await LedgerService().read_general(inv)
    assert rows[0]["kind"] == "request"


async def test_audit_hypothesis_requires_real_confirmation(test_db) -> None:
    del test_db
    hypothesis = Hypothesis(
        id="h-unconfirmed",
        claim="Possible injection",
        why_plausible="Input reaches a query",
        kill_criterion="The query uses bound parameters",
    )
    new_state = ReasoningCaseState(hypotheses=[hypothesis.model_copy(deep=True)])
    decision = ReasoningTurnDecision(reasoning="candidate", hypotheses=[hypothesis])
    me = SimpleNamespace(investigation_id="inv-unconfirmed", branch_id="b-unconfirmed")

    async with UnitOfWork() as uow:
        await AgentTurnRunnerBase._post_ledger_writes(
            me, decision, 1, uow.session, _AUDIT,
        )
        await uow.session.commit()

    assert await LedgerService().read_general("inv-unconfirmed") == []
    assert new_state.hypotheses[0].confirmed_by == ""


async def test_confirmed_audit_hypothesis_preserves_evidence_citation(test_db) -> None:
    del test_db
    hypothesis = Hypothesis(
        id="h-confirmed",
        claim="Confirmed injection",
        confirmed_by="audit_mcp.read_function:src/login.c:42",
    )
    decision = ReasoningTurnDecision(reasoning="confirmed", hypotheses=[hypothesis])
    me = SimpleNamespace(investigation_id="inv-confirmed", branch_id="b-confirmed")

    async with UnitOfWork() as uow:
        await AgentTurnRunnerBase._post_ledger_writes(
            me, decision, 1, uow.session, _AUDIT,
        )
        await uow.session.commit()

    rows = await LedgerService().read_general("inv-confirmed")
    assert len(rows) == 1
    assert rows[0]["payload"]["confirmed_by"] == "audit_mcp.read_function:src/login.c:42"
    assert rows[0]["payload"]["source"] == "taint_confirmed"


async def test_coerced_discovery_activates_audit_condition(test_db) -> None:
    del test_db
    inv, branch = "inv-activate", "b-act"
    me = SimpleNamespace(investigation_id=inv, branch_id=branch)
    # Recon posts a note; coercion records it as a discovery.
    decision = ReasoningTurnDecision(
        reasoning="found a surface",
        ledger_writes=[LedgerWrite(kind="note", payload={"surface": "parser"})],
    )
    async with UnitOfWork() as uow:
        await AgentTurnRunnerBase._post_ledger_writes(me, decision, 1, uow.session, _RECON)
        await uow.session.commit()
    # The audit-phase activation condition now fires (before the fix it never did).
    condition = make_discovery_condition("discovery")
    enabled, reason = await condition(
        {"investigation_id": inv, "_dispatch_phase_trust": "advisory"},
    )
    assert enabled is True
    assert "discovery" in reason.lower()
