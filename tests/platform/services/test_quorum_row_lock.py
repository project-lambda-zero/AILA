"""Regression guard for issue #166 -- evaluate_quorum must SELECT the
outcome row with FOR UPDATE so concurrent callers (turn_runner and
investigation_emit_base re-entry) serialize on the row instead of both
reading state == DRAFT and clobbering each other's set_outcome_state
write.

Rationale for the shape of this test:

- A true concurrency reproduction requires two worker tasks driving
  independent async sessions and stepping them in lockstep across the
  DB (each waiting on the other's SELECT before the write). The test
  harness runs a single asyncio event loop and shares the aila engine
  pool, so a genuine race is hard to stage deterministically here.
- Instead we assert the guarantee at the SQL layer: the SELECT that
  evaluate_quorum emits against the outcomes table MUST carry
  ``FOR UPDATE``. That is the row lock; without it, concurrent
  read-modify-writes over the same row cannot serialize on Postgres.
- We attach a SQLAlchemy engine event to capture every statement
  executed while evaluate_quorum runs, then filter to the outcome
  SELECT and assert ``FOR UPDATE`` is present in the compiled SQL.
  This exercises the actual code path -- no mocking, no source-text
  scanning -- and would fail if the ``.with_for_update()`` call were
  ever removed.
"""
from __future__ import annotations

from sqlalchemy import event

from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationOutcomeReviewRecord,
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.platform.services.outcome_review import (
    VOTE_APPROVE,
    evaluate_quorum,
)
from aila.platform.uow import UnitOfWork
from aila.storage.database import get_async_engine

_MODELS = {
    "outcome_model": VRInvestigationOutcomeRecord,
    "branch_model": VRInvestigationBranchRecord,
    "outcome_review_model": VRInvestigationOutcomeReviewRecord,
}


async def _seed_outcome(inv: str, proposer: str) -> str:
    """Seed the minimum FK chain and a draft outcome, return its id."""
    ws_id = f"ws-{inv}"
    tgt_id = f"tgt-{inv}"
    async with UnitOfWork() as uow:
        uow.session.add(VRWorkspaceRecord(id=ws_id, name="ws", slug=ws_id))
        await uow.session.flush()
        uow.session.add(
            VRTargetRecord(
                id=tgt_id,
                workspace_id=ws_id,
                display_name="tgt",
                kind="native_binary",
            ),
        )
        await uow.session.flush()
        uow.session.add(
            VRInvestigationRecord(
                id=inv,
                target_id=tgt_id,
                title="seed",
                kind="discovery",
                strategy_family="vulnerability_research.discovery_research",
            ),
        )
        await uow.session.flush()
        outcome = VRInvestigationOutcomeRecord(
            investigation_id=inv,
            branch_id=proposer,
            outcome_kind="vulnerability",
            confidence="high",
        )
        uow.session.add(outcome)
        uow.session.add(
            VRInvestigationBranchRecord(id=proposer, investigation_id=inv),
        )
        # One sibling with one approve vote -- enough to exercise the
        # tally + set_outcome_state write path (quorum_k = 1 for a
        # single non-proposing sibling).
        uow.session.add(
            VRInvestigationBranchRecord(
                id="s1", investigation_id=inv, status="active",
            ),
        )
        await uow.session.flush()
        outcome_id = outcome.id
        uow.session.add(
            VRInvestigationOutcomeReviewRecord(
                outcome_id=outcome_id,
                reviewer_branch_id="s1",
                reviewer_persona="s1",
                vote=VOTE_APPROVE,
            ),
        )
        await uow.session.commit()
    return outcome_id


async def test_evaluate_quorum_select_carries_for_update(test_db) -> None:
    """The outcome SELECT emitted by evaluate_quorum MUST carry
    ``FOR UPDATE``. This is the row lock that serializes concurrent
    evaluate_quorum calls for the same outcome (#166); without it,
    two callers can both read state == DRAFT, both decide, and the
    last commit wins -- an approve and a reject then resolve to
    whichever committed last.
    """
    del test_db
    outcome_id = await _seed_outcome("inv-166-lock", "p")

    captured: list[str] = []
    engine = get_async_engine()

    def _capture(_conn, _cursor, statement, _params, _context, _executemany):
        captured.append(statement)

    event.listen(engine.sync_engine, "before_cursor_execute", _capture)
    try:
        await evaluate_quorum(
            outcome_id, veto_k=1, audit_stage="source_audit", **_MODELS,
        )
    finally:
        event.remove(engine.sync_engine, "before_cursor_execute", _capture)

    # Find the SELECT against the outcomes table that filters by id.
    # There is exactly one such SELECT in evaluate_quorum -- the
    # locking read at the top of the function.
    outcome_selects = [
        sql for sql in captured
        if "FROM vr_investigation_outcomes" in sql
        and "vr_investigation_outcomes.id =" in sql
        and sql.lstrip().upper().startswith("SELECT")
    ]
    assert outcome_selects, (
        "evaluate_quorum did not emit any SELECT against "
        "vr_investigation_outcomes filtered by id; the test seed or "
        "the function shape changed -- update this test to match."
    )
    # Postgres compiles ``.with_for_update()`` as ``FOR UPDATE`` at the
    # end of the statement. Assert on the last (locking) SELECT the
    # function emitted for the outcome row.
    locking_sql = outcome_selects[-1]
    assert "FOR UPDATE" in locking_sql.upper(), (
        "evaluate_quorum SELECT on the outcome row is missing "
        "FOR UPDATE -- #166 regression. Concurrent evaluate_quorum "
        "calls on the same outcome will no longer serialize on the "
        "row and can clobber each other's set_outcome_state write. "
        f"Emitted SQL:\n{locking_sql}"
    )
