"""Active-voter quorum: real sibling votes resolve a draft outcome.

Regression guard for the dispatch-hub convergence endgame. A branch that
submits a terminal outcome must be corroborated by its siblings before the
outcome ships. ``evaluate_quorum`` tallies real vote rows and flips the
outcome state:

- ``approved_K_of_K_required`` when active siblings approve to threshold
  (the genuine dialectic outcome, NOT the ``auto_approved_no_active_voters``
  safety net that fires only when every sibling is dead),
- ``vetoed_by_N_sibling(s)`` when rejects reach ``veto_k``,
- no transition (stays ``draft``) when votes fall short while siblings are
  still active -- so a live investigation cannot ship prematurely and the
  no-active-voters fallback does not fire while voters remain.

Provider-independent -- proves the active-voter wiring without a live LLM.
"""
from __future__ import annotations

from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationOutcomeReviewRecord,
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.platform.services.outcome_review import (
    OUTCOME_STATE_APPROVED,
    OUTCOME_STATE_DRAFT,
    OUTCOME_STATE_REJECTED,
    VOTE_ABSTAIN,
    VOTE_APPROVE,
    VOTE_NOT_READY,
    VOTE_REJECT,
    evaluate_quorum,
)
from aila.platform.uow import UnitOfWork

_MODELS = {
    "outcome_model": VRInvestigationOutcomeRecord,
    "branch_model": VRInvestigationBranchRecord,
    "outcome_review_model": VRInvestigationOutcomeReviewRecord,
}


async def _seed(
    *,
    inv: str,
    proposer: str,
    sibling_ids: list[str],
    votes: list[tuple[str, str]],
    sibling_status: str = "active",
) -> str:
    """Create the FK chain, a draft outcome, its branches, and vote rows."""
    ws_id, tgt_id = f"ws-{inv}", f"tgt-{inv}"
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
        for sid in sibling_ids:
            uow.session.add(
                VRInvestigationBranchRecord(
                    id=sid, investigation_id=inv, status=sibling_status,
                ),
            )
        await uow.session.flush()
        outcome_id = outcome.id
        for reviewer_branch_id, vote in votes:
            uow.session.add(
                VRInvestigationOutcomeReviewRecord(
                    outcome_id=outcome_id,
                    reviewer_branch_id=reviewer_branch_id,
                    reviewer_persona=reviewer_branch_id,
                    vote=vote,
                ),
            )
        await uow.session.commit()
    return outcome_id


async def test_active_voters_approve_to_quorum(test_db) -> None:
    del test_db
    # Five non-proposing siblings -> majority K=3; three approvals ship it.
    outcome_id = await _seed(
        inv="inv-q-approve",
        proposer="p",
        sibling_ids=["s1", "s2", "s3", "s4", "s5"],
        votes=[
            ("s1", VOTE_APPROVE),
            ("s2", VOTE_APPROVE),
            ("s3", VOTE_APPROVE),
        ],
    )
    res = await evaluate_quorum(
        outcome_id, veto_k=1, audit_stage="source_audit", **_MODELS,
    )
    assert res.quorum_k == 3
    assert res.approve_count == 3
    assert res.new_state == OUTCOME_STATE_APPROVED
    assert res.transition_occurred is True
    assert res.transition_reason.startswith("approved_3_of_3")
    # The genuine dialectic path, NOT the dead-voter safety net.
    assert "auto_approved" not in res.transition_reason


async def test_abstain_does_not_block_majority(test_db) -> None:
    del test_db
    # Regression: under the old unanimous rule (K = N-1) a single abstain
    # made approval unreachable and stalled deliberation. With majority K,
    # three approvals ship the finding even though two siblings abstained.
    outcome_id = await _seed(
        inv="inv-q-abstain",
        proposer="p",
        sibling_ids=["s1", "s2", "s3", "s4", "s5"],
        votes=[
            ("s1", VOTE_APPROVE),
            ("s2", VOTE_APPROVE),
            ("s3", VOTE_APPROVE),
            ("s4", VOTE_ABSTAIN),
            ("s5", VOTE_ABSTAIN),
        ],
    )
    res = await evaluate_quorum(
        outcome_id, veto_k=1, audit_stage="source_audit", **_MODELS,
    )
    assert res.quorum_k == 3
    assert res.approve_count == 3
    assert res.abstain_count == 2
    assert res.new_state == OUTCOME_STATE_APPROVED
    assert res.transition_occurred is True


async def test_active_voters_reject_veto(test_db) -> None:
    del test_db
    outcome_id = await _seed(
        inv="inv-q-reject",
        proposer="p",
        sibling_ids=["s1", "s2"],
        votes=[("s1", VOTE_REJECT), ("s2", VOTE_REJECT)],
    )
    res = await evaluate_quorum(
        outcome_id, veto_k=2, audit_stage="source_audit", **_MODELS,
    )
    assert res.reject_count == 2
    assert res.new_state == OUTCOME_STATE_REJECTED
    assert res.transition_occurred is True
    assert "veto" in res.transition_reason.lower()


async def test_no_active_voters_holds_for_operator(test_db) -> None:
    del test_db
    # Five NON-active (completed) siblings, zero votes -> the old fallback
    # auto-approved (a vacuous 0-vote ship). Now it must HOLD as draft for
    # operator review: no state transition, a held_for_operator reason.
    outcome_id = await _seed(
        inv="inv-q-novoters",
        proposer="p",
        sibling_ids=["s1", "s2", "s3", "s4", "s5"],
        votes=[],
        sibling_status="completed",
    )
    res = await evaluate_quorum(
        outcome_id, veto_k=1, audit_stage="source_audit", **_MODELS,
    )
    assert res.quorum_k == 3
    assert res.siblings_active == 0
    assert res.new_state == OUTCOME_STATE_DRAFT
    assert res.transition_occurred is False
    assert "held_for_operator_no_active_voters" in res.transition_reason
    assert "auto_approved" not in res.transition_reason


async def test_active_voters_block_premature_approval(test_db) -> None:
    del test_db
    # Five non-proposing siblings -> majority K=3; two approvals are short
    # of quorum, so the finding stays draft (no premature ship) and the
    # no-active-voters fallback must NOT fire while voters are alive.
    outcome_id = await _seed(
        inv="inv-q-hold",
        proposer="p",
        sibling_ids=["s1", "s2", "s3", "s4", "s5"],
        votes=[("s1", VOTE_APPROVE), ("s2", VOTE_APPROVE)],
    )
    res = await evaluate_quorum(
        outcome_id, veto_k=1, audit_stage="source_audit", **_MODELS,
    )
    assert res.quorum_k == 3
    assert res.approve_count == 2
    assert res.siblings_active == 5
    assert res.new_state == OUTCOME_STATE_DRAFT
    assert res.transition_occurred is False
    assert "auto_approved" not in res.transition_reason


# ----------------------------------------------------------------------
# #6 convergence fix -- ``not_ready`` is a first-class vote that
# records a blocker without moving approve or reject quorum. When
# every non-proposing sibling responds not_ready and no active voter
# remains, the draft stays in DRAFT with a ``blocked_pending_evidence``
# reason (NOT the ``held_for_operator_no_active_voters`` operator-hold
# banner that fires when the panel is genuinely silent).
# ----------------------------------------------------------------------


async def test_not_ready_records_without_moving_quorum(test_db) -> None:
    """Two approvals + three not_ready responses: not_ready is tallied
    but does not add to approve_count, so with K=3 the draft stays in
    DRAFT (no premature ship on a chorus of pending-evidence votes)."""
    del test_db
    outcome_id = await _seed(
        inv="inv-q-notready-partial",
        proposer="p",
        sibling_ids=["s1", "s2", "s3", "s4", "s5"],
        votes=[
            ("s1", VOTE_APPROVE),
            ("s2", VOTE_APPROVE),
            ("s3", VOTE_NOT_READY),
            ("s4", VOTE_NOT_READY),
            ("s5", VOTE_NOT_READY),
        ],
    )
    res = await evaluate_quorum(
        outcome_id, veto_k=1, audit_stage="source_audit", **_MODELS,
    )
    assert res.quorum_k == 3
    assert res.approve_count == 2
    assert res.not_ready_count == 3
    # State stays DRAFT: not_ready never adds to approve or reject.
    assert res.new_state == OUTCOME_STATE_DRAFT
    assert res.transition_occurred is False


async def test_all_siblings_not_ready_blocked_pending_evidence(
    test_db,
) -> None:
    """All non-proposing siblings vote not_ready (and are already
    completed so no active voters remain): draft stays in DRAFT with
    the ``blocked_pending_evidence`` reason -- NOT the operator-hold
    banner. This is the panel actively signaling "waiting on
    evidence", not a dead-panel needing operator intervention."""
    del test_db
    outcome_id = await _seed(
        inv="inv-q-notready-all",
        proposer="p",
        sibling_ids=["s1", "s2", "s3"],
        votes=[
            ("s1", VOTE_NOT_READY),
            ("s2", VOTE_NOT_READY),
            ("s3", VOTE_NOT_READY),
        ],
        sibling_status="completed",
    )
    res = await evaluate_quorum(
        outcome_id, veto_k=1, audit_stage="source_audit", **_MODELS,
    )
    assert res.not_ready_count == 3
    assert res.siblings_active == 0
    assert res.new_state == OUTCOME_STATE_DRAFT
    assert res.transition_occurred is False
    assert "blocked_pending_evidence" in res.transition_reason
    assert "held_for_operator" not in res.transition_reason
    assert "auto_approved" not in res.transition_reason


async def test_mixed_abstain_and_not_ready_falls_back_to_operator_hold(
    test_db,
) -> None:
    """Some siblings abstain + some not_ready + no active voters =
    the panel is not uniformly signaling pending-evidence, so the
    fallback stays with ``held_for_operator_no_active_voters`` (with
    ``not_ready`` surfaced in the reason)."""
    del test_db
    outcome_id = await _seed(
        inv="inv-q-notready-mixed",
        proposer="p",
        sibling_ids=["s1", "s2", "s3"],
        votes=[
            ("s1", VOTE_ABSTAIN),
            ("s2", VOTE_NOT_READY),
            ("s3", VOTE_NOT_READY),
        ],
        sibling_status="completed",
    )
    res = await evaluate_quorum(
        outcome_id, veto_k=1, audit_stage="source_audit", **_MODELS,
    )
    assert res.abstain_count == 1
    assert res.not_ready_count == 2
    assert res.new_state == OUTCOME_STATE_DRAFT
    assert res.transition_occurred is False
    assert "held_for_operator" in res.transition_reason
    assert "not_ready=2" in res.transition_reason
    assert "blocked_pending_evidence" not in res.transition_reason


async def test_not_ready_does_not_close_branch(test_db) -> None:
    """A not_ready vote leaves the draft in DRAFT and DOES NOT
    trigger sibling halt (which only fires on APPROVED). Belt-and-
    suspenders regression -- the sibling halt loop only runs on
    APPROVED transitions, and DRAFT never touches sibling.status."""
    del test_db
    outcome_id = await _seed(
        inv="inv-q-notready-branch",
        proposer="p",
        sibling_ids=["s1", "s2", "s3"],
        votes=[("s1", VOTE_NOT_READY)],
    )
    res = await evaluate_quorum(
        outcome_id, veto_k=1, audit_stage="source_audit", **_MODELS,
    )
    assert res.new_state == OUTCOME_STATE_DRAFT
    assert res.transition_occurred is False
    # And confirm the sibling rows are still active on the DB side
    # (the halt loop should NOT have fired).
    async with UnitOfWork() as uow:
        from sqlmodel import select as _sel
        rows = (await uow.session.exec(
            _sel(VRInvestigationBranchRecord).where(
                VRInvestigationBranchRecord.investigation_id
                == "inv-q-notready-branch",
            ),
        )).all()
    for row in rows:
        if row.id == "p":
            continue
        # Sibling rows created active; the halt path never ran.
        assert row.status == "active", (
            f"sibling {row.id} incorrectly halted on a not_ready vote"
        )
