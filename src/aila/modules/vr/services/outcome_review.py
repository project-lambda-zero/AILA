"""Draft-outcome review service (migration 062).

Lifecycle of one outcome:

    new outcome row written
              |
              v
        state='draft'  <-- one branch terminal-submitted
              |
              v
   sibling branches review
   (vote='approve' | 'reject' | 'request_edit' | 'abstain')
              |
       +------+------+
       |             |
   approve_count   any reject
   >= QUORUM_K      vote present
       |             |
       v             v
   state='approved'  state='rejected'
       |             |
       v             v
  dispatcher fires   branches resume;
       |             outcome stays as
       v             permanent record
  state='dispatched'

Quorum threshold ``QUORUM_K`` = ``max(2, ceil(non_proposing_siblings/2))``.
For a typical 6-branch investigation: 5 non-proposing siblings -> K=3.
For a 3-branch investigation: 2 non-proposing -> K=2. For a single-
branch investigation (no siblings): K=0 means the outcome auto-approves
on creation (no one to review, gate is a no-op).

Reject is a hard veto: a single reject flips the outcome to ``rejected``
and the gate refuses dispatch. The proposing branch can resume reasoning
and submit a new outcome, which is a fresh row (DRAFT again). The
rejected row is preserved as audit trail.

This module is the single source of truth for:
  * vote upsert (one row per branch per outcome)
  * quorum evaluation
  * state transition (draft -> approved | rejected)
  * sibling halt on approved
  * downstream dispatch trigger on approved
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

from sqlmodel import delete as _delete
from sqlmodel import select as _select

from aila.modules.vr.contracts import (
    BranchStatus,
    OperatorIntent,
    PayloadKind,
    SenderKind,
)
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationMessageRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationOutcomeReviewRecord,
)
from aila.platform.contracts._common import utc_now
from aila.platform.services.audit import record_audit_event
from aila.platform.uow import UnitOfWork

__all__ = [
    "OUTCOME_STATE_APPROVED",
    "OUTCOME_STATE_DISPATCHED",
    "OUTCOME_STATE_DRAFT",
    "OUTCOME_STATE_REJECTED",
    "VOTE_ABSTAIN",
    "VOTE_APPROVE",
    "VOTE_REJECT",
    "VOTE_REQUEST_EDIT",
    "compute_quorum",
    "evaluate_quorum",
    "post_draft_review_request",
    "set_outcome_state",
    "upsert_review",
]

_log = logging.getLogger(__name__)


OUTCOME_STATE_DRAFT = "draft"
OUTCOME_STATE_APPROVED = "approved"
OUTCOME_STATE_REJECTED = "rejected"
OUTCOME_STATE_DISPATCHED = "dispatched"

VOTE_APPROVE = "approve"
VOTE_REJECT = "reject"
VOTE_REQUEST_EDIT = "request_edit"
VOTE_ABSTAIN = "abstain"

_VALID_VOTES = frozenset({VOTE_APPROVE, VOTE_REJECT, VOTE_REQUEST_EDIT, VOTE_ABSTAIN})


@dataclass(slots=True)
class QuorumOutcome:
    """Result of evaluating quorum on a draft outcome."""

    outcome_id: str
    new_state: str  # 'draft' | 'approved' | 'rejected'
    approve_count: int
    reject_count: int
    request_edit_count: int
    abstain_count: int
    quorum_k: int
    siblings_active: int
    transition_occurred: bool
    transition_reason: str = ""


def compute_quorum(non_proposing_sibling_count: int) -> int:
    """Approve threshold for a draft outcome.

    fix §148 -- derive K from the count of non-proposing branches
    (a static investigation-level count), NOT from active-only siblings.
    Stale-abandoned siblings used to reduce the denominator, so a single
    approve vote could ship an outcome when 4 of 5 siblings had been
    abandoned. New formula matches the spec: ``max(N_total_personas - 1, 2)``
    where ``N_total_personas - 1`` is exactly the non-proposing count.
    Floor of 2 prevents a single rogue approver from auto-shipping; the
    no-active-voters fallback (later in evaluate_quorum) catches the
    case where K is unreachable because every voter is dead.

    >>> compute_quorum(0)  # single-branch investigation, no siblings
    0
    >>> compute_quorum(2)  # 3-branch: 2 non-proposing siblings, K=2
    2
    >>> compute_quorum(5)  # 6-branch: 5 non-proposing siblings, K=5
    5
    >>> compute_quorum(1)  # 2-branch: 1 non-proposing, K=2 (unreachable)
    2
    """
    if non_proposing_sibling_count <= 0:
        return 0
    return max(2, non_proposing_sibling_count)


def set_outcome_state(
    uow: UnitOfWork,
    outcome: VRInvestigationOutcomeRecord,
    new_state: str,
    *,
    reason: str,
) -> bool:
    """Single point for ``vr_investigation_outcomes.state`` writes.

    Fix §20 -- every direct ``outcome.state = ...`` write goes through
    this helper so the audit trail (``AuditEventRecord`` in the
    platform audit table) records the prior→new transition plus the
    caller-supplied reason. Without that row a forensic question of
    'who flipped this outcome and when' has only ``_log.info`` chatter
    to chase.

    Caller still owns the commit boundary -- this helper adds the
    outcome row + the audit row to the active session and returns.

    Args:
        uow: Active UnitOfWork. The outcome row was already loaded
            via ``uow.session`` so the same session adds both writes.
        outcome: ORM-attached outcome row.
        new_state: Target state. One of ``OUTCOME_STATE_*``.
        reason: Human-readable explanation (e.g. ``"approved_3_of_3_required"``,
            ``"dispatched_by_outcome_dispatcher"``). Stored in the
            audit row's ``details_json``.

    Returns:
        True when a transition occurred (prior_state != new_state);
        False when ``outcome.state`` already equals ``new_state``
        (no-op call, no audit row written).

    §14 known callers (single source of truth for outcome state
    transitions across the codebase):
      - ``services/outcome_review.evaluate_quorum`` -- draft → approved /
        rejected based on sibling votes.
      - ``agents/outcome_dispatcher._update_outcome_status`` --
        approved → dispatched on successful downstream ship.
    The synthesis_agent path (``agents/synthesis_agent``) does NOT
    write ``outcome.state`` -- it updates ``payload_json`` and
    ``confidence`` on the canonical row and flips investigation
    ``status`` instead; the outcome's state continues to be owned by
    the two callers above. New writers MUST route through this
    helper.

    Phase B note. Phase B routes outcome state transitions through
    the workflow engine (one transition row in
    ``workflow_state_transitions``, no direct column write). When
    that lands this helper becomes a thin wrapper that delegates to
    the engine; the call sites here stay unchanged.
    """
    prior_state = outcome.state
    if prior_state == new_state:
        return False
    outcome.state = new_state
    uow.session.add(outcome)

    # Audit trail. Platform-owned audit table -- same table the
    # workflow engine writes its transition rows to (engine.py:1000)
    # so an operator querying by run_id sees a single chronological
    # stream of state changes.
    record_audit_event(
        uow.session,
        run_id=outcome.investigation_id,
        stage="vr.outcome",
        action=f"outcome_state:{prior_state}->{new_state}",
        target=f"outcome:{outcome.id}",
        details={
            "outcome_id": outcome.id,
            "prior_state": prior_state,
            "new_state": new_state,
            "reason": reason,
        },
    )
    _log.info(
        "outcome_state STATE %s -> %s outcome=%s reason=%s",
        prior_state, new_state, outcome.id, reason,
    )
    return True


async def upsert_review(
    *,
    outcome_id: str,
    reviewer_branch_id: str,
    vote: str,
    comment: str = "",
    suggested_edits: dict[str, Any] | None = None,
) -> VRInvestigationOutcomeReviewRecord:
    """Insert-or-update one sibling's vote on a draft outcome.

    Idempotent per (outcome_id, reviewer_branch_id): the latest call
    replaces any prior vote from the same branch. Caller is responsible
    for separately calling :func:`evaluate_quorum` after the upsert
    completes -- the two are split so a transaction can group several
    reviews and evaluate quorum once at the end.

    Raises ``ValueError`` on unknown vote string, missing outcome row,
    or missing reviewer branch row.

    ``suggested_edits_json`` contract (fix §170)
    --------------------------------------------
    When ``vote == 'request_edit'`` the agent may attach a
    ``suggested_edits`` payload (e.g. ``{"confidence": "weak"}``,
    ``{"answer": "corrected text"}``). That payload is persisted on the
    review row as ``suggested_edits_json`` and is **consumed by the
    synthesis agent** when it merges per-persona panel contributions
    into the canonical outcome. See :class:`aila.modules.vr.agents.
    synthesis_agent.SynthesisAgent.run` -- that is the ONE place
    suggested edits get folded back into the canonical narrative.

    Structured per-row semantics for downstream readers:

    - ``suggested_edits_json``      stored as JSON (this function).
    - ``applied_by_synthesis: bool`` IMPLICIT contract -- there is no
      column for it; the synthesis agent's panel-merge step is the
      sole consumer and operates idempotently (its ``panel_summary``
      marker on the canonical outcome means the merge has incorporated
      every review row visible at synthesis time). A future ``applied_at``
      column on the review row would let the synthesis agent record
      provenance per suggestion, but the current contract is "all
      review rows belonging to the canonical outcome MUST be reread
      on every synthesis run" -- no per-row applied bit required.

    DESIGN (fix §170): chose option (b) from prior design notes §4 --
    synthesis-agent consumption rather than a frontend Apply button.
    Rationale: (a) needs a frontend project + operator-gated API + a
    second write path on the canonical outcome; (b) reuses the
    existing synthesis chokepoint that ALREADY merges per-persona
    contributions, runs without operator clicks, and folds the
    correction into the same panel_summary the operator already reads.
    The two-path version (a)+(b) was rejected as a duplicate-write
    risk against Golden Rule #19 (don't repeat yourself).
    """
    if vote not in _VALID_VOTES:
        raise ValueError(
            f"unknown vote {vote!r}; expected one of {sorted(_VALID_VOTES)}",
        )
    suggested = suggested_edits or {}

    async with UnitOfWork() as uow:
        outcome = (await uow.session.exec(
            _select(VRInvestigationOutcomeRecord).where(
                VRInvestigationOutcomeRecord.id == outcome_id,
            ),
        )).first()
        if outcome is None:
            raise ValueError(f"outcome {outcome_id} not found")

        reviewer = (await uow.session.exec(
            _select(VRInvestigationBranchRecord).where(
                VRInvestigationBranchRecord.id == reviewer_branch_id,
            ),
        )).first()
        if reviewer is None:
            raise ValueError(
                f"reviewer branch {reviewer_branch_id} not found",
            )

        # Wipe any prior vote from this branch on this outcome -- the
        # UNIQUE(outcome_id, reviewer_branch_id) constraint forces the
        # delete-then-insert dance because sqlmodel doesn't expose an
        # ON CONFLICT helper across dialects.
        await uow.session.exec(
            _delete(VRInvestigationOutcomeReviewRecord).where(
                VRInvestigationOutcomeReviewRecord.outcome_id == outcome_id,
                VRInvestigationOutcomeReviewRecord.reviewer_branch_id
                == reviewer_branch_id,
            ),
        )

        row = VRInvestigationOutcomeReviewRecord(
            outcome_id=outcome_id,
            reviewer_branch_id=reviewer_branch_id,
            reviewer_persona=reviewer.persona_voice or "unknown",
            vote=vote,
            comment=comment,
            suggested_edits_json=json.dumps(suggested),
        )
        uow.session.add(row)
        await uow.commit()
        await uow.session.refresh(row)

    # fix §170 -- synthesis agent consumes -- see merge_panel_contributions
    # (i.e. SynthesisAgent.run in agents/synthesis_agent.py -- the
    # consolidator step that reads every contribution + review on the
    # canonical outcome and folds them into ``panel_summary``).
    #
    # DESIGN: option (b) chosen -- agent-driven consumption rather than
    # a frontend-Apply path. Until the synthesis agent's
    # _load_panel_reviews step lands (TODO: wire the SELECT against
    # vr_investigation_outcome_reviews into SynthesisAgent.run so it
    # passes suggested_edits into the LLM panel-render), this WARNING
    # is the visible-in-logs marker that a request_edit vote is
    # waiting on synthesis pickup. After the wiring lands, drop the
    # warning -- the merge step makes the suggestion non-silent by
    # construction.
    #
    # NOTE on ``applied_by_synthesis``: the docstring above documents
    # this as an IMPLICIT contract bit, not a DB column. Synthesis is
    # the sole consumer and runs idempotently against panel_summary;
    # we do NOT need a per-row applied flag because re-running
    # synthesis is a no-op once panel_summary is set.
    if suggested:
        _log.warning(
            "outcome_review.suggested_edits_pending_synthesis -- "
            "outcome=%s branch=%s persona=%s vote=%s edits_keys=%s. "
            "Suggestion stored on review row; will be picked up by "
            "SynthesisAgent.run on next synthesis (see fix §170 "
            "design note in services/outcome_review.upsert_review).",
            outcome_id, reviewer_branch_id, row.reviewer_persona, vote,
            sorted(suggested.keys()),
        )
    _log.info(
        "outcome_review UPSERT outcome=%s branch=%s persona=%s vote=%s",
        outcome_id, reviewer_branch_id, row.reviewer_persona, vote,
    )
    return row


async def evaluate_quorum(outcome_id: str) -> QuorumOutcome:
    """Tally reviews + flip state if a threshold is reached.

    Returns a snapshot of vote counts AND whether the state moved this
    call. When ``new_state`` is APPROVED, the caller (usually the
    review tool handler or an API endpoint) is responsible for
    triggering the actual dispatch via ``OutcomeDispatcher.dispatch``.

    Sibling halt happens here: when state flips to APPROVED, every
    sibling branch with ``status == 'active'`` and no terminal outcome
    submitted yet is closed with reason ``sibling_outcome_approved``.
    This frees worker capacity immediately -- without the halt, siblings
    keep being re-enqueued and burn turns on a question already
    answered.
    """
    async with UnitOfWork() as uow:
        outcome = (await uow.session.exec(
            _select(VRInvestigationOutcomeRecord).where(
                VRInvestigationOutcomeRecord.id == outcome_id,
            ),
        )).first()
        if outcome is None:
            raise ValueError(f"outcome {outcome_id} not found")

        prior_state = outcome.state or OUTCOME_STATE_DRAFT
        investigation_id = outcome.investigation_id
        proposing_branch_id = outcome.branch_id

        # Tally votes.
        reviews = (await uow.session.exec(
            _select(VRInvestigationOutcomeReviewRecord).where(
                VRInvestigationOutcomeReviewRecord.outcome_id == outcome_id,
            ),
        )).all()
        approve_count = sum(1 for r in reviews if r.vote == VOTE_APPROVE)
        reject_count = sum(1 for r in reviews if r.vote == VOTE_REJECT)
        request_edit_count = sum(
            1 for r in reviews if r.vote == VOTE_REQUEST_EDIT
        )
        abstain_count = sum(1 for r in reviews if r.vote == VOTE_ABSTAIN)

        # Count siblings that exist to review (any non-proposing branch
        # in the same investigation). Closed branches still count as
        # eligible reviewers -- they could have voted before closing --
        # but we don't expect new votes from them.
        siblings = (await uow.session.exec(
            _select(VRInvestigationBranchRecord).where(
                VRInvestigationBranchRecord.investigation_id == investigation_id,
                VRInvestigationBranchRecord.id != proposing_branch_id,
            ),
        )).all()
        non_proposing_count = len(siblings)
        quorum_k = compute_quorum(non_proposing_count)
        # ACTIVE siblings are the only ones the halt loop touches. The
        # ``PAUSED`` filter below is defensive -- PAUSED is already not
        # in ACTIVE, but if someone broadens this filter later the halt
        # guard at the per-sibling loop will still skip them.
        active_siblings = [
            b for b in siblings if b.status == BranchStatus.ACTIVE.value
        ]
        # fix §78 -- count PAUSED siblings as "potentially voting once
        # resumed". The no-active-voters auto-approve must NOT fire
        # when there are PAUSED siblings that could vote later; treating
        # them as dead voters would let the operator's pause survive a
        # silent auto-approval and a phantom resume on a terminal
        # investigation.
        paused_siblings_count = sum(
            1 for b in siblings if b.status == BranchStatus.PAUSED.value
        )

        new_state = prior_state
        transition_reason = ""

        # If the gate is a no-op (no siblings, K=0) and state is still
        # draft, auto-approve. The dispatcher would otherwise refuse a
        # legitimately complete single-branch investigation.
        if (
            prior_state == OUTCOME_STATE_DRAFT
            and quorum_k == 0
        ):
            new_state = OUTCOME_STATE_APPROVED
            transition_reason = "auto_approved_no_siblings"

        # Fallback: siblings exist (quorum_k > 0) but every single one
        # is already non-active (completed/abandoned) and the recorded
        # votes are still below quorum. Nobody can ever vote on this
        # outcome -- auto-approve so the investigation can settle.
        # Stamps the transition with a distinct reason so the operator
        # can audit which outcomes shipped without sibling corroboration.
        # The pre-submit draft_pending gate (vuln_researcher) is the
        # primary mitigation; this is the safety net for investigations
        # that predate the gate or hit the gate's blind spots.
        # fix §78 -- gate the fallback on PAUSED count too: if there are
        # paused siblings, they may resume and vote, so do not collapse
        # to auto-approve. Operator action (pause) blocks auto-settle.
        if (
            prior_state == OUTCOME_STATE_DRAFT
            and quorum_k > 0
            and len(active_siblings) == 0
            and paused_siblings_count == 0
            and (approve_count + reject_count) < quorum_k
        ):
            new_state = OUTCOME_STATE_APPROVED
            transition_reason = (
                f"auto_approved_no_active_voters_"
                f"approve={approve_count}_reject={reject_count}_"
                f"abstain={abstain_count}_k={quorum_k}"
            )

        # Reject is hard veto, evaluated before approve.
        if (
            prior_state == OUTCOME_STATE_DRAFT
            and reject_count >= 1
        ):
            new_state = OUTCOME_STATE_REJECTED
            transition_reason = (
                f"vetoed_by_{reject_count}_sibling"
                + ("s" if reject_count > 1 else "")
            )

        elif (
            prior_state == OUTCOME_STATE_DRAFT
            and approve_count >= quorum_k
        ):
            new_state = OUTCOME_STATE_APPROVED
            transition_reason = (
                f"approved_{approve_count}_of_{quorum_k}_required"
            )

        transition_occurred = new_state != prior_state
        if transition_occurred:
            # fix §20 -- route the state write through set_outcome_state
            # so the audit trail (AuditEventRecord) captures the
            # prior->new flip alongside the quorum derivation reason.
            set_outcome_state(uow, outcome, new_state, reason=transition_reason)
            # Sibling halt on approval. Closed (=ABANDONED) so the
            # branch stops being re-enqueued and the UI shows it as
            # done rather than perpetually active.
            if new_state == OUTCOME_STATE_APPROVED:
                for sibling in active_siblings:
                    # fix §78 -- defensive guard: skip PAUSED branches
                    # should they ever appear in active_siblings (the filter
                    # above currently excludes them, but a future change
                    # could broaden it). Operator-paused branches must
                    # NOT be flipped to ABANDONED here -- the pause is
                    # the operator's explicit hold; halting via ABANDONED
                    # would lose that semantic and prevent resume.
                    if sibling.status == BranchStatus.PAUSED.value:
                        continue
                    sibling.status = BranchStatus.ABANDONED.value
                    sibling.closed_reason = (
                        f"sibling_outcome_approved:{outcome_id}"
                    )
                    sibling.closed_at = utc_now()
                    uow.session.add(sibling)
                _log.info(
                    "outcome_review HALT_SIBLINGS outcome=%s "
                    "halted_count=%d",
                    outcome_id, len(active_siblings),
                )
            await uow.commit()
            _log.info(
                "outcome_review STATE %s -> %s outcome=%s reason=%s "
                "approve=%d reject=%d k=%d siblings=%d",
                prior_state, new_state, outcome_id, transition_reason,
                approve_count, reject_count, quorum_k, non_proposing_count,
            )

    return QuorumOutcome(
        outcome_id=outcome_id,
        new_state=new_state,
        approve_count=approve_count,
        reject_count=reject_count,
        request_edit_count=request_edit_count,
        abstain_count=abstain_count,
        quorum_k=quorum_k,
        siblings_active=len(active_siblings),
        transition_occurred=transition_occurred,
        transition_reason=transition_reason,
    )


async def post_draft_review_request(
    *,
    investigation_id: str,
    outcome_id: str,
    proposing_branch_id: str,
    proposing_persona: str,
    outcome_kind: str,
    confidence: str,
    payload_summary: str,
) -> str:
    """Post a system-authored message that tells every sibling there's
    a draft outcome up for review.

    Lands at OPERATOR position on the next prompt for every branch
    (same shape auto_steering uses). The message text spells out
    exactly how to respond: call the ``submit_outcome_review`` action
    with vote and rationale.

    Idempotent: if a review-request message for the same outcome was
    already posted, this is a no-op and returns the existing message
    id. Without this guard, every re-entry of the ``investigation_emit``
    state (e.g. after a sibling vote, after a workflow restart, after
    operator pause/resume) re-posts the same notice, producing the spam
    pattern operators have reported.
    """
    auto_steering_key = f"draft_review_request:{outcome_id}"
    text = (
        f"*** DRAFT OUTCOME UP FOR REVIEW ***\n"
        f"\n"
        f"{proposing_persona} (branch {proposing_branch_id[:8]}) submitted "
        f"a terminal {outcome_kind} outcome with confidence={confidence}.\n"
        f"\n"
        f"Outcome id: {outcome_id}\n"
        f"\n"
        f"Summary:\n{payload_summary}\n"
        f"\n"
        f"This outcome will NOT dispatch until siblings corroborate it. "
        f"Your next turn MUST be a submit_outcome_review action with one "
        f"of these votes:\n"
        f"  - approve       -- you have independently verified the claims "
        f"and they hold.\n"
        f"  - reject        -- at least one claim is wrong (file path, "
        f"line number, semantics). One reject vetoes the whole outcome.\n"
        f"  - request_edit  -- claims are mostly right but need correction. "
        f"Include suggested_edits with specific changes.\n"
        f"  - abstain       -- you have not investigated this code path "
        f"and cannot judge.\n"
        f"\n"
        f"DO NOT keep generating new hypotheses while a draft is up -- "
        f"review the existing one. The submit_outcome_review action "
        f"requires you to GROUND every claim against actual source via "
        f"audit_mcp.read_lines / read_function before you can approve. "
        f"If you cannot ground a claim, vote reject or abstain."
    )
    # fix §248 -- exact-key dedup via the indexed ``auto_steering_key``
    # column added by migration 063 (originally for auto_steering, but
    # the column is generic -- it's the canonical "system-authored
    # message dedup sentinel"). No new migration needed.
    #
    # Why no separate ``dedup_key`` column: 063 already provides the
    # exact shape we need -- VARCHAR(128) NULL with a partial UNIQUE
    # index on (investigation_id, auto_steering_key) WHERE NOT NULL,
    # and a composite index for the read path. Adding a parallel
    # ``dedup_key`` column would duplicate schema for the same purpose;
    # we reuse the existing column and document the name as historical.
    #
    # Atomicity: we fire the INSERT first and rely on the UNIQUE
    # constraint for racing concurrent callers (same pattern auto_steering
    # uses, see fix §338). If two parallel re-entries of investigation_emit
    # both miss the read check, the second INSERT raises IntegrityError;
    # we look up the surviving row and return its id. No SELECT FOR
    # UPDATE needed because the unique constraint provides the
    # serialization point at write time.
    from sqlalchemy.exc import IntegrityError

    async with UnitOfWork() as uow:
        # Idempotency: skip if a request for the same outcome already exists.
        existing = (await uow.session.exec(
            _select(VRInvestigationMessageRecord)
            .where(
                VRInvestigationMessageRecord.investigation_id == investigation_id,
            )
            .where(
                VRInvestigationMessageRecord.auto_steering_key == auto_steering_key,
            )
            .limit(1),
        )).first()
        if existing is not None:
            return existing.id

        msg = VRInvestigationMessageRecord(
            investigation_id=investigation_id,
            branch_id=proposing_branch_id,
            # fix §250 -- system-authored. Previously OPERATOR (the only
            # broadcast-tagged kind). vuln_researcher.py:1077 broadcast
            # filter expanded to {OPERATOR, SYSTEM} so siblings still see
            # this message; SenderKind enum + the filter update ship
            # together in this commit.
            sender_kind=SenderKind.SYSTEM.value,
            sender_id="outcome_review",
            payload_kind=PayloadKind.TEXT.value,
            payload_json=json.dumps({
                "text": text,
                "auto_steering_key": auto_steering_key,
                "outcome_id": outcome_id,
            }),
            operator_intent=OperatorIntent.STEERING.value,
            # fix §248 -- populate the indexed dedup column so the
            # UNIQUE constraint catches concurrent re-entry races.
            auto_steering_key=auto_steering_key,
            created_at=utc_now(),
        )
        uow.session.add(msg)
        # fix §251 -- ``uow.commit()`` is the canonical UnitOfWork API:
        # ``platform/uow.py`` defines it as a thin wrapper around
        # ``self.session.commit()``. Both call shapes commit the
        # currently-open transaction, but ``uow.commit()`` is preferred
        # so the UoW remains the single coordination point if it ever
        # grows additional hooks (audit, team-context flush, etc.).
        # Other call sites in this file (lines ~210, ~378) already use
        # this form; the inconsistent ``uow.session.commit()`` callers
        # in pattern_store / outcome_dispatcher / target_analysis are
        # not structural drift -- same behaviour today -- but should
        # converge on ``uow.commit()`` opportunistically.
        try:
            await uow.commit()
        except IntegrityError:
            # fix §248 -- race window between the read check and the
            # write: a concurrent re-entry inserted the same key
            # first. Roll back the failed insert (auto on session
            # exit) and look up the surviving row in a fresh UoW.
            await uow.rollback()
            _log.info(
                "outcome_review.post_draft_review_request race-deduped "
                "inv=%s outcome=%s key=%s",
                investigation_id, outcome_id, auto_steering_key,
            )
            async with UnitOfWork() as lookup:
                surviving = (await lookup.session.exec(
                    _select(VRInvestigationMessageRecord)
                    .where(
                        VRInvestigationMessageRecord.investigation_id
                        == investigation_id,
                    )
                    .where(
                        VRInvestigationMessageRecord.auto_steering_key
                        == auto_steering_key,
                    )
                    .limit(1),
                )).first()
                if surviving is None:
                    # Unique-violation but no surviving row? DB is in
                    # an unexpected state; surface loudly.
                    raise
                return surviving.id
        await uow.session.refresh(msg)
        return msg.id
