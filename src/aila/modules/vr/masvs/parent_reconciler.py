"""Lifecycle reconciler for MASVS audit parent investigations.

A MASVS audit fans out into one parent ``VRInvestigationRecord``
(``kind=masvs_audit``) plus N child investigations
(``kind=audit``, each linked via ``parent_investigation_id``). The
dispatcher commits the parent at ``status=CREATED`` and submits each
child to the ``vr`` ARQ queue. Nothing else tracks the batch
lifecycle: without this reconciler the parent sits at ``CREATED``
forever even after every child finishes, leaving the operator UI
(R-4 "Download MASVS report" button, D-5 progress card) unable to
tell when the batch has actually completed.

This reconciler runs every minute via the existing ARQ cron, side
by side with ``investigation_reaper`` and ``branch_reaper`` in
``aila.platform.tasks.worker._run_reaper_block``. Per active batch
parent it counts children grouped by status and applies one of two
atomic transitions:

  ``CREATED  → RUNNING``    once at least one child has progressed
                            past ``CREATED`` (so the operator UI flips
                            to "running" the moment the first worker
                            picks up the queue).
  ``CREATED/RUNNING → COMPLETED``
                            once every child has reached a terminal
                            status (``COMPLETED`` / ``FAILED`` /
                            ``ABANDONED``).

``PAUSED`` children keep the parent in ``RUNNING`` so an operator's
pause-then-resume of one child does not flip the batch into a fake
terminal state. ``PAUSED`` parents themselves are excluded from the
candidate set so an operator-initiated pause of the batch root is
honoured.

Concurrency: both transitions are issued as ``UPDATE ... WHERE
status IN (<expected before>)``. A concurrent operator action that
flipped a parent into ``ABANDONED`` or ``FAILED`` between the
candidate read and the update simply causes the update to match zero
rows; the reconciler does not overwrite human-driven status changes.
``rowcount`` distinguishes a real transition from a lost race.

Defensive: parents with zero visible children are skipped. The
dispatcher commits parent + children atomically, so a zero-child
parent is either an in-flight rollback or a manual stub the
reconciler must not flip into ``COMPLETED`` with nothing underneath.
"""
from __future__ import annotations

import logging
import os
from datetime import timedelta

from sqlalchemy import func, select, update
from sqlalchemy.sql.functions import coalesce

from aila.modules.vr._task_queue import default_task_queue
from aila.modules.vr.contracts import (
    BranchStatus,
    InvestigationKind,
    InvestigationStatus,
)
from aila.modules.vr.contracts.target import TargetKind
from aila.modules.vr.db_models import VRInvestigationRecord, VRTargetRecord
from aila.modules.vr.workflow.task import run_vr_investigate
from aila.platform.contracts._common import utc_now
from aila.platform.tasks.models import TaskRecord
from aila.platform.uow import UnitOfWork

__all__ = ["sweep_masvs_audit_parents"]

_log = logging.getLogger(__name__)

_TERMINAL_STATUSES: frozenset[str] = frozenset(
    (
        InvestigationStatus.COMPLETED.value,
        InvestigationStatus.FAILED.value,
        InvestigationStatus.ABANDONED.value,
    ),
)


def _batch_size() -> int:
    """Read MASVS_AUDIT_BATCH_SIZE env var with safe default.

    Keeps tunable read inline (cheap) instead of cached at import — an
    operator can flip the env between dispatches and the next reconciler
    tick picks up the new value.
    """
    try:
        n = int(os.environ.get("MASVS_AUDIT_BATCH_SIZE", "5"))
    except ValueError:
        n = 5
    return max(1, n)


async def _refill_apk_batches(uow: UnitOfWork) -> int:
    """Top up in-flight slots for every APK MASVS audit parent.

    For each parent whose target is ``android_apk``, ensure no more than
    ``_batch_size()`` children are in-flight (RUNNING / QUEUED) at any
    given moment. When slots are free and CREATED children remain that
    have never been enqueued (no TaskRecord row containing the child id),
    submit the next slice on the ``vr`` queue.

    Returns the total number of children newly enqueued in this tick.

    Why APK-only: source_repo / cve / patch_diff MASVS audits don't strain
    the local LLM proxy (no jadx tree, no 64K-token contexts). APK audits
    OOM'd OmniRoute when 30 streams hit simultaneously — this throttle
    keeps that pressure bounded.

    Why not a column for "enqueued?": adding one needs a migration. The
    TaskRecord JOIN below uses the existing JSONB cmd-line containment
    operator, which is fast enough for the per-parent ≤46-child set we
    sweep once per minute.
    """
    inv = VRInvestigationRecord
    tgt = VRTargetRecord
    tsk = TaskRecord
    batch_size = _batch_size()

    # APK MASVS parents currently in CREATED / RUNNING. Joined to the
    # target row so we can filter on target.kind without a second round
    # trip per parent.
    parent_rows = (
        await uow.session.exec(
            select(inv.id, tgt.id)
            .join(tgt, tgt.id == inv.target_id)
            .where(inv.kind == InvestigationKind.MASVS_AUDIT.value)
            .where(inv.parent_investigation_id.is_(None))
            .where(inv.status.in_((
                InvestigationStatus.CREATED.value,
                InvestigationStatus.RUNNING.value,
            )))
            .where(tgt.kind == TargetKind.ANDROID_APK.value),
        )
    ).all()
    if not parent_rows:
        return 0

    enqueued_total = 0
    queue = default_task_queue()

    for parent_id, _target_id in parent_rows:
        # Count children currently consuming a slot. CREATED counts only
        # when a TaskRecord exists (the child has been enqueued, just not
        # picked up yet); CREATED children with no TaskRecord are the
        # virgin pool we'll draw from.
        def _scalar(row: object) -> int:
            if row is None:
                return 0
            try:
                return int(row[0]) if hasattr(row, "__getitem__") else int(row)
            except (TypeError, ValueError, IndexError):
                return 0

        in_flight_row = (
            await uow.session.exec(
                select(func.count(inv.id))
                .where(inv.parent_investigation_id == parent_id)
                .where(inv.status.in_((
                    InvestigationStatus.RUNNING.value,
                    InvestigationStatus.PAUSED.value,
                ))),
            )
        ).first()
        in_flight = _scalar(in_flight_row)

        # Add CREATED children that ALREADY have a TaskRecord — they're
        # enqueued, just sitting in the queue waiting for a worker. They
        # count toward in_flight so we don't double-enqueue.
        created_with_task_row = (
            await uow.session.exec(
                select(func.count(inv.id))
                .where(inv.parent_investigation_id == parent_id)
                .where(inv.status == InvestigationStatus.CREATED.value)
                .where(
                    select(tsk.id)
                    .where(tsk.kwargs_json.ilike(
                        func.concat("%", inv.id, "%"),
                    ))
                    .exists(),
                ),
            )
        ).first()
        in_flight += _scalar(created_with_task_row)

        slots = batch_size - int(in_flight)
        if slots <= 0:
            continue

        # Virgin CREATED children: no TaskRecord for this investigation_id.
        # Order by created_at to enqueue oldest-first (preserves the
        # operator-visible MASVS control id order from the dispatcher).
        virgin = (
            await uow.session.exec(
                select(inv.id)
                .where(inv.parent_investigation_id == parent_id)
                .where(inv.status == InvestigationStatus.CREATED.value)
                .where(
                    ~select(tsk.id)
                    .where(tsk.kwargs_json.ilike(
                        func.concat("%", inv.id, "%"),
                    ))
                    .exists(),
                )
                .order_by(inv.created_at)
                .limit(slots),
            )
        ).all()

        for row in virgin:
            # Row tuples → unwrap to scalar string. SQLModel session.exec
            # returns Row tuples for select(scalar_column); we want the
            # plain UUID/str value for the task kwarg.
            if hasattr(row, "__getitem__") and not isinstance(row, str):
                child_id = str(row[0])
            else:
                child_id = str(row)
            try:
                await queue.submit(
                    track="vr",
                    fn=run_vr_investigate,
                    kwargs={"investigation_id": child_id},
                    user_id="system",
                    group_id="system",
                    team_id=None,
                )
                enqueued_total += 1
            except Exception as exc:  # noqa: BLE001 — submission is best-effort
                _log.warning(
                    "masvs batch refill: parent=%s child=%s enqueue failed: %s",
                    parent_id, child_id, exc,
                )
                break  # bail this parent; next tick will retry

    if enqueued_total:
        _log.info(
            "masvs_batch_refill: %d children enqueued across %d parent(s) "
            "(batch_size=%d)",
            enqueued_total, len(parent_rows), batch_size,
        )
    return enqueued_total


async def _enforce_total_turn_cap(uow: UnitOfWork) -> int:
    """Force-close children whose total turn count across all branches
    exceeds ``VR_INVESTIGATION_TOTAL_TURN_CAP`` (default 200).

    Why: ``vuln_researcher``'s per-task ``max_turns`` (70) auto-re-enqueues
    on overflow (``investigation_emit.py:181``), keeping branches alive
    forever when no terminal_submit lands. Cost cap is broken
    (``cost_actual_usd`` stays 0). Without a cumulative ceiling the audit
    pipeline burns LLM tokens indefinitely on children that won't
    naturally converge — operator's 4-of-5 stuck investigations on
    MASVS audit 5d627a39 had 6 branches each pushing toward 70 turns
    with zero terminal outcomes and re-enqueue waiting.

    Algorithm: for every RUNNING child of a MASVS-kind parent (or
    standalone running investigation), sum ``turn_count`` across all
    its branches. If sum > cap:
      - abandon every active branch with
        ``closed_reason='exhausted_total_turn_cap'``;
      - if the investigation has a draft primary outcome, leave it —
        the inline ``evaluate_quorum`` call below hits
        ``auto_approved_no_active_voters``
        (``services/outcome_review.py:290-301``) and ships it;
      - if NO draft, mark investigation ``status=completed`` with
        ``pause_reason='exhausted_total_turn_cap'`` so the dashboard
        shows the honest signal.

    Returns the count of investigations force-closed this tick.
    """
    try:
        cap = int(os.environ.get("VR_INVESTIGATION_TOTAL_TURN_CAP", "200"))
    except ValueError:
        cap = 200
    cap = max(50, cap)  # floor so a typo doesn't kill everything

    inv = VRInvestigationRecord
    from aila.modules.vr.db_models import (  # noqa: PLC0415
        VRInvestigationBranchRecord,
    )

    over_cap_rows = (
        await uow.session.exec(
            select(
                inv.id,
                func.coalesce(
                    func.sum(VRInvestigationBranchRecord.turn_count), 0,
                ).label("total_turns"),
            )
            .join(
                VRInvestigationBranchRecord,
                VRInvestigationBranchRecord.investigation_id == inv.id,
                isouter=True,
            )
            .where(inv.parent_investigation_id.isnot(None))
            .where(inv.status == InvestigationStatus.RUNNING.value)
            .group_by(inv.id)
            .having(
                func.coalesce(
                    func.sum(VRInvestigationBranchRecord.turn_count), 0,
                ) > cap,
            ),
        )
    ).all()

    if not over_cap_rows:
        return 0

    force_closed = 0
    for inv_id, total_turns in over_cap_rows:
        await uow.session.exec(
            update(VRInvestigationBranchRecord)
            .where(VRInvestigationBranchRecord.investigation_id == inv_id)
            .where(
                VRInvestigationBranchRecord.status
                == BranchStatus.ACTIVE.value,
            )
            .values(
                status=BranchStatus.ABANDONED.value,
                closed_reason=f"exhausted_total_turn_cap:total={total_turns}",
                closed_at=utc_now(),
                updated_at=utc_now(),
            ),
        )

        target_inv = (
            await uow.session.exec(
                select(inv).where(inv.id == inv_id),
            )
        ).first()
        has_draft = False
        if target_inv and target_inv.primary_outcome_id:
            from aila.modules.vr.db_models import (  # noqa: PLC0415
                VRInvestigationOutcomeRecord,
            )
            o = (await uow.session.exec(
                select(VRInvestigationOutcomeRecord).where(
                    VRInvestigationOutcomeRecord.id
                    == target_inv.primary_outcome_id,
                ),
            )).first()
            if o and o.state == "draft":
                has_draft = True

        if not has_draft and target_inv:
            target_inv.status = InvestigationStatus.COMPLETED.value
            target_inv.pause_reason = (
                f"exhausted_total_turn_cap:total_turns={total_turns}"
            )
            target_inv.stopped_at = utc_now()
            target_inv.updated_at = utc_now()
            uow.session.add(target_inv)

        force_closed += 1
        _log.warning(
            "cumulative_turn_cap_hit inv=%s total_turns=%d cap=%d has_draft=%s",
            inv_id, total_turns, cap, has_draft,
        )

    await uow.commit()

    # Kick the quorum re-eval for any exhausted investigation that had
    # a draft outcome so the auto_approved_no_active_voters branch fires
    # this tick.
    from aila.modules.vr.services.outcome_review import (  # noqa: PLC0415
        evaluate_quorum,
    )
    for inv_id, _ in over_cap_rows:
        target_inv = (
            await uow.session.exec(
                select(inv).where(inv.id == inv_id),
            )
        ).first()
        if target_inv and target_inv.primary_outcome_id:
            try:
                await evaluate_quorum(target_inv.primary_outcome_id)
            except (OSError, RuntimeError, ValueError) as exc:
                _log.warning(
                    "cumulative_turn_cap_hit inv=%s outcome=%s "
                    "re-eval failed: %s",
                    inv_id, target_inv.primary_outcome_id, exc,
                )

    return force_closed


_MIN_DRAFT_AGE_TURNS = 8


async def _escalate_stuck_drafts(uow: UnitOfWork) -> int:
    """Inject mandatory-vote directive into branches that haven't voted
    on a draft outcome older than ``_MIN_DRAFT_AGE_TURNS`` (= 8 turns).

    The natural quorum path requires every active sibling to:
      1. notice the draft directive in their prompt,
      2. choose to interrupt their own audit, and
      3. emit ``submit_outcome_review`` with vote=approve/reject.

    Critic-persona branches (yuki / maddie) often skip step 2 — they
    keep chasing their own hypothesis tree past 30+ turns, and the
    draft sits without enough approves to reach quorum. Observed live
    on ``0887ffe7`` / ``0afb0643`` / ``1ee0c949`` — 5 sibling branches
    per investigation, ZERO votes cast on their respective drafts.

    This escalator fires every reconciler tick (~once/minute). For
    each draft older than the threshold:
      - find every active non-proposer sibling that has NOT yet voted
        (no row in ``vr_outcome_reviews`` for this branch+outcome);
      - update each such branch's ``case_state_json`` to set
        ``observables["_directive.mandatory_vote_now"]`` to the
        escalation text;
      - the directive renders into the next per-turn prompt
        (``render_case_model``) and the agent's structured-output
        schema makes ``submit_outcome_review`` the obvious action.

    Returns the count of branches that received the directive this
    tick. Idempotent: re-setting the same directive on the same branch
    is a no-op for the agent (already sees it on next turn).
    """
    import json as _json_local  # noqa: PLC0415

    from aila.modules.vr.db_models import (  # noqa: PLC0415
        VRInvestigationBranchRecord,
        VRInvestigationOutcomeRecord,
    )
    from aila.modules.vr.db_models.outcome_review import (  # noqa: PLC0415
        VRInvestigationOutcomeReviewRecord,
    )

    inv = VRInvestigationRecord
    out = VRInvestigationOutcomeRecord
    branch = VRInvestigationBranchRecord
    review = VRInvestigationOutcomeReviewRecord

    # Find every running investigation with a draft primary outcome.
    candidates = (
        await uow.session.exec(
            select(inv.id, inv.primary_outcome_id, out.branch_id)
            .join(out, out.id == inv.primary_outcome_id)
            .where(inv.status == InvestigationStatus.RUNNING.value)
            .where(out.state.in_(("draft", "rejected", "refuted"))),
        )
    ).all()
    if not candidates:
        return 0

    nudged = 0
    for inv_id, outcome_id, proposer_branch_id in candidates:
        # Compute draft age: max turn_count of any branch since the
        max_turn_row = (
            await uow.session.exec(
                select(func.max(branch.turn_count))
                .where(branch.investigation_id == inv_id),
            )
        ).first()
        if max_turn_row is None:
            max_turn = 0
        elif hasattr(max_turn_row, "__getitem__") and not isinstance(max_turn_row, int):
            max_turn = int(max_turn_row[0] or 0)
        else:
            max_turn = int(max_turn_row or 0)
        if max_turn < _MIN_DRAFT_AGE_TURNS:
            continue

        # Active non-proposer branches that haven't voted on this outcome.
        voter_branch_rows = (
            await uow.session.exec(
                select(review.reviewer_branch_id)
                .where(review.outcome_id == outcome_id),
            )
        ).all()
        # rows may be Row(reviewer_branch_id=...) or plain scalar — handle both
        voted: set[str] = set()
        for r in voter_branch_rows:
            if r is None:
                continue
            v = r[0] if hasattr(r, "__getitem__") and not isinstance(r, str) else r
            if v:
                voted.add(str(v))
        voted.add(str(proposer_branch_id))

        stuck_branches = (
            await uow.session.exec(
                select(branch)
                .where(branch.investigation_id == inv_id)
                .where(branch.status == BranchStatus.ACTIVE.value),
            )
        ).all()

        for raw_b in stuck_branches:
            # Row tuple unwrap — same pattern as virgin children
            b = raw_b[0] if hasattr(raw_b, "__getitem__") and not isinstance(raw_b, str) else raw_b
            if str(b.id) in voted:
                continue
            try:
                state_obj = _json_local.loads(b.case_state_json or "{}")
            except (ValueError, TypeError):
                state_obj = {}
            obs = state_obj.setdefault("observables", {})
            already_set = obs.get("_directive.mandatory_vote_now")
            is_rejected = False  # decided per-loop below
            # outcome_state captured from the join row — recompute via lookup
            # to keep the directive text accurate (draft vs rejected).
            # Cheap: 1 row hit per stuck branch, only when the directive
            # actually needs to change.
            outcome_state_row = (
                await uow.session.exec(
                    select(out.state).where(out.id == outcome_id),
                )
            ).first()
            outcome_state = (
                outcome_state_row[0]
                if outcome_state_row is not None
                and hasattr(outcome_state_row, "__getitem__")
                and not isinstance(outcome_state_row, str)
                else (outcome_state_row or "draft")
            )
            is_rejected = outcome_state in ("rejected", "refuted")
            if is_rejected:
                directive = (
                    f"*** MANDATORY VOTE — PRIMARY OUTCOME REJECTED ***\n\n"
                    f"Outcome {outcome_id} has been REJECTED by a sibling "
                    f"vote. Investigation cannot close until every active "
                    f"branch records a vote (any of approve/reject/abstain "
                    f"is valid — silence is not). You have been silent for "
                    f"{max_turn} turns of the investigation lifetime.\n\n"
                    f"YOUR NEXT TURN MUST be action='submit_outcome_review' "
                    f"with one of:\n"
                    f"  - vote='approve' if you DISAGREE with the rejection "
                    f"(the finding is real and the rejection is wrong).\n"
                    f"  - vote='reject' if you agree the finding is invalid.\n"
                    f"  - vote='abstain' if you cannot evaluate the finding.\n\n"
                    f"If you have a DIFFERENT vulnerability to propose, "
                    f"emit action='submit' with your own finding INSTEAD "
                    f"of voting — that creates a competing outcome the "
                    f"siblings will then vote on. Otherwise, vote and "
                    f"close out — your audit branch is blocking the parent "
                    f"batch."
                )
            else:
                directive = (
                    f"*** MANDATORY VOTE — DRAFT REVIEW BLOCKED YOUR AUDIT ***\n\n"
                    f"Outcome {outcome_id} has been awaiting your vote for "
                    f"{max_turn} turns. Your investigation pool now requires "
                    f"a quorum decision before any branch (including yours) "
                    f"can progress further.\n\n"
                    f"YOUR NEXT TURN MUST be action='submit_outcome_review' "
                    f"with one of:\n"
                    f"  - vote='approve' if the cited evidence holds up.\n"
                    f"  - vote='reject' if you have refuting evidence.\n"
                    f"  - vote='abstain' if you cannot resolve either way.\n\n"
                    f"Voting an abstain is valid and counts toward quorum "
                    f"closure — silence does not. Once 3 distinct siblings "
                    f"cast any combination of approve/reject/abstain, the "
                    f"outcome closes and all branches dispatch. Continuing "
                    f"your audit on a separate hypothesis is no longer "
                    f"productive; the parent batch is blocked on YOU."
                )
            if already_set == directive:
                continue
            obs["_directive.mandatory_vote_now"] = directive
            b.case_state_json = _json_local.dumps(state_obj)
            b.updated_at = utc_now()
            uow.session.add(b)
            nudged += 1

    if nudged:
        await uow.commit()
        _log.info(
            "masvs_stuck_drafts: nudged %d sibling branches into mandatory-vote",
            nudged,
        )

    return nudged

async def _close_rejected_outcomes(uow: UnitOfWork) -> int:
    """Force-close investigations whose primary outcome was REJECTED by quorum.

    Mirror of the existing ``auto_approved_no_active_voters`` path in
    ``services/outcome_review.py`` but for the rejection direction:
    once ``evaluate_quorum`` flips an outcome ``draft → rejected``
    (reject_count ≥ quorum_k), the investigation has no auto-close
    path — it just sits at ``status=running`` waiting for some other
    branch to propose an alternative outcome. In practice the other
    branches are already deep in their own audits and rarely produce
    a competing outcome, so the investigation runs forever.

    Policy: when ``primary_outcome.state ∈ {rejected, refuted}`` AND
    every active non-proposer branch has either voted on the rejected
    outcome OR is itself abandoned/completed, the rejection is
    effectively final. Mark the investigation ``completed`` with
    ``pause_reason='operator'`` (closest valid enum value — the auto-
    closer is operator-policy-driven, not a true pause), abandon any
    remaining active branches with ``closed_reason='outcome_rejected
    _by_quorum'`` so the audit trail is clear.

    Returns the count of investigations closed this tick.
    """
    from aila.modules.vr.db_models import (  # noqa: PLC0415
        VRInvestigationBranchRecord,
        VRInvestigationOutcomeRecord,
    )
    from aila.modules.vr.db_models.outcome_review import (  # noqa: PLC0415
        VRInvestigationOutcomeReviewRecord,
    )

    inv = VRInvestigationRecord
    out = VRInvestigationOutcomeRecord
    branch = VRInvestigationBranchRecord
    review = VRInvestigationOutcomeReviewRecord

    # Find running investigations whose primary outcome is rejected.
    candidates = (
        await uow.session.exec(
            select(inv.id, inv.primary_outcome_id, out.branch_id)
            .join(out, out.id == inv.primary_outcome_id)
            .where(inv.status == InvestigationStatus.RUNNING.value)
            .where(out.state.in_(("rejected", "refuted"))),
        )
    ).all()
    if not candidates:
        return 0

    closed = 0
    for inv_id, outcome_id, proposer_branch_id in candidates:
        # Count active non-proposer branches that HAVEN'T voted yet.
        # If any remain, leave the inv alone — they might propose an
        # alternative outcome. If all have voted, the rejection is final.
        voter_rows = (
            await uow.session.exec(
                select(review.reviewer_branch_id)
                .where(review.outcome_id == outcome_id),
            )
        ).all()
        voted: set[str] = set()
        for r in voter_rows:
            v = r[0] if hasattr(r, "__getitem__") and not isinstance(r, str) else r
            if v:
                voted.add(str(v))
        voted.add(str(proposer_branch_id))

        active_rows = (
            await uow.session.exec(
                select(branch.id)
                .where(branch.investigation_id == inv_id)
                .where(branch.status == BranchStatus.ACTIVE.value),
            )
        ).all()
        active_ids: list[str] = []
        for r in active_rows:
            v = r[0] if hasattr(r, "__getitem__") and not isinstance(r, str) else r
            if v:
                active_ids.append(str(v))

        unvoted_active = [bid for bid in active_ids if bid not in voted]
        if unvoted_active:
            # Leave it — they may still vote OR submit own outcome.
            continue

        # All non-proposer active branches voted (or none remain). Close.
        await uow.session.exec(
            update(branch)
            .where(branch.investigation_id == inv_id)
            .where(branch.status == BranchStatus.ACTIVE.value)
            .values(
                status=BranchStatus.ABANDONED.value,
                closed_reason="outcome_rejected_by_quorum",
                closed_at=utc_now(),
                updated_at=utc_now(),
            ),
        )
        target_inv = (
            await uow.session.exec(
                select(inv).where(inv.id == inv_id),
            )
        ).first()
        if target_inv and not isinstance(target_inv, type(None)):
            t = target_inv[0] if hasattr(target_inv, "__getitem__") and not isinstance(target_inv, str) else target_inv
            t.status = InvestigationStatus.COMPLETED.value
            t.pause_reason = "operator"  # closest valid enum value
            t.stopped_at = utc_now()
            t.updated_at = utc_now()
            uow.session.add(t)
            closed += 1
            _log.info(
                "rejected_outcome_closed inv=%s outcome=%s",
                inv_id, outcome_id,
            )

    if closed:
        await uow.commit()
    return closed

async def _abandon_stale_branches(uow: UnitOfWork) -> int:
    """Abandon active branches that have stopped making progress.

    Two failure modes observed in production:
      1. ``turn_count=0`` since the dispatcher created the branch hours
         ago — the first turn never queued (lost task, dead worker,
         dependency wait that never resolved). These are dead from
         birth.
      2. ``turn_count>=1`` but ``updated_at`` is many hours old — the
         agent made some progress, then the task chain broke (auto-
         steering operator message logged but no engine reply, ARQ
         orphan, OmniRoute crash). The branch sits ``status=active`` so
         it blocks the parent investigation from auto-completing in
         ``_check_terminal_status``.

    Thresholds (tunable via env):
      ``VR_STALE_BRANCH_FROZEN_MIN`` (default 30): minutes of inactivity
        before a branch with ``turn_count < 5`` is abandoned. These
        never really started; short timeout is safe.
      ``VR_STALE_BRANCH_HALTED_MIN`` (default 120): minutes of
        inactivity before a branch with ``turn_count >= 5`` is
        abandoned. They made real progress; give them longer in case
        the agent comes back.

    A healthy active branch writes ``updated_at`` every tool call
    (every few seconds during a turn), so 30 min of inactivity is
    already a strong signal of failure. Abandoned branches get
    ``closed_reason='stale_no_progress_<frozen|halted>_<min>min'`` so
    the operator can grep the audit trail.

    Returns the count of branches abandoned this tick.
    """
    from aila.modules.vr.db_models import (  # noqa: PLC0415
        VRInvestigationBranchRecord,
    )

    frozen_min = int(os.environ.get("VR_STALE_BRANCH_FROZEN_MIN", "30"))
    halted_min = int(os.environ.get("VR_STALE_BRANCH_HALTED_MIN", "120"))
    branch = VRInvestigationBranchRecord
    now = utc_now()
    frozen_cutoff = now - timedelta(minutes=frozen_min)
    halted_cutoff = now - timedelta(minutes=halted_min)

    # 1. Frozen-from-birth: turn_count < 5 + idle >= frozen_min.
    frozen_result = await uow.session.exec(
        update(branch)
        .where(branch.status == BranchStatus.ACTIVE.value)
        .where(branch.turn_count < 5)
        .where(branch.updated_at < frozen_cutoff)
        .values(
            status=BranchStatus.ABANDONED.value,
            closed_reason=f"stale_no_progress_frozen_{frozen_min}min",
            closed_at=now,
            updated_at=now,
        ),
    )
    frozen_count = getattr(frozen_result, "rowcount", 0) or 0

    # 2. Halted-after-progress: turn_count >= 5 + idle >= halted_min.
    halted_result = await uow.session.exec(
        update(branch)
        .where(branch.status == BranchStatus.ACTIVE.value)
        .where(branch.turn_count >= 5)
        .where(branch.updated_at < halted_cutoff)
        .values(
            status=BranchStatus.ABANDONED.value,
            closed_reason=f"stale_no_progress_halted_{halted_min}min",
            closed_at=now,
            updated_at=now,
        ),
    )
    halted_count = getattr(halted_result, "rowcount", 0) or 0

    total = frozen_count + halted_count
    if total:
        await uow.commit()
        _log.info(
            "stale_branches_abandoned frozen=%d halted=%d total=%d",
            frozen_count, halted_count, total,
        )
    return total




async def sweep_masvs_audit_parents() -> dict[str, int]:
    """Reconcile parent status for every active MASVS audit batch.

    Returns a ``{"started": int, "completed": int, "refilled": int,
    "exhausted": int}`` counter pair naming the number of
    ``CREATED → RUNNING`` and ``{CREATED, RUNNING} → COMPLETED``
    transitions actually applied in this sweep. ``exhausted`` counts
    investigations that hit the cumulative-turn cap. All counters are
    post-rowcount so a lost race against a concurrent operator action
    does not inflate them.
    """
    inv = VRInvestigationRecord

    started = 0
    completed = 0

    async with UnitOfWork() as uow:
        # 1. Top up APK batch slots before status transitions.
        try:
            refilled = await _refill_apk_batches(uow)
        except Exception as exc:  # noqa: BLE001 — best-effort tick
            _log.warning("masvs reconciler: refill failed: %s", exc, exc_info=True)
            refilled = 0
        # 2. Enforce cumulative-turn cap.
        try:
            exhausted = await _enforce_total_turn_cap(uow)
        except Exception as exc:  # noqa: BLE001
            _log.warning("masvs reconciler: turn-cap failed: %s", exc, exc_info=True)
            exhausted = 0
        # 3. Escalate stuck drafts (mandatory-vote directive).
        try:
            nudged = await _escalate_stuck_drafts(uow)  # noqa: F841
        except Exception as exc:  # noqa: BLE001
            _log.warning("masvs reconciler: stuck-draft escalation failed: %s", exc, exc_info=True)
            nudged = 0  # noqa: F841
        # 4. Close investigations whose primary outcome was REJECTED.
        try:
            rejected_closed = await _close_rejected_outcomes(uow)  # noqa: F841
        except Exception as exc:  # noqa: BLE001
            _log.warning("masvs reconciler: rejected-close failed: %s", exc, exc_info=True)
            rejected_closed = 0  # noqa: F841
        # 5. Abandon active branches that stopped making progress.
        try:
            stale = await _abandon_stale_branches(uow)  # noqa: F841
        except Exception as exc:  # noqa: BLE001
            _log.warning("masvs reconciler: stale-branch abandon failed: %s", exc, exc_info=True)
            stale = 0  # noqa: F841
        # Candidate parents: kind=masvs_audit, parent_investigation_id
        # IS NULL (true batch root), status in {CREATED, RUNNING}. PAUSED
        # parents are intentionally excluded so an operator who paused
        # the batch root keeps control until they resume.
        parent_rows = (
            await uow.session.exec(
                select(inv.id, inv.status)
                .where(inv.kind == InvestigationKind.MASVS_AUDIT.value)
                .where(inv.parent_investigation_id.is_(None))
                .where(
                    inv.status.in_(
                        (
                            InvestigationStatus.CREATED.value,
                            InvestigationStatus.RUNNING.value,
                        ),
                    ),
                ),
            )
        ).all()
        if not parent_rows:
            return {"started": 0, "completed": 0, "refilled": refilled}

        parent_ids = [row[0] for row in parent_rows]
        # One aggregate query covers every candidate batch: child status
        # counts grouped per parent. Avoids N+1 SELECTs for a batch with
        # ~46 children.
        child_rows = (
            await uow.session.exec(
                select(
                    inv.parent_investigation_id,
                    inv.status,
                    func.count(inv.id),
                )
                .where(inv.parent_investigation_id.in_(parent_ids))
                .group_by(inv.parent_investigation_id, inv.status),
            )
        ).all()

        per_parent: dict[str, dict[str, int]] = {}
        for parent_id, child_status, count in child_rows:
            per_parent.setdefault(parent_id, {})[child_status] = int(count)

        now = utc_now()
        any_changes = False

        for parent_id, parent_status in parent_rows:
            buckets = per_parent.get(parent_id)
            if not buckets:
                # Defensive: zero visible children = in-flight rollback
                # or manual stub. Leave alone.
                continue

            total_children = sum(buckets.values())
            terminal_children = sum(
                count
                for status_value, count in buckets.items()
                if status_value in _TERMINAL_STATUSES
            )
            created_children = buckets.get(
                InvestigationStatus.CREATED.value, 0,
            )

            if terminal_children == total_children:
                # Every child terminal → flip parent to COMPLETED.
                # coalesce keeps started_at when already set (the parent
                # transitioned through RUNNING earlier); fills it when
                # the entire batch ran fast enough to skip past RUNNING
                # between cron ticks (rare but real).
                result = await uow.session.exec(
                    update(inv)
                    .where(inv.id == parent_id)
                    .where(
                        inv.status.in_(
                            (
                                InvestigationStatus.CREATED.value,
                                InvestigationStatus.RUNNING.value,
                            ),
                        ),
                    )
                    .values(
                        status=InvestigationStatus.COMPLETED.value,
                        started_at=coalesce(inv.started_at, now),
                        stopped_at=now,
                        updated_at=now,
                    )
                    .execution_options(synchronize_session=False),
                )
                if (getattr(result, "rowcount", 0) or 0) > 0:
                    completed += 1
                    any_changes = True
            elif (
                parent_status == InvestigationStatus.CREATED.value
                and created_children < total_children
            ):
                # At least one child has moved past CREATED but not all
                # are terminal → parent is mid-batch. Flip to RUNNING and
                # stamp started_at on first transition so the wall-clock
                # reaper has an anchor.
                result = await uow.session.exec(
                    update(inv)
                    .where(inv.id == parent_id)
                    .where(inv.status == InvestigationStatus.CREATED.value)
                    .values(
                        status=InvestigationStatus.RUNNING.value,
                        started_at=coalesce(inv.started_at, now),
                        updated_at=now,
                    )
                    .execution_options(synchronize_session=False),
                )
                if (getattr(result, "rowcount", 0) or 0) > 0:
                    started += 1
                    any_changes = True

        if any_changes:
            await uow.commit()

    if started or completed or refilled:
        _log.info(
            "masvs_parent_reconciler: started=%d completed=%d refilled=%d",
            started,
            completed,
            refilled,
        )

    return {"started": started, "completed": completed, "refilled": refilled}
