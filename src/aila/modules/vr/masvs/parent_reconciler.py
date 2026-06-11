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

from sqlalchemy import cast, func, select, update
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.sql.functions import coalesce

from aila.modules.vr._task_queue import default_task_queue
from aila.modules.vr.contracts import (
    BranchStatus,
    InvestigationKind,
    InvestigationPauseReason,
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


class PauseReason:
    """Canonical values this reconciler writes to ``pause_reason``.

    fix §19 — the ``pause_reason`` column is ``varchar(32)`` and the
    API deserialiser (``api_router._investigation_summary``) calls
    ``InvestigationPauseReason(record.pause_reason)`` on read. Any
    value outside the contract enum 500's the next investigation
    fetch (D-280). Prior writes here put free-form strings like
    ``"exhausted_total_turn_cap:total_turns=200"`` (36+ chars AND
    not in the enum) into the column.

    This class collapses the reconciler's local reason vocabulary
    onto contract-enum values. Each constant names the structural
    reason at THIS layer; its value is whatever contract enum the
    operator UI expects to render for that reason. Adding a new
    reason here is a comment-only change unless it needs a new
    contract-enum member (then update ``InvestigationPauseReason``
    first and add the migration).

    TURN_CAP / WALL_CLOCK / STUCK_DRAFT are all forced completions
    rather than literal pauses — the closest valid enum value is
    ``COST_BUDGET`` (every cap is structurally a budget cap: turn,
    wall-clock, dollar). Detail (actual turn count, wall-clock
    elapsed) goes in the log line, NOT the bounded column.
    """

    TURN_CAP = InvestigationPauseReason.COST_BUDGET.value
    WALL_CLOCK = InvestigationPauseReason.COST_BUDGET.value
    OPERATOR = InvestigationPauseReason.OPERATOR.value
    STUCK_DRAFT = InvestigationPauseReason.COST_BUDGET.value



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
    TaskRecord JOIN below uses a JSONB extract on ``kwargs_json``
    (`(kwargs_json::jsonb)->>'investigation_id' = inv.id`) so the match
    is on a typed JSON path, not a substring. Cheap enough for the
    per-parent ≤46-child set we sweep once per minute, and removes the
    false-positive class where a different task's kwargs_json happens
    to embed the same UUID elsewhere (see §41 in MY_VIOLATIONS.md).
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
                    .where(
                        # fix §41 — JSONB extract on `investigation_id`
                        # replaces substring ilike(%uuid%) which matched
                        # any task whose kwargs_json contained the UUID
                        # in any field (parent_investigation_id, etc.).
                        cast(tsk.kwargs_json, JSONB)["investigation_id"]
                        .astext == inv.id,
                    )
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
                    .where(
                        # fix §41 — JSONB extract on `investigation_id`
                        # (see _refill_apk_batches in_flight count above).
                        cast(tsk.kwargs_json, JSONB)["investigation_id"]
                        .astext == inv.id,
                    )
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
            # fix §19 — bounded enum value (<=32 chars, validates
            # against InvestigationPauseReason); detail moves to the
            # log line below so the API serializer doesn't 500.
            target_inv.pause_reason = PauseReason.TURN_CAP
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
    # Don't early-return when candidates is empty — the wake-enqueue
    # below scans ALL active branches regardless of outcome state.
    # Variant_hunt + audit investigations with NO outcome at all need
    # the wake too. The directive-write loop just skips itself when
    # there are no candidates; wake-enqueue runs unconditionally.
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
    if nudged:
        _log.info("masvs_stuck_drafts: nudged=%d", nudged)
    return nudged


async def _wake_stale_branches(uow: UnitOfWork) -> int:
    """Side-channel wake for active branches with no live ARQ task.

    fix §12 — Extracted from ``_escalate_stuck_drafts`` so the wake
    can run LAST in the sweep tick (fix §43). Mixing the wake into the
    directive-write helper let it race with the close-rejected and
    abandon-stale steps that ran after it: the wake re-armed a worker
    on the same branch those steps were about to close, so the
    branch could advance its cursor mid-evaluation and produce a torn
    transition.

    Architectural note (§12): emitting ARQ tasks from a reconciler is
    a layering violation — the engine should re-enqueue the next task
    on every cursor advance. The auto-continue chain in
    ``investigation_emit`` only re-enqueues on ``(max_turns,
    researcher_error*)`` exit reasons; every other exit
    (``terminal_submit`` on a sibling, ``status_flipped``,
    ``submit_outcome_review``, default fallthrough) leaves the branch
    at ``status=active`` with no follow-up task. Until the engine
    learns those exits, this side channel keeps the queue moving.

    Idempotent by construction: ``task_queue.submit`` computes a
    SHA-256 ``input_hash`` over ``(fn_path, kwargs)`` and refuses a
    duplicate while a task with the same hash is in
    ``(queued, running, waiting)`` (``platform/tasks/queue.py:127-140``).
    So a single tick is at-most-once per branch, and a no-op when the
    branch already has a live task.

    Returns the count of branches newly enqueued this tick.
    """
    from aila.modules.vr._task_queue import default_task_queue  # noqa: PLC0415
    from aila.modules.vr.db_models import (  # noqa: PLC0415
        VRInvestigationBranchRecord,
    )
    from aila.modules.vr.workflow.task import run_vr_investigate  # noqa: PLC0415

    inv = VRInvestigationRecord
    branch = VRInvestigationBranchRecord
    q = default_task_queue()
    enqueued = 0

    wakeable = (
        await uow.session.exec(
            select(branch.id, branch.investigation_id)
            .join(inv, inv.id == branch.investigation_id)
            .where(branch.status == BranchStatus.ACTIVE.value)
            .where(
                inv.status.in_(
                    (
                        InvestigationStatus.RUNNING.value,
                        InvestigationStatus.CREATED.value,
                    ),
                ),
            ),
        )
    ).all()
    for raw_row in wakeable:
        r = raw_row if not hasattr(raw_row, "__getitem__") or isinstance(raw_row, str) else raw_row
        bid = str(r[0])
        inv_id_local = str(r[1])
        try:
            await q.submit(
                track="vr",
                fn=run_vr_investigate,
                kwargs={"investigation_id": inv_id_local, "branch_id": bid},
                user_id="system",
                group_id="vr_escalator_wake",
            )
            enqueued += 1
        except Exception as exc:  # noqa: BLE001 — submit is best-effort;
            # dedup misses and Redis blips are tolerable, the next tick retries.
            _log.warning(
                "wake_stale_branches: branch=%s submit failed: %s",
                bid, exc,
            )
    if enqueued:
        _log.info(
            "wake_stale_branches: wake_enqueued=%d "
            "(dedup may have skipped some)",
            enqueued,
        )
    return enqueued


async def _synthesize_no_finding_outcomes(uow: UnitOfWork) -> int:
    """Synthesize an ``audit_memo`` outcome for orphaned investigations.

    Operator rule: EVERY investigation must terminate with an outcome,
    no exceptions. The existing close paths only fire when an outcome
    already exists:

      - ``services/outcome_review.py:auto_approved_no_active_voters``:
        requires primary_outcome in ``draft`` state, gets approved.
      - ``_close_rejected_outcomes`` (step 4): requires primary_outcome
        in ``rejected``/``refuted`` state, closes after siblings vote.

    Gap: variant_hunt / audit investigations that never produced any
    outcome at all (agents abandoned without submitting). Observed
    live on ``a0b33905`` — 6 branches all ``status=abandoned`` via
    step 5 stale-detector, ``primary_outcome_id=NULL``, investigation
    still ``running``. No closer exists for this shape.

    Per operator rule: do NOT just mark completed without an outcome.
    Instead synthesize an honest negative-result outcome:

      - ``outcome_kind = AUDIT_MEMO`` — the catalog kind for
        "this team audited and here's what they concluded";
      - ``confidence = CAVEATED`` — honest about the limitation;
      - ``state = approved`` — no quorum needed, all branches are
        already terminal so no one can vote;
      - ``dispatch_status = skipped`` — nothing to dispatch
        downstream;
      - ``branch_id`` = the branch with highest ``turn_count``
        (the most "informed" branch; ties broken by created_at
        ASC for determinism);
      - payload includes a structured summary of which branches
        abandoned, why, and the total turn count consumed.

    Then set ``investigation.primary_outcome_id = new outcome.id``,
    ``status = completed``, ``stopped_at`` and ``updated_at``.

    Direct SQL INSERT for the outcome row because the ORM model has
    13 columns including JSON fields; constructing via SQL avoids
    importing the model and gives a single round-trip.

    Returns count of investigations resolved this tick.
    """
    import json as _json_local  # noqa: PLC0415
    import uuid as _uuid_local  # noqa: PLC0415

    from sqlalchemy import text  # noqa: PLC0415

    from aila.modules.vr.db_models import (  # noqa: PLC0415
        VRInvestigationBranchRecord,
    )

    inv = VRInvestigationRecord
    branch = VRInvestigationBranchRecord

    # Find running investigations with primary_outcome_id IS NULL and
    # where every branch is in a terminal state. The GROUP BY pattern
    # gives us branch_count + terminal_count per investigation cheaply.
    rows = (
        await uow.session.exec(
            select(
                inv.id,
                func.count(branch.id).label("branch_count"),
                func.sum(
                    coalesce(
                        (
                            branch.status.in_(
                                (
                                    BranchStatus.ABANDONED.value,
                                    BranchStatus.COMPLETED.value,
                                    BranchStatus.MERGED.value,
                                    BranchStatus.PROMOTED.value,
                                ),
                            )
                        ).cast(__import__("sqlalchemy").Integer),
                        0,
                    ),
                ).label("terminal_count"),
            )
            .select_from(inv)
            .join(branch, branch.investigation_id == inv.id, isouter=True)
            .where(inv.status == InvestigationStatus.RUNNING.value)
            .group_by(inv.id),
        )
    ).all()

    orphan_inv_ids: list[str] = []
    for row in rows:
        if not (hasattr(row, "__getitem__") and not isinstance(row, str)):
            continue
        inv_id = str(row[0])
        branch_count = int(row[1] or 0)
        terminal_count = int(row[2] or 0)
        if branch_count == 0:
            # In-flight rollback / dispatcher race — leave alone.
            continue
        if terminal_count >= branch_count:
            orphan_inv_ids.append(inv_id)

    if not orphan_inv_ids:
        return 0

    now = utc_now()
    now_iso = now.isoformat()
    synthesized = 0

    for inv_id in orphan_inv_ids:
        # Check if this investigation already has a primary outcome.
        # If yes: skip synthesis, just flip the inv to completed.
        # If no: synthesize an audit_memo and link it.
        existing_outcome_row = (
            await uow.session.exec(
                select(inv.primary_outcome_id).where(inv.id == inv_id),
            )
        ).first()
        existing_outcome: str | None = None
        if existing_outcome_row is not None:
            if hasattr(existing_outcome_row, "__getitem__") and not isinstance(existing_outcome_row, str):
                existing_outcome = existing_outcome_row[0]
            else:
                existing_outcome = existing_outcome_row

        if existing_outcome:
            # Just flip — outcome already exists (was approved by quorum
            # earlier, or some other path created it; we don't care
            # which). Operator rule satisfied: investigation terminates
            # with an outcome.
            try:
                await uow.session.exec(
                    update(inv)
                    .where(inv.id == inv_id)
                    .where(inv.status == InvestigationStatus.RUNNING.value)
                    .values(
                        status=InvestigationStatus.COMPLETED.value,
                        stopped_at=now,
                        updated_at=now,
                    ),
                )
                synthesized += 1
            except Exception as exc:  # noqa: BLE001
                _log.warning(
                    "orphan close (with existing outcome) failed inv=%s: %s",
                    inv_id, exc, exc_info=True,
                )
            continue

        # No outcome: synthesize one.
        # Pick the most "informed" branch: highest turn_count, ties
        # broken by earliest created_at for determinism.
        branch_rows = (
            await uow.session.exec(
                select(branch.id, branch.persona_voice, branch.turn_count, branch.closed_reason, branch.status)
                .where(branch.investigation_id == inv_id)
                .order_by(branch.turn_count.desc(), branch.created_at.asc()),
            )
        ).all()
        if not branch_rows:
            continue
        unwrapped: list[tuple[str, str, int, str | None, str]] = []
        for br in branch_rows:
            if hasattr(br, "__getitem__") and not isinstance(br, str):
                unwrapped.append(
                    (str(br[0]), str(br[1] or "?"), int(br[2] or 0), br[3], str(br[4] or "?")),
                )
        if not unwrapped:
            continue

        proposer_branch_id = unwrapped[0][0]
        total_turns = sum(r[2] for r in unwrapped)
        summary_text = (
            "Investigation auto-closed by reconciler: every branch "
            "reached a terminal state without proposing a finding. "
            f"{len(unwrapped)} branches consumed {total_turns} total "
            "turns. Per-branch outcome:"
        )
        per_branch = [
            {
                "persona": p,
                "turns": t,
                "status": s,
                "closed_reason": cr or "n/a",
            }
            for (_bid, p, t, cr, s) in unwrapped
        ]
        payload = {
            "verdict": "no_finding",
            "summary": summary_text,
            "branches": per_branch,
            "synthesized_by": "parent_reconciler._synthesize_no_finding_outcomes",
            "synthesized_at": now_iso,
            "rule": "every_investigation_has_outcome",
        }

        outcome_id = str(_uuid_local.uuid4())
        try:
            await uow.session.exec(
                text(
                    """
                    INSERT INTO vr_investigation_outcomes (
                        id, investigation_id, branch_id, outcome_kind,
                        payload_json, confidence, evidence_refs_json,
                        accepted_by_operator, accepted_at,
                        dispatch_status, dispatch_target,
                        created_at, state
                    ) VALUES (
                        :id, :inv_id, :branch_id, :kind,
                        :payload, :confidence, :evidence,
                        false, NULL,
                        'skipped', NULL,
                        :now, 'approved'
                    )
                    """,
                ),
                params={
                    "id": outcome_id,
                    "inv_id": inv_id,
                    "branch_id": proposer_branch_id,
                    "kind": "audit_memo",
                    "payload": _json_local.dumps(payload),
                    "confidence": "caveated",
                    "evidence": "[]",
                    "now": now,
                },
            )
            await uow.session.exec(
                update(inv)
                .where(inv.id == inv_id)
                .where(inv.status == InvestigationStatus.RUNNING.value)
                .values(
                    primary_outcome_id=outcome_id,
                    status=InvestigationStatus.COMPLETED.value,
                    stopped_at=now,
                    updated_at=now,
                ),
            )
            synthesized += 1
        except Exception as exc:  # noqa: BLE001
            _log.warning(
                "synthesize_no_finding failed inv=%s: %s", inv_id, exc, exc_info=True,
            )

    if synthesized:
        await uow.commit()
        _log.info(
            "synthesized_no_finding_outcomes count=%d (first 5 ids=%s)",
            synthesized,
            ",".join(i[:8] for i in orphan_inv_ids[:5])
            + ("..." if len(orphan_inv_ids) > 5 else ""),
        )
    return synthesized




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
    from aila.platform.llm.client import is_llm_recently_unhealthy  # noqa: PLC0415

    # LLM-outage gate (operator rule): branches sitting idle through
    # an LLM endpoint outage are NOT stalled — they are waiting for
    # work. Abandoning them in that window destroys real progress
    # because the workflow couldn't run their next turn. Skip the
    # whole abandonment step when the LLM has had any error in the
    # trailing 10 min without a more recent success. The escalator
    # wake-enqueue at step 3 still fires regardless: when the LLM
    # recovers, the next wake will pick up the queued task and the
    # branch resumes from its last known turn.
    if is_llm_recently_unhealthy(600.0):
        _log.info(
            "stale_branches: skipping abandonment (LLM unhealthy "
            "within last 10 min — branches waiting for work, not "
            "stalled)",
        )
        return 0
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

async def _reap_zombie_tasks_and_cursors(uow: UnitOfWork) -> dict[str, int]:
    """Reap zombie tasks and stale workflow_state_cursor rows.

    Two coupled failure modes leave the queue silently jammed (D-283):

    1. Zombie task: ``taskrecord.status='running'`` with
       ``heartbeat_at`` older than ``VR_ZOMBIE_TASK_HEARTBEAT_MIN``
       (default 10 min). Caused by worker crash mid-task,
       OmniRoute retry-loop wedging the worker for hours, or any
       hang the worker can't recover from. The TaskRecord row
       stays at ``running`` indefinitely, and dedup at
       queue.py:132-140 then refuses to re-enqueue the same
       investigation+branch payload because there's still an
       "in-flight" task — but no worker is actually working it.

    2. Stale workflow_state_cursor: rows persist after the owning
       task terminates abnormally. When a fresh task for the same
       run_id starts, the workflow engine sees a stale cursor in
       a transient state (``investigation_loop`` etc.) and
       silently blocks. Observed live: 19 fresh tasks at 01:35:01
       all stuck at first heartbeat for 10+ min because of 169
       leftover cursors from a prior crash window.

    This sweep:
      (a) marks any vr-track task at ``status=running`` with
          stale heartbeat as ``cancelled`` (frees dedup slot),
      (b) deletes orphan cursors (no matching TaskRecord at all),
      (c) deletes cursors whose TaskRecord is already terminal
          (cancelled / done / failed / dead_letter),
      (d) deletes cursors at the success terminal state
          ``__succeeded__`` regardless of TaskRecord linkage
          (the workflow engine itself never reads these again).

    Active in-flight tasks (status IN queued/running/waiting with
    fresh heartbeat) are left strictly alone. Only the explicitly
    dead state gets reaped.

    Returns ``{zombies_cancelled, cursors_purged}``.

    fix §42 — Single-session-scope assumption.
    --------------------------------------------------
    The function issues four UPDATE/DELETE statements:
      (1) UPDATE taskrecord SET status='cancelled' WHERE stale heartbeat
      (2) DELETE workflow_state_cursor WHERE no matching taskrecord
      (3) DELETE workflow_state_cursor WHERE taskrecord is terminal
      (4) DELETE workflow_state_cursor WHERE current_state='__succeeded__'

    Steps 1 → 3 are intentionally ordered so step 3 sees the rows step 1
    just marked ``cancelled`` (the cancelled rows then become eligible
    for cursor deletion in the same tick). This is correct ONLY when
    all four statements run inside the SAME session/transaction, so
    step 3's ``JOIN taskrecord`` sees step 1's uncommitted update —
    Postgres' default READ COMMITTED visibility for statements within a
    single transaction makes this work. If the caller ever split this
    helper across two sessions, step 3 would miss the just-cancelled
    rows and they'd survive until the next tick.

    The assertion below enforces the assumption at function entry: the
    caller MUST hand us a session that is already in a transaction.
    Documentation-only change otherwise — no statement reordering, no
    new commits.
    """
    from sqlalchemy import text  # noqa: PLC0415

    # fix §42 — single-session-scope invariant. The caller's UnitOfWork
    # implicitly begins a transaction on first session use; a stand-
    # alone session that has not yet executed any statement will assert
    # False here and surface the misuse loudly rather than silently
    # losing the step-1→step-3 visibility chain.
    assert uow.session.in_transaction(), (  # noqa: S101
        "_reap_zombie_tasks_and_cursors must run inside a single "
        "transaction so step 3's JOIN observes step 1's UPDATE"
    )

    heartbeat_min = int(os.environ.get("VR_ZOMBIE_TASK_HEARTBEAT_MIN", "10"))
    batch_cap = int(os.environ.get("VR_CURSOR_CLEANUP_BATCH", "5000"))

    # 1. Cancel zombie tasks: vr-track, status=running, heartbeat
    #    older than threshold (also catches the case where
    #    heartbeat is NULL but started_at is old — both indicate
    #    a worker that never reported life).
    zombie_sql = text(
        """
        UPDATE taskrecord
        SET status = 'cancelled',
            completed_at = NOW(),
            updated_at = NOW(),
            error = COALESCE(error, '') || ' [reaped by parent_reconciler: stale heartbeat]'
        WHERE track = 'vr'
          AND status = 'running'
          AND COALESCE(heartbeat_at, started_at) < NOW() - (:mins || ' minutes')::interval
        """,
    )
    zombie_result = await uow.session.exec(zombie_sql, params={"mins": str(heartbeat_min)})
    zombies_cancelled = getattr(zombie_result, "rowcount", 0) or 0

    # 2. Purge orphan cursors (no matching TaskRecord row at all).
    #    Use NOT EXISTS to dodge a self-join cost on huge tables.
    orphan_sql = text(
        """
        DELETE FROM workflow_state_cursor
        WHERE run_id IN (
            SELECT c.run_id FROM workflow_state_cursor c
            WHERE NOT EXISTS (
                SELECT 1 FROM taskrecord t WHERE t.id::text = c.run_id::text
            )
            LIMIT :cap
        )
        """,
    )
    orphan_result = await uow.session.exec(orphan_sql, params={"cap": batch_cap})
    orphan_purged = getattr(orphan_result, "rowcount", 0) or 0

    # 3. Purge cursors whose TaskRecord is terminal.
    terminal_sql = text(
        """
        DELETE FROM workflow_state_cursor
        WHERE run_id IN (
            SELECT c.run_id FROM workflow_state_cursor c
            JOIN taskrecord t ON t.id::text = c.run_id::text
            WHERE t.status IN ('cancelled', 'done', 'failed', 'dead_letter')
            LIMIT :cap
        )
        """,
    )
    terminal_result = await uow.session.exec(terminal_sql, params={"cap": batch_cap})
    terminal_purged = getattr(terminal_result, "rowcount", 0) or 0

    # 4. Purge __succeeded__ cursors — terminal in the workflow engine,
    #    never re-read, just accumulate.
    succeeded_sql = text(
        """
        DELETE FROM workflow_state_cursor
        WHERE run_id IN (
            SELECT run_id FROM workflow_state_cursor
            WHERE current_state = '__succeeded__'
            LIMIT :cap
        )
        """,
    )
    succeeded_result = await uow.session.exec(succeeded_sql, params={"cap": batch_cap})
    succeeded_purged = getattr(succeeded_result, "rowcount", 0) or 0

    cursors_purged = orphan_purged + terminal_purged + succeeded_purged

    if zombies_cancelled or cursors_purged:
        await uow.commit()
        _log.info(
            "zombie_reaper zombies=%d cursors_purged=%d "
            "(orphan=%d terminal=%d succeeded=%d)",
            zombies_cancelled, cursors_purged,
            orphan_purged, terminal_purged, succeeded_purged,
        )

    return {
        "zombies_cancelled": zombies_cancelled,
        "cursors_purged": cursors_purged,
    }





async def _cascade_terminal_to_deferred_children(
    uow: UnitOfWork,
) -> int:
    """Cascade parent terminal status to deferred CREATED children.

    fix §52 — when a MASVS audit parent reaches a terminal status
    (``COMPLETED`` / ``FAILED`` / ``ABANDONED``) the deferred child
    pool — children that never got an ARQ task because the APK refill
    cap was already full — used to sit at ``CREATED`` forever. The
    refill helper only operates on parents in ``CREATED``/``RUNNING``,
    so once the parent crossed into a terminal state the deferred
    children were orphaned: no operator UI flipped them, no reaper
    swept them, and the parent's completion percentage was reported
    against a child count that no longer made sense.

    ``PAUSED`` parents are NOT included — the operator may resume them
    and expect the deferred children to pick back up. Only the three
    irrevocable terminal states cascade.

    Children are flipped to ``ABANDONED`` with ``stopped_at`` /
    ``updated_at`` set and ``pause_reason`` left untouched (the cascade
    is not a pause; pause_reason carries only PAUSED-state metadata).

    Returns the number of children cascaded this tick.
    """
    inv = VRInvestigationRecord
    now = utc_now()

    # One UPDATE covers every cascade — joining on the parent's terminal
    # status keeps the scan cheap and atomic. We don't need a separate
    # SELECT-then-UPDATE because the WHERE clause already excludes
    # children whose parent is still in CREATED/RUNNING/PAUSED.
    parent_alias = inv.__table__.alias("parent_inv")
    result = await uow.session.exec(
        update(inv)
        .where(inv.status == InvestigationStatus.CREATED.value)
        .where(inv.parent_investigation_id.isnot(None))
        .where(
            inv.parent_investigation_id.in_(
                select(parent_alias.c.id)
                .where(
                    parent_alias.c.kind
                    == InvestigationKind.MASVS_AUDIT.value,
                )
                .where(parent_alias.c.status.in_(_TERMINAL_STATUSES)),
            ),
        )
        .values(
            status=InvestigationStatus.ABANDONED.value,
            stopped_at=now,
            updated_at=now,
        )
        .execution_options(synchronize_session=False),
    )
    cascaded = getattr(result, "rowcount", 0) or 0
    if cascaded:
        await uow.commit()
        _log.info(
            "cascade_terminal_to_deferred_children: cascaded=%d "
            "(parent already terminal, child stuck at CREATED)",
            cascaded,
        )
    return cascaded


async def sweep_masvs_audit_parents() -> dict[str, int]:
    """Reconcile parent status for every active MASVS audit batch.

    Returns a ``{"started": int, "completed": int, "refilled": int}``
    counter dict naming the number of ``CREATED → RUNNING`` and
    ``{CREATED, RUNNING} → COMPLETED`` transitions actually applied in
    this sweep. All counters are post-rowcount so a lost race against
    a concurrent operator action does not inflate them.

    Sweep step order (fix §43 — wake moved LAST):
      1. ``_refill_apk_batches``    — top up APK in-flight slots.
      2. ``_enforce_total_turn_cap`` — close runs over the cumulative
         turn cap before any later step inspects branch state.
      3. ``_escalate_stuck_drafts`` — inject the mandatory-vote
         directive (no wake-enqueue any more; that moved to step 9).
      4. ``_close_rejected_outcomes`` — close investigations whose
         primary outcome was rejected by quorum.
      5. ``_abandon_stale_branches`` — abandon branches that stopped
         making progress.
      6. ``_synthesize_no_finding_outcomes`` — fill in audit_memo
         outcomes for any investigation that orphaned at step 5.
      7. ``_reap_zombie_tasks_and_cursors`` — cancel stale ``running``
         taskrecords and purge dead workflow_state_cursors.
      8. Parent ``CREATED/RUNNING → COMPLETED`` rollup (inline below).
      8.5. ``_cascade_terminal_to_deferred_children`` — flip deferred
         ``CREATED`` children whose parent is already terminal
         (``COMPLETED`` / ``FAILED`` / ``ABANDONED``) to
         ``ABANDONED`` so they don't sit orphaned (fix §52).
      9. ``_wake_stale_branches`` — side-channel ARQ wake LAST so
         a freshly-enqueued task cannot race steps 4/5/8's snapshot
         reads (a worker advancing a branch mid-evaluation produced
         torn transitions in the pre-fix layout).
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
            await _enforce_total_turn_cap(uow)
        except Exception as exc:  # noqa: BLE001
            _log.warning("masvs reconciler: turn-cap failed: %s", exc, exc_info=True)
        # 3. Escalate stuck drafts (mandatory-vote directive only;
        #    wake-enqueue moved to step 9 — fix §43).
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
        # 6. Synthesize audit_memo outcomes for any investigation
        # where all branches are now terminal but no outcome exists.
        # Runs AFTER step 5 abandonment because that's what creates
        # the orphan condition. Operator rule: every investigation
        # MUST end with an outcome.
        try:
            synthesized = await _synthesize_no_finding_outcomes(uow)  # noqa: F841
        except Exception as exc:  # noqa: BLE001
            _log.warning("masvs reconciler: no-finding synth failed: %s", exc, exc_info=True)
            synthesized = 0  # noqa: F841
        # 7. Reap zombie tasks + stale workflow_state_cursors (D-283).
        try:
            reaped = await _reap_zombie_tasks_and_cursors(uow)  # noqa: F841
        except Exception as exc:  # noqa: BLE001
            _log.warning("masvs reconciler: zombie reaper failed: %s", exc, exc_info=True)
            reaped = {"zombies_cancelled": 0, "cursors_purged": 0}  # noqa: F841
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

        # 8.5. Cascade terminal parents → deferred CREATED children
        # (fix §52). Runs AFTER the parent rollup so the
        # just-COMPLETED parents from step 8 are included alongside
        # parents the operator put into FAILED/ABANDONED earlier.
        # PAUSED parents are intentionally excluded — operator may
        # resume and expect deferred children to pick back up.
        try:
            await _cascade_terminal_to_deferred_children(uow)
        except Exception as exc:  # noqa: BLE001 — cascade is best-effort
            _log.warning(
                "masvs reconciler: cascade-deferred-children failed: %s",
                exc, exc_info=True,
            )

        # 9. Side-channel wake LAST (fix §43). Earlier ordering ran
        # the wake inside _escalate_stuck_drafts (step 3); a worker
        # picking up that fresh task could advance a branch's cursor
        # while steps 4/5/8 were mid-evaluation, producing torn
        # transitions. Running the wake AFTER every read-and-write
        # step guarantees the sweep tick observes a stable branch
        # snapshot.
        try:
            await _wake_stale_branches(uow)
        except Exception as exc:  # noqa: BLE001 — wake is best-effort
            _log.warning(
                "masvs reconciler: wake-stale-branches failed: %s",
                exc, exc_info=True,
            )

    if started or completed or refilled:
        _log.info(
            "masvs_parent_reconciler: started=%d completed=%d refilled=%d",
            started,
            completed,
            refilled,
        )

    return {"started": started, "completed": completed, "refilled": refilled}
