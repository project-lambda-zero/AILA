"""Generic investigation finalizers -- implementation site.

Three helpers that handle generic investigation finalization
(rejected-quorum close, orphan audit_memo synthesis, stale-branch
abandonment). They are not MASVS-specific; this module is their
canonical home after Phase C's cleanup of the
``vr.masvs.parent_reconciler`` overload.

Two surface layers:

* **Sweep impls** (``close_rejected_outcomes``,
  ``synthesize_no_finding_outcomes``, ``abandon_stale_branches_impl``)
  take a caller-supplied ``UnitOfWork``. Used by the cron sweep in
  ``parent_reconciler.sweep_masvs_audit_parents`` so the whole batch
  runs in one transaction.

* **Per-id wrappers** (``close_rejected_for_investigation``,
  ``synthesize_no_finding_for_investigation``,
  ``abandon_stale_branches``) open their own ``UnitOfWork`` and pass
  ``only_id=...`` where supported. Used by the Phase C finalize
  chokepoint so a per-investigation invocation is O(1) instead of an
  O(N) sweep scan.

History: the implementations originally lived in
:mod:`vr.masvs.parent_reconciler` because that's where the first
cron sweep wiring landed. The 500+ lines of generic investigation
logic was an accidental fit; this module is where they belong.
``parent_reconciler.py`` now imports + delegates so MASVS-specific
batch reconciliation stays the only thing under ``vr/masvs/``.
"""
from __future__ import annotations

import json as _json
import logging
import uuid as _uuid
from datetime import timedelta

from sqlalchemy import Integer, func, text, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.sql.functions import coalesce
from sqlmodel import select

from aila.modules.vr.contracts.branch import BranchStatus
from aila.modules.vr.contracts.investigation import InvestigationStatus
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
)
from aila.modules.vr.db_models.outcome_review import (
    VRInvestigationOutcomeReviewRecord,
)
from aila.modules.vr.services.config_helpers import get_int
from aila.platform.contracts import utc_now
from aila.platform.llm.client import is_llm_recently_unhealthy
from aila.platform.uow import UnitOfWork

_log = logging.getLogger(__name__)

__all__ = [
    "abandon_stale_branches",
    "abandon_stale_branches_impl",
    "close_rejected_for_investigation",
    "close_rejected_outcomes",
    "synthesize_no_finding_for_investigation",
    "synthesize_no_finding_outcomes",
]


# ─────────────────────────────────────────────────────────────────
# Sweep impls (caller supplies UoW; cron uses one UoW per tick)
# ─────────────────────────────────────────────────────────────────


async def synthesize_no_finding_outcomes(
    uow: UnitOfWork,
    *,
    only_id: str | None = None,
) -> int:
    """Synthesize ``audit_memo`` outcomes for orphaned investigations.

    Operator rule: EVERY investigation must terminate with an outcome,
    no exceptions. The existing close paths only fire when an outcome
    already exists:

      - ``services/outcome_review.py:auto_approved_no_active_voters``:
        requires primary_outcome in ``draft`` state, gets approved.
      - :func:`close_rejected_outcomes`: requires primary_outcome
        in ``rejected``/``refuted`` state, closes after siblings vote.

    Gap: variant_hunt / audit investigations that never produced any
    outcome at all (agents abandoned without submitting). Observed
    live on ``a0b33905`` -- 6 branches all ``status=abandoned`` via the
    stale-detector, ``primary_outcome_id=NULL``, investigation still
    ``running``. No closer existed for this shape until Phase C.

    Phase C: optional ``only_id`` filters the orphan scan to one
    investigation. The finalize chokepoint passes this so per-id
    invocations are O(1) instead of O(N) scans.

    Returns count of investigations resolved this tick.
    """
    # Do not synthesize "no finding" outcomes while the LLM is
    # unhealthy. During an outage every branch fails its turn and
    # gets driven terminal with zero real work; synthesizing a
    # no_finding memo then masks an infra failure as a clean audit.
    # Mirror the guard in abandon_stale_branches_impl -- skip this
    # tick and let the branches resume once the LLM recovers.
    if is_llm_recently_unhealthy(600.0):
        _log.info(
            "synthesize_no_finding: skipping (LLM unhealthy within last "
            "10 min -- orphaned branches are outage fallout, not a real "
            "no-finding result)",
        )
        return 0

    inv = VRInvestigationRecord
    branch = VRInvestigationBranchRecord

    candidate_stmt = (
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
                    ).cast(Integer),
                    0,
                ),
            ).label("terminal_count"),
        )
        .select_from(inv)
        .join(branch, branch.investigation_id == inv.id, isouter=True)
        .where(inv.status == InvestigationStatus.RUNNING.value)
        .group_by(inv.id)
    )
    if only_id is not None:
        candidate_stmt = candidate_stmt.where(inv.id == only_id)
    rows = (await uow.session.exec(candidate_stmt)).all()

    orphan_inv_ids: list[str] = []
    for row in rows:
        if not (hasattr(row, "__getitem__") and not isinstance(row, str)):
            continue
        inv_id = str(row[0])
        branch_count = int(row[1] or 0)
        terminal_count = int(row[2] or 0)
        if branch_count == 0:
            continue
        if terminal_count >= branch_count:
            orphan_inv_ids.append(inv_id)

    if not orphan_inv_ids:
        return 0

    now = utc_now()
    now_iso = now.isoformat()
    synthesized = 0

    for inv_id in orphan_inv_ids:
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
                from aila.modules.vr.services.branch_cleanup import (
                    close_orphan_branches_on_terminal,
                )
                await close_orphan_branches_on_terminal(
                    uow, inv_id, reason="investigation_completed", now=now,
                )
                synthesized += 1
            except (SQLAlchemyError, ImportError, RuntimeError) as exc:
                _log.warning(
                    "orphan close (with existing outcome) failed inv=%s: %s",
                    inv_id, exc, exc_info=True,
                )
            continue

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
        # A zero-turn investigation never actually ran -- every branch
        # reached terminal without completing a single reasoning turn
        # (LLM outage, dispatch crash, or immediate abandonment). This
        # is a failure, not a "we audited and found nothing" result.
        # Mark it FAILED (retryable via reopen / re-enqueue) instead of
        # synthesizing a hollow no_finding audit_memo that reads as a
        # clean completion.
        if total_turns == 0:
            try:
                await uow.session.exec(
                    update(inv)
                    .where(inv.id == inv_id)
                    .where(inv.status == InvestigationStatus.RUNNING.value)
                    .values(
                        status=InvestigationStatus.FAILED.value,
                        stopped_at=now,
                        updated_at=now,
                    ),
                )
                from aila.modules.vr.services.branch_cleanup import (
                    close_orphan_branches_on_terminal,
                )
                await close_orphan_branches_on_terminal(
                    uow, inv_id, reason="zero_turn_no_progress", now=now,
                )
                synthesized += 1
                _log.info(
                    "synthesize_no_finding: inv=%s marked FAILED (0 turns "
                    "across %d branches -- never ran, not synthesizing a "
                    "no_finding memo)", inv_id, len(unwrapped),
                )
            except (SQLAlchemyError, ImportError, RuntimeError) as exc:
                _log.warning(
                    "zero-turn FAILED close failed inv=%s: %s",
                    inv_id, exc, exc_info=True,
                )
            continue
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
            "synthesized_by": "investigation_finalizers.synthesize_no_finding_outcomes",
            "synthesized_at": now_iso,
            "rule": "every_investigation_has_outcome",
        }

        outcome_id = str(_uuid.uuid4())
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
                    "payload": _json.dumps(payload),
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
            from aila.modules.vr.services.branch_cleanup import (
                close_orphan_branches_on_terminal,
            )
            await close_orphan_branches_on_terminal(
                uow, inv_id, reason="investigation_completed", now=now,
            )
            synthesized += 1
        except (SQLAlchemyError, ImportError, RuntimeError) as exc:
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


async def close_rejected_outcomes(
    uow: UnitOfWork,
    *,
    only_id: str | None = None,
) -> int:
    """Force-close investigations whose primary outcome was REJECTED by quorum.

    Mirror of the ``auto_approved_no_active_voters`` path in
    ``services/outcome_review.py`` but for the rejection direction:
    once ``evaluate_quorum`` flips an outcome ``draft → rejected``
    (reject_count ≥ quorum_k), the investigation has no auto-close
    path -- it sits at ``status=running`` waiting for some other branch
    to propose an alternative outcome. In practice the other branches
    are already deep in their own audits and rarely produce a competing
    outcome, so the investigation runs forever.

    Policy: when ``primary_outcome.state ∈ {rejected, refuted}`` AND
    every active non-proposer branch has either voted on the rejected
    outcome OR is itself abandoned/completed, the rejection is
    effectively final. Mark the investigation ``completed`` with
    ``pause_reason='operator'`` (closest valid enum value), abandon any
    remaining active branches with ``closed_reason='outcome_rejected_by_quorum'``.

    Phase C: optional ``only_id`` filters the candidate scan to one
    investigation.

    Returns the count of investigations closed this tick.
    """
    inv = VRInvestigationRecord
    out = VRInvestigationOutcomeRecord
    branch = VRInvestigationBranchRecord
    review = VRInvestigationOutcomeReviewRecord

    candidate_stmt = (
        select(inv.id, inv.primary_outcome_id, out.branch_id)
        .join(out, out.id == inv.primary_outcome_id)
        .where(inv.status == InvestigationStatus.RUNNING.value)
        .where(out.state.in_(("rejected", "refuted")))
    )
    if only_id is not None:
        candidate_stmt = candidate_stmt.where(inv.id == only_id)
    candidates = (await uow.session.exec(candidate_stmt)).all()
    if not candidates:
        return 0

    closed = 0
    for inv_id, outcome_id, proposer_branch_id in candidates:
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
            continue

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
            t.pause_reason = "operator"
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


async def abandon_stale_branches_impl(uow: UnitOfWork) -> int:
    """Abandon active branches that have stopped making progress.

    Two failure modes observed in production:

      1. ``turn_count=0`` since the dispatcher created the branch hours
         ago -- the first turn never queued (lost task, dead worker,
         dependency wait that never resolved). These are dead from
         birth.
      2. ``turn_count>=1`` but ``updated_at`` is many hours old -- the
         agent made some progress, then the task chain broke (auto-
         steering operator message logged but no engine reply, ARQ
         orphan, OmniRoute crash). The branch sits ``status=active`` so
         it blocks the parent investigation from auto-completing.

    Thresholds (tunable via ConfigRegistry namespace=vr):
      ``stale_branch_frozen_min`` (default 30): minutes of inactivity
        before a branch with ``turn_count < 5`` is abandoned.
      ``stale_branch_halted_min`` (default 120): minutes of
        inactivity before a branch with ``turn_count >= 5`` is
        abandoned.

    LLM-outage gate (operator rule): branches sitting idle through
    an LLM endpoint outage are NOT stalled -- they are waiting for work.
    Abandoning them in that window destroys real progress because the
    workflow couldn't run their next turn. Skip the whole abandonment
    step when the LLM has had any error in the trailing 10 min without
    a more recent success.

    Returns the count of branches abandoned this tick.
    """
    if is_llm_recently_unhealthy(600.0):
        _log.info(
            "stale_branches: skipping abandonment (LLM unhealthy "
            "within last 10 min -- branches waiting for work, not "
            "stalled)",
        )
        return 0
    frozen_min = await get_int("stale_branch_frozen_min")
    halted_min = await get_int("stale_branch_halted_min")
    branch = VRInvestigationBranchRecord
    now = utc_now()
    frozen_cutoff = now - timedelta(minutes=frozen_min)
    halted_cutoff = now - timedelta(minutes=halted_min)

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


# ─────────────────────────────────────────────────────────────────
# Per-id wrappers (each opens its own UoW)
# ─────────────────────────────────────────────────────────────────


async def close_rejected_for_investigation(investigation_id: str) -> int:
    """Per-id wrapper for :func:`close_rejected_outcomes`.

    Returns 1 when the investigation closed this call, 0 when the
    quorum-rejected condition didn't hold.
    """
    async with UnitOfWork() as uow:
        closed = await close_rejected_outcomes(uow, only_id=investigation_id)
        await uow.commit()
    return closed


async def synthesize_no_finding_for_investigation(investigation_id: str) -> int:
    """Per-id wrapper for :func:`synthesize_no_finding_outcomes`.

    Returns 1 when an audit_memo was written, 0 when the orphan
    condition didn't hold.
    """
    async with UnitOfWork() as uow:
        wrote = await synthesize_no_finding_outcomes(
            uow, only_id=investigation_id,
        )
        await uow.commit()
    return wrote


async def abandon_stale_branches() -> int:
    """Per-id-less wrapper (sweep-shaped) for :func:`abandon_stale_branches_impl`.

    Stale-branch detection is naturally a sweep -- the LLM-outage gate
    and frozen/halted thresholds apply across all active branches.
    """
    async with UnitOfWork() as uow:
        flipped = await abandon_stale_branches_impl(uow)
        await uow.commit()
    return flipped
