"""Reaper for orphan VR investigation branches.

Background: an investigation can transition to a terminal status
(``completed`` / ``failed`` / ``abandoned``) via several paths today —
cap_exceeded sweep in ``investigation_emit``, the dispatcher's halt-on-
ship in ``outcome_dispatcher._update_outcome_status``, the operator-
driven pause-then-complete path that ran before the status_locked fix
in ``investigation_setup``, and manual DB operator action. Some of
those paths did NOT cascade to branches, leaving rows with
``status='active'`` under a terminal parent. The dashboard shows them
as "still running" forever; the call-stack reasoning treats them as
in-flight; nothing actually drives them because the worker's per-turn
status check sees the investigation isn't running and exits the loop.

Operator observed 736 such orphan branches accumulated by 2026-06-03,
distributed across cap_exceeded completions and pause-bypass bug
residue. This reaper cleans them up automatically every minute via the
ARQ cron, so even when a new code path forgets to halt branches at
transition time, the orphans get reclaimed within ~1 minute.

This is a SAFETY NET. The proactive fix lives wherever the
investigation status is flipped — those call sites SHOULD halt branches
in the same transaction. The reaper exists for the cases where they
don't (legacy, bugs, manual DB ops).

Concurrency safety: the sweep is a single atomic SQL UPDATE, NOT a
Python SELECT-then-UPDATE. PostgreSQL re-evaluates the WHERE clause at
update time and acquires per-row locks, so:

  * an operator who restores an investigation (terminal -> running)
    between the reaper's plan and the row's update simply causes that
    row to fall out of the match set; the branch is NOT abandoned.
  * a worker that's commit-racing a branch update (e.g. writing a
    fresh turn result) holds the row lock first; the reaper waits or
    sees the branch no longer matches because its updated_at advanced
    past the touch-grace window.

Two safety graces baked into the WHERE so even the SQL-atomic version
doesn't reap branches that are about to be written by some other path:

  (a) the investigation must have been terminal for at least
      ``_ORPHAN_GRACE_SECONDS`` (5 min). Covers in-flight transitions
      that are about to halt their own branches.
  (b) the branch must not have been updated in the last
      ``_BRANCH_TOUCH_GRACE_SECONDS`` (2 min). Covers worker mid-LLM-call
      whose commit is in flight.

Cost of waiting is a UI showing "running" for a few minutes; cost of
NOT waiting is a worker's commit overwriting the reaper's flip (or
vice-versa). The graces are intentionally generous.
"""
from __future__ import annotations

import logging

from sqlalchemy import text

from aila.modules.vr.contracts import InvestigationStatus
from aila.platform.uow import UnitOfWork

__all__ = ["sweep_orphan_active_branches"]

_log = logging.getLogger(__name__)

# Terminal statuses where active branches under them are orphans.
# PAUSED is intentionally excluded — paused branches resume cleanly
# when the operator un-pauses; reaping them would force the operator
# to also resurrect every branch by hand.
_TERMINAL_STATUSES = (
    InvestigationStatus.COMPLETED.value,
    InvestigationStatus.FAILED.value,
    InvestigationStatus.ABANDONED.value,
)

_ORPHAN_GRACE_SECONDS = 300
_BRANCH_TOUCH_GRACE_SECONDS = 120

_SWEEP_SQL = text("""
    UPDATE vr_investigation_branches AS b
    SET status = 'abandoned',
        closed_reason = CASE
            WHEN b.closed_reason IS NULL OR b.closed_reason = ''
                THEN 'investigation_terminal:' || i.status
            ELSE b.closed_reason || '; investigation_terminal:' || i.status
        END,
        closed_at = COALESCE(b.closed_at, NOW()),
        updated_at = NOW()
    FROM vr_investigations AS i
    WHERE b.investigation_id::text = i.id::text
      AND b.status = 'active'
      AND i.status = ANY(:terminal_statuses)
      AND (
          (i.stopped_at IS NOT NULL
           AND i.stopped_at < NOW() - (:inv_grace_s || ' seconds')::interval)
          OR
          (i.stopped_at IS NULL
           AND i.updated_at < NOW() - (:inv_grace_s || ' seconds')::interval)
      )
      AND b.updated_at < NOW() - (:branch_grace_s || ' seconds')::interval
    RETURNING b.id
""")


async def sweep_orphan_active_branches() -> int:
    """Flip ACTIVE branches under terminal investigations to ABANDONED.

    Atomic per row via a single ``UPDATE ... FROM ... RETURNING`` so
    concurrent investigation-restore and worker branch-commits don't
    race against the reaper's snapshot.

    Returns the number of branches flipped.
    """
    async with UnitOfWork() as uow:
        result = await uow.session.exec(
            _SWEEP_SQL.bindparams(
                terminal_statuses=list(_TERMINAL_STATUSES),
                inv_grace_s=_ORPHAN_GRACE_SECONDS,
                branch_grace_s=_BRANCH_TOUCH_GRACE_SECONDS,
            ),
        )
        rows = list(result)
        await uow.commit()
    if rows:
        _log.warning(
            "branch_reaper: flipped %d orphan active branches under "
            "terminal investigations (inv_grace=%ds branch_grace=%ds)",
            len(rows), _ORPHAN_GRACE_SECONDS, _BRANCH_TOUCH_GRACE_SECONDS,
        )
    return len(rows)
