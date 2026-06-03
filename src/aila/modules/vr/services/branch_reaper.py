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

This reaper cleans them up automatically every minute via the ARQ
cron, so even when a new code path forgets to halt branches at
transition time, the orphans get reclaimed within ~1 minute.

Concurrency safety: the sweep is a single ORM ``update()`` statement,
NOT a Python SELECT-then-UPDATE. SQLAlchemy compiles it to a
``UPDATE ... FROM ... WHERE ... RETURNING ...`` that PostgreSQL
evaluates atomically with per-row locks acquired at the UPDATE step.
So:

  * an operator who restores an investigation (terminal -> running)
    between query plan and row update simply causes that row to fall
    out of the match set; the branch is NOT abandoned.
  * a worker that's commit-racing a branch update holds the row lock
    first; the reaper waits or sees the branch's updated_at advanced
    past the touch-grace window, no flip.

Two safety graces baked into the WHERE so even the SQL-atomic version
doesn't reap branches that are about to be written by some other path:

  (a) the investigation must have been terminal for at least
      ``_ORPHAN_GRACE_SECONDS`` (5 min). Covers in-flight transitions
      that are about to halt their own branches.
  (b) the branch must not have been updated in the last
      ``_BRANCH_TOUCH_GRACE_SECONDS`` (2 min). Covers worker mid-LLM-call
      whose commit is in flight.

Both graces are intentionally generous: cost of waiting is a UI
showing "running" for a few minutes; cost of NOT waiting is a worker's
commit overwriting the reaper's flip (or vice-versa).
"""
from __future__ import annotations

import logging
from datetime import timedelta

from sqlalchemy import and_, case, or_, update
from sqlalchemy.sql.functions import coalesce

from aila.modules.vr.contracts import BranchStatus, InvestigationStatus
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationRecord,
)
from aila.platform.contracts._common import utc_now
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


async def sweep_orphan_active_branches() -> int:
    """Flip ACTIVE branches under terminal investigations to ABANDONED.

    Atomic per row via a single ORM ``update()`` compiled to ``UPDATE
    ... FROM ... WHERE ... RETURNING``. Concurrent investigation-restore
    and worker branch-commits don't race against the reaper's snapshot.

    Returns the number of branches flipped.
    """
    now = utc_now()
    inv_terminal_cutoff = now - timedelta(seconds=_ORPHAN_GRACE_SECONDS)
    branch_touch_cutoff = now - timedelta(seconds=_BRANCH_TOUCH_GRACE_SECONDS)

    BR = VRInvestigationBranchRecord  # noqa: N806
    INV = VRInvestigationRecord  # noqa: N806

    new_reason = case(
        (
            or_(BR.closed_reason.is_(None), BR.closed_reason == ""),
            "investigation_terminal:" + INV.status,
        ),
        else_=BR.closed_reason + "; investigation_terminal:" + INV.status,
    )

    stmt = (
        update(BR)
        .where(
            BR.investigation_id == INV.id,
            BR.status == BranchStatus.ACTIVE.value,
            INV.status.in_(_TERMINAL_STATUSES),  # type: ignore[attr-defined]
            # Grace (a): investigation must have been terminal long enough.
            # Use stopped_at when set (true transition timestamp);
            # fall back to updated_at for legacy rows without stopped_at.
            or_(
                and_(
                    INV.stopped_at.is_not(None),
                    INV.stopped_at < inv_terminal_cutoff,
                ),
                and_(
                    INV.stopped_at.is_(None),
                    INV.updated_at < inv_terminal_cutoff,
                ),
            ),
            # Grace (b): branch must be idle long enough.
            BR.updated_at < branch_touch_cutoff,
        )
        .values(
            status=BranchStatus.ABANDONED.value,
            closed_reason=new_reason,
            closed_at=coalesce(BR.closed_at, now),
            updated_at=now,
        )
        .returning(BR.id)
        .execution_options(synchronize_session=False)
    )

    async with UnitOfWork() as uow:
        result = await uow.session.exec(stmt)
        flipped_ids = list(result)
        await uow.commit()

    if flipped_ids:
        _log.warning(
            "branch_reaper: flipped %d orphan active branches under "
            "terminal investigations (inv_grace=%ds branch_grace=%ds)",
            len(flipped_ids), _ORPHAN_GRACE_SECONDS, _BRANCH_TOUCH_GRACE_SECONDS,
        )
    return len(flipped_ids)
