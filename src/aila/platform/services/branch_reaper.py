"""Reaper for orphan investigation branches.

An investigation can transition to a terminal status (``completed`` / ``failed``
/ ``abandoned``) via several paths (cap-exceeded sweep, the dispatcher's
halt-on-ship, the operator pause-then-complete path, manual DB action). Some of
those paths did not cascade to branches, leaving rows with ``status='active'``
under a terminal parent. The dashboard shows them as "still running" forever;
nothing drives them because the worker's per-turn status check sees the
investigation is not running and exits the loop.

This reaper cleans them up every cron tick, so even when a new code path forgets
to halt branches at transition time, the orphans get reclaimed within ~1 minute.

Concurrency safety: the sweep is a single ORM ``update()`` statement, NOT a
Python SELECT-then-UPDATE. SQLAlchemy compiles it to ``UPDATE ... FROM ... WHERE
... RETURNING`` that PostgreSQL evaluates atomically with per-row locks acquired
at the UPDATE step. So:

  * an operator who restores an investigation (terminal -> running) between
    query plan and row update simply causes that row to fall out of the match
    set; the branch is NOT abandoned.
  * a worker commit-racing a branch update holds the row lock first; the reaper
    waits or sees the branch's updated_at advanced past the touch-grace window,
    no flip.

Two safety graces baked into the WHERE:

  (a) the investigation must have been terminal for at least
      ``_ORPHAN_GRACE_SECONDS`` (5 min). Covers in-flight transitions that are
      about to halt their own branches.
  (b) the branch must not have been updated in the last
      ``_BRANCH_TOUCH_GRACE_SECONDS`` (2 min). Covers a worker mid-LLM-call
      whose commit is in flight.

Generic over the module: the caller supplies its branch + investigation record
models; this service never names a module. Each module binds the models via a
module-level ``functools.partial`` so the registered sweep callable is a stable
object (the periodic-sweep registry keys re-registration on callable identity).
"""
from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from sqlalchemy import and_, case, or_, update
from sqlalchemy.sql.functions import coalesce

from aila.platform.contracts import utc_now
from aila.platform.contracts.enums import BranchStatus, InvestigationStatus
from aila.platform.uow import UnitOfWork

__all__ = ["sweep_orphan_active_branches"]

_log = logging.getLogger(__name__)

# Terminal statuses where active branches under them are orphans. PAUSED is
# intentionally excluded -- paused branches resume cleanly when the operator
# un-pauses; reaping them would force the operator to also resurrect every
# branch by hand.
_TERMINAL_STATUSES = (
    InvestigationStatus.COMPLETED.value,
    InvestigationStatus.FAILED.value,
    InvestigationStatus.ABANDONED.value,
)

_ORPHAN_GRACE_SECONDS = 300
_BRANCH_TOUCH_GRACE_SECONDS = 120


async def sweep_orphan_active_branches(
    *,
    branch_model: Any,
    investigation_model: Any,
) -> int:
    """Flip ACTIVE branches under terminal investigations to ABANDONED.

    Atomic per row via a single ORM ``update()`` compiled to ``UPDATE ... FROM
    ... WHERE ... RETURNING``. Concurrent investigation-restore and worker
    branch-commits don't race against the reaper's snapshot.

    ``branch_model`` and ``investigation_model`` are the caller's concrete
    record models. Returns the number of branches flipped.
    """
    now = utc_now()
    inv_terminal_cutoff = now - timedelta(seconds=_ORPHAN_GRACE_SECONDS)
    branch_touch_cutoff = now - timedelta(seconds=_BRANCH_TOUCH_GRACE_SECONDS)

    BR = branch_model
    INV = investigation_model

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
            INV.status.in_(_TERMINAL_STATUSES),
            # Grace (a): investigation must have been terminal long enough.
            # Use stopped_at when set (true transition timestamp); fall back to
            # updated_at for legacy rows without stopped_at.
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
            "branch_reaper: flipped %d orphan active branches under terminal "
            "investigations (inv_grace=%ds branch_grace=%ds)",
            len(flipped_ids), _ORPHAN_GRACE_SECONDS, _BRANCH_TOUCH_GRACE_SECONDS,
        )
    return len(flipped_ids)
