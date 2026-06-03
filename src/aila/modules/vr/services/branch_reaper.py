"""Reaper for orphan VR investigation branches.

Background: an investigation can transition to a terminal status
(``completed`` / ``failed`` / ``cancelled``) via several paths today —
cap_exceeded sweep in ``investigation_emit``, the dispatcher's halt-on-
ship in ``outcome_dispatcher._update_outcome_status``, the operator-
driven pause-then-complete path that ran before the status_locked fix
in ``investigation_setup``, and manual DB operator action. Some of
those paths did NOT cascade to branches, leaving rows with
``status='active'`` under a terminal parent. The dashboard shows them
as "still running" forever; the call-stack reasoning treats them as
in-flight; nothing actually drives them because the worker's per-turn
status check sees the investigation isn't running and exits the loop.

Operator observed 736 such orphan branches accumulated this session
(today: 2026-06-03), distributed across cap_exceeded completions and
old pause-bypass bug residue. This reaper cleans them up automatically
every minute via the ARQ cron, so even when a new code path forgets to
halt branches at transition time, the orphans get reclaimed within ~1
minute.

This is a SAFETY NET. The proactive fix lives wherever the
investigation status is flipped — those call sites SHOULD halt branches
in the same transaction. The reaper exists for the cases where they
don't (legacy, bugs, manual DB ops).
"""
from __future__ import annotations

import logging

from sqlmodel import select as _select

from aila.modules.vr.contracts import BranchStatus, InvestigationStatus
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationRecord,
)
from aila.platform.contracts._common import utc_now
from aila.platform.uow import UnitOfWork

__all__ = ["sweep_orphan_active_branches"]

_log = logging.getLogger(__name__)

_TERMINAL_INVESTIGATION_STATUSES = frozenset({
    InvestigationStatus.COMPLETED.value,
    InvestigationStatus.FAILED.value,
    InvestigationStatus.CANCELLED.value,
})


async def sweep_orphan_active_branches() -> int:
    """Flip any ACTIVE branch under a terminal investigation to ABANDONED.

    Returns the count of branches flipped. Safe to run every minute;
    no-op when nothing's orphaned (the typical case once the install
    has been running with this reaper for a while).
    """
    async with UnitOfWork() as uow:
        rows = (await uow.session.exec(
            _select(VRInvestigationBranchRecord, VRInvestigationRecord)
            .join(
                VRInvestigationRecord,
                VRInvestigationRecord.id == VRInvestigationBranchRecord.investigation_id,
            )
            .where(
                VRInvestigationBranchRecord.status == BranchStatus.ACTIVE.value,
                VRInvestigationRecord.status.in_(_TERMINAL_INVESTIGATION_STATUSES),  # type: ignore[attr-defined]
            ),
        )).all()
        if not rows:
            return 0
        now = utc_now()
        flipped = 0
        for branch, inv in rows:
            branch.status = BranchStatus.ABANDONED.value
            reason_tag = f"investigation_terminal:{inv.status}"
            if branch.closed_reason and reason_tag not in branch.closed_reason:
                branch.closed_reason = f"{branch.closed_reason}; {reason_tag}"
            else:
                branch.closed_reason = reason_tag
            if branch.closed_at is None:
                branch.closed_at = now
            branch.updated_at = now
            uow.session.add(branch)
            flipped += 1
        await uow.commit()
        _log.warning(
            "branch_reaper: flipped %d orphan active branches under "
            "terminal investigations to abandoned",
            flipped,
        )
        return flipped
