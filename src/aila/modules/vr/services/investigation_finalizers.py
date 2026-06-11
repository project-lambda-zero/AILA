"""Generic investigation finalizers — operator-facing entry point.

The three helpers below handle GENERIC investigation finalization
(rejected-quorum close, orphan audit_memo synthesis, stale-branch
abandonment). They are not MASVS-specific, even though the
implementations historically live in :mod:`vr.masvs.parent_reconciler`
because that's where the first cron sweep wiring landed.

This module is the canonical API surface: ``finalize.py``,
``investigation_emit``, and ``parent_reconciler``'s sweep step all
import from here. The physical bodies stay in ``parent_reconciler``
for now to avoid risking a 500-line code move during the cutover;
the next refactor pass will move them and turn this file into the
literal implementation site rather than a re-export shim.

Public API (operator-facing names):

* :func:`close_rejected_for_investigation(inv_id)` — per-id
  rejected-quorum close. ``finalize._handle_rejected_quorum`` uses this.
* :func:`synthesize_no_finding_for_investigation(inv_id)` — per-id
  orphan audit_memo synthesis. ``finalize._handle_all_terminal_no_outcome``
  uses this.
* :func:`abandon_stale_branches()` — sweep that flips ACTIVE branches
  whose ``updated_at`` is past the staleness threshold. No per-id
  variant: stale-branch detection is naturally a sweep (LLM-outage
  gate + frozen/halted thresholds apply across all active branches).
"""
from __future__ import annotations

from aila.platform.uow import UnitOfWork

__all__ = [
    "abandon_stale_branches",
    "close_rejected_for_investigation",
    "synthesize_no_finding_for_investigation",
]


async def close_rejected_for_investigation(investigation_id: str) -> int:
    """Close a single investigation whose primary outcome is rejected.

    See :func:`vr.masvs.parent_reconciler._close_rejected_outcomes` for
    the full policy. Returns 1 when the investigation closed this call,
    0 when the quorum-rejected condition didn't hold (e.g. some active
    sibling hasn't voted yet).
    """
    # Deferred import: parent_reconciler imports a large module graph
    # we don't want pulled in at every consumer's import time.
    from ..masvs.parent_reconciler import (  # noqa: PLC0415
        _close_rejected_outcomes,
    )

    async with UnitOfWork() as uow:
        closed = await _close_rejected_outcomes(uow, only_id=investigation_id)
        await uow.commit()
    return closed


async def synthesize_no_finding_for_investigation(investigation_id: str) -> int:
    """Synthesize an audit_memo for one orphaned investigation.

    See :func:`vr.masvs.parent_reconciler._synthesize_no_finding_outcomes`
    for the policy. Returns 1 when an audit_memo was written, 0 when the
    orphan condition didn't hold (e.g. an active branch still exists).
    """
    from ..masvs.parent_reconciler import (  # noqa: PLC0415
        _synthesize_no_finding_outcomes,
    )

    async with UnitOfWork() as uow:
        wrote = await _synthesize_no_finding_outcomes(
            uow, only_id=investigation_id,
        )
        await uow.commit()
    return wrote


async def abandon_stale_branches() -> int:
    """Sweep: abandon ACTIVE branches whose ``updated_at`` is stale.

    Frozen-from-birth (``turn_count<5`` AND idle >=
    ``VR_STALE_BRANCH_FROZEN_MIN`` minutes) and halted-after-progress
    (``turn_count>=5`` AND idle >= ``VR_STALE_BRANCH_HALTED_MIN``)
    are both handled. Skips abandonment entirely while
    ``is_llm_recently_unhealthy`` is True (operator rule: branches
    waiting through an LLM outage are not stalled).
    """
    from ..masvs.parent_reconciler import (  # noqa: PLC0415
        _abandon_stale_branches,
    )

    async with UnitOfWork() as uow:
        flipped = await _abandon_stale_branches(uow)
        await uow.commit()
    return flipped
