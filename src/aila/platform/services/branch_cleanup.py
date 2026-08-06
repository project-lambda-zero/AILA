"""Orphan-branch cleanup on investigation completion.

When an investigation transitions to a terminal status (COMPLETED / FAILED /
ABANDONED), every branch still in a non-terminal projection status (``active``)
must be moved to ``abandoned`` with ``closed_reason='investigation_completed'``
so the operator-facing projection is consistent. Without this, a branch that
raced the stale-detector could keep advancing turns under a completed
investigation with no UI signal that it was orphaned.

Contract:
  - Caller passes a ``UnitOfWork`` whose session is mid-transaction and the
    concrete branch table name (``branch_table``); the helper never names a
    module. The table name is a trusted module constant, not user input.
  - Helper UPDATEs the branch table only -- no commit, no flush; that is the
    caller's responsibility. This lets the caller bundle branch-cleanup
    atomicity with its existing inv.status write.
  - Helper does NOT close branches in ``completed`` / ``abandoned`` /
    ``merged`` / ``promoted`` / ``paused`` -- those are correct states the
    branch reached on its own merit (``paused`` is an operator holding pattern
    that resume owns).
  - Returns the count of branches transitioned for log visibility.
"""
from __future__ import annotations

import logging
from datetime import datetime

from sqlalchemy import text as _sql_text

from aila.platform.contracts import utc_now
from aila.platform.uow import UnitOfWork

_log = logging.getLogger(__name__)

__all__ = ["close_orphan_branches_on_terminal"]


# Branch statuses we forcibly close when their investigation goes terminal.
# ``completed`` / ``abandoned`` / ``merged`` / ``promoted`` / ``paused`` are
# intentionally excluded:
#
# - ``completed`` / ``abandoned`` / ``merged`` / ``promoted`` -- branch already
#   reached its own terminal; we don't rewrite history.
# - ``paused`` -- operator may pause the investigation deliberately as a
#   holding pattern; closing the branch here would surprise them. pause_resume
#   owns the paused -> active flip on resume, and a terminal investigation
#   forbids resume anyway.
_PROJECTION_LIVE_STATUSES: tuple[str, ...] = ("active",)


async def close_orphan_branches_on_terminal(
    uow: UnitOfWork,
    investigation_id: str,
    *,
    branch_table: str,
    reason: str = "investigation_completed",
    now: datetime | None = None,
) -> int:
    """Close every active branch under the given investigation.

    Returns the rowcount of branches transitioned to ``abandoned``.

    ``branch_table`` is the concrete branch table name the caller's module
    owns (e.g. ``vr_investigation_branches``); it is a trusted constant
    interpolated into the statement (a table identifier cannot be a bind
    parameter). The caller MUST commit; the helper writes inside the caller's
    UoW so branch-cleanup and the inv.status flip succeed-or-fail atomically.

    ``reason`` is stamped on ``closed_reason`` (prepended to any existing
    content with `` | `` if a row already had one). Default
    ``investigation_completed`` covers the common case; pass
    ``investigation_failed`` / ``investigation_abandoned`` when the parent
    transitioned to those instead.
    """
    ts = now or utc_now()
    stmt = _sql_text(
        f"UPDATE {branch_table} "
        "SET status = 'abandoned', "
        "    closed_reason = CASE "
        "        WHEN closed_reason IS NULL OR closed_reason = '' THEN :reason "
        "        ELSE closed_reason || ' | ' || :reason "
        "    END, "
        "    closed_at = COALESCE(closed_at, :ts), "
        "    updated_at = :ts "
        "WHERE investigation_id = :inv "
        "  AND status = ANY(:live_statuses)"
    ).bindparams(
        reason=reason,
        ts=ts,
        inv=investigation_id,
        live_statuses=list(_PROJECTION_LIVE_STATUSES),
    )
    result = await uow.session.exec(stmt)
    rowcount = result.rowcount or 0
    if rowcount:
        _log.info(
            "close_orphan_branches_on_terminal inv=%s reason=%s closed=%d",
            investigation_id, reason, rowcount,
        )
    return rowcount
