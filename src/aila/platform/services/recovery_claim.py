"""Atomic recovery-claim primitive shared by the two recovery sweeps.

Both :mod:`aila.platform.services.stall_recovery` and
:mod:`aila.platform.services.stuck_healer` walk overlapping investigation
sets. Their eligibility clauses intentionally overlap so an investigation
that fell through one sweep's pre-filters is still recoverable by the
other: an inv with ``status=running`` past the idle grace, no live
``taskrecord``, and no resumable ``workflow_state_cursor`` matches BOTH
sweeps. Without mutual exclusion the two sweeps in the same cron tick
(or two worker processes running the sweep in parallel) re-enqueue the
same investigation twice with divergent semantics:

* ``sweep_stalled_investigations`` submits directly via the module's
  ``submit_fn`` with ``bypass_dedup=True`` (so the built-in SHA dedup
  cannot catch it);
* ``sweep_stuck_investigations`` submits via
  :func:`reenqueue_investigation`, which first cancels stale tasks and
  wipes crashed cursors before its own submit.

Two concurrent re-enqueues on one inv corrupt state (double turn
billing, split cursor). Issue #121.

This module offers ONE primitive both sweeps call before their submit:
:func:`try_claim_recovery`. The claim is a compare-and-set on the
investigation's ``updated_at`` (or module-chosen equivalent) column --
identical shape to the ``register_crash`` / ``evaluate_quorum`` atomic
UPDATE pattern the rest of the platform uses. The winning caller's
``UPDATE ... WHERE <col> = :seen RETURNING id`` matches exactly one
row across every racer; the losing callers' UPDATEs affect zero rows
and MUST skip their submit this tick.

Bumping the timestamp is NOT a side effect -- it IS the signal every
subsequent sweep uses to decide "this row was recently touched". After
a successful claim, the row moves past every sweep's idle-grace cutoff
so the next tick's SELECT does not surface it again until the actual
recovery drives a turn that settles the row.

Failure mode: an SQLAlchemy transport error while attempting the claim
returns ``False`` -- the caller MUST skip. This is the safe default:
better to skip a tick than to re-enqueue an investigation whose claim
status we could not confirm.
"""
from __future__ import annotations

import logging
from datetime import datetime

from sqlalchemy import text as _sql_text
from sqlalchemy.exc import SQLAlchemyError

from aila.storage.database import async_session_scope

__all__ = ["try_claim_recovery"]

_log = logging.getLogger(__name__)


async def try_claim_recovery(
    *,
    inv_table: str,
    timestamp_column: str,
    inv_id: str,
    seen_timestamp: datetime,
) -> bool:
    """Atomically claim one investigation for a recovery sweep.

    Returns ``True`` when the caller won the claim (the compare-and-set
    UPDATE bumped the timestamp), ``False`` when a concurrent recovery
    sweep already claimed the row between the SELECT that produced
    ``seen_timestamp`` and this call, OR when the UPDATE itself failed
    with a transport-layer error (safe-default skip).

    Callers MUST pass the exact ``timestamp_column`` value they saw at
    SELECT time. Two concurrent racers each executing this UPDATE with
    the same ``(inv_id, seen_timestamp)`` produce exactly one row-hit
    across the pair: whichever transaction commits first bumps the
    timestamp; the other's ``WHERE`` no longer matches and its RETURNING
    is empty.

    Args:
        inv_table: SQL identifier for the module's investigations
            table (trusted platform / module constant, never operator
            input; Postgres disallows bind parameters for identifiers).
        timestamp_column: column name whose value the caller observed
            at SELECT time. Must match the SELECT-side eligibility
            column so a successful claim also hides the row from the
            next tick's SELECT.
        inv_id: investigation row primary key.
        seen_timestamp: value of ``timestamp_column`` returned by the
            caller's SELECT. The claim's ``WHERE`` compares this
            exactly; a microsecond-level mismatch (e.g. the row was
            touched by an unrelated writer between SELECT and claim)
            correctly fails the claim.

    Returns:
        True if this caller won the claim, False if a racer already
        claimed the row or the UPDATE failed transport-wise.
    """
    stmt = _sql_text(
        f"""
        UPDATE {inv_table}
        SET {timestamp_column} = NOW()
        WHERE id = :inv_id
          AND {timestamp_column} = :seen
        RETURNING id
        """,
    ).bindparams(inv_id=inv_id, seen=seen_timestamp)
    try:
        async with async_session_scope() as session:
            row = (await session.execute(stmt)).first()
            await session.commit()
    except SQLAlchemyError as exc:
        _log.warning(
            "try_claim_recovery: UPDATE failed table=%s id=%s: %s",
            inv_table, inv_id, exc,
        )
        return False
    return row is not None
