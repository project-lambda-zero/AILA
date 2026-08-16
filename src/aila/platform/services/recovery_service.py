"""Unified recovery-service surface for the two investigation sweeps.

Owns the eligibility SELECTs and per-row strategy classification that
:mod:`aila.platform.services.stall_recovery` and
:mod:`aila.platform.services.stuck_healer` used to duplicate. The two
sweeps still register separately with the periodic-sweep registry
(their execution paths diverge intentionally -- see below), but every
"is this row eligible, and if so under which strategy" decision now
lives in exactly one place.

Split rationale
---------------

The two sweeps target overlapping-but-not-identical row sets:

* ``sweep_stalled_investigations`` handles ``created`` / ``running`` /
  ``stalled`` rows that have gone past the module's idle threshold and
  have no live ``taskrecord``. Its execution is a rate-limited
  fan-out submit through the module's plain ``submit_fn``. Cursor
  state is IGNORED at eligibility time -- a running row with a
  resumable cursor is still eligible if its task is dead.
* ``sweep_stuck_investigations`` handles the strict subset ``running``
  rows that ALSO have no resumable ``workflow_state_cursor``. Its
  execution is the full :func:`reenqueue_investigation`
  four-source-of-truth reset plus a durable ``kind='recovery'``
  ledger event (RFC-07 #31 criterion 6).

The two paths do different work per row (rate-limited direct submit
vs cursor+task reset + journal), so merging into a single sweep would
be a behavior change: whichever strategy we picked, the other's
guarantees would be lost. Issue #133's recommended resolution
explicitly allows the residual divergence -- what it demands (and what
this module delivers) is that eligibility + strategy live in one place
so the two sweeps cannot silently drift apart.

Mutual exclusion (issue #121) still runs through
:func:`aila.platform.services.recovery_claim.try_claim_recovery`
unchanged. Both sweeps call it before their per-row submit, so the
double-submit race stays neutralized regardless of which strategy
classified the row.

Public surface
--------------

* :data:`NON_RESUMABLE_CURSOR_STATES` -- shared cursor sentinel set the
  stuck-healer eligibility SELECT filters on. Kept in one place so a
  future addition (e.g. a new ``__superseded__`` terminal) does not
  drift between call sites.
* :data:`LIVE_TASK_STATUSES` -- the ``taskrecord.status`` values that
  make a row ineligible for BOTH sweeps.
* :class:`RecoveryStrategy` -- names the two execution paths.
* :class:`PlatformRecoveryService` -- namespace holding the shared
  eligibility SELECTs, the row classifier, and the atomic
  status-flip claim used by the stalled path. Everything is a
  staticmethod so callers use it as a service surface without
  constructing an instance.
"""
from __future__ import annotations

import enum
import logging
from datetime import datetime
from typing import Any

from sqlalchemy import text as _sql_text
from sqlalchemy.exc import SQLAlchemyError

from aila.platform.services.recovery_claim import try_claim_recovery
from aila.storage.database import async_session_scope

__all__ = [
    "LIVE_TASK_STATUSES",
    "NON_RESUMABLE_CURSOR_STATES",
    "PlatformRecoveryService",
    "RecoveryStrategy",
]

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Shared constants
# ---------------------------------------------------------------------------

# Cursor states that count as NON-resumable for the stuck-healer path.
# Terminal engine states plus the ``__paused__`` operator sentinel. Kept
# in sync with :data:`aila.platform.tasks.state_reconciler._TERMINAL_CURSOR_STATES`
# (the reconciler owns the resumable side); the healer runs when the
# reconciler cannot -- either the cursor is absent or it is one of
# these non-resumable values.
NON_RESUMABLE_CURSOR_STATES: tuple[str, ...] = (
    "__crashed__",
    "__failed__",
    "__cancelled__",
    "__succeeded__",
    "__paused__",
)

# ``taskrecord.status`` values that make an investigation ineligible for
# every recovery sweep: an in-flight task is either about to make
# progress or about to be reaped by the task-level state reconciler.
LIVE_TASK_STATUSES: tuple[str, ...] = ("queued", "running", "waiting")


# ---------------------------------------------------------------------------
# Strategy classifier
# ---------------------------------------------------------------------------


class RecoveryStrategy(enum.StrEnum):
    """Which recovery path applies to an eligible row.

    ``STALL_REENQUEUE`` -- direct rate-limited submit (fan-out per active
    branch, or one inv-level submit for single-submit kinds). Handled
    by :func:`aila.platform.services.stall_recovery.sweep_stalled_investigations`.

    ``STUCK_HEAL`` -- full :func:`reenqueue_investigation` reset plus a
    durable resilience recovery event. Handled by
    :func:`aila.platform.services.stuck_healer.sweep_stuck_investigations`.
    """

    STALL_REENQUEUE = "stall_reenqueue"
    STUCK_HEAL = "stuck_heal"


# ---------------------------------------------------------------------------
# Service surface
# ---------------------------------------------------------------------------


class PlatformRecoveryService:
    """Shared eligibility + classification surface for the two sweeps.

    Every method is a ``staticmethod`` so this class is a stable
    namespace, never an object with state. Callers reach it as
    ``PlatformRecoveryService.<method>`` -- no factory, no injection.
    The class exists to give the RFC's "one service" wording a real
    reference point in the codebase rather than a loose module.
    """

    # Re-export the shared constants on the class surface so callers
    # that already import ``PlatformRecoveryService`` do not need a
    # second import to reach the sentinel tuples.
    NON_RESUMABLE_CURSOR_STATES = NON_RESUMABLE_CURSOR_STATES
    LIVE_TASK_STATUSES = LIVE_TASK_STATUSES

    # ---- Row classifier ------------------------------------------------

    @staticmethod
    def classify(
        *,
        status: str,
        has_live_task: bool,
        has_resumable_cursor: bool,
        stall_sweepable_statuses: tuple[str, ...] = (
            "created", "running", "stalled",
        ),
        stuck_running_statuses: tuple[str, ...] = ("running",),
    ) -> RecoveryStrategy | None:
        """Name the recovery strategy that applies to this row.

        Encodes the eligibility+strategy decision both sweeps used to
        implement independently. Not a scheduler: returns the strategy
        the row IS ELIGIBLE FOR, or ``None`` when neither sweep should
        touch it. The two live sweeps still run independently; the
        classifier is the shared decision surface so the two cannot
        drift apart under future edits.

        Precedence (matches the pre-lift behavior when the two sweeps
        raced on the same row):

        * A live in-flight ``taskrecord`` blocks every sweep -- return
          ``None``.
        * A ``running`` row with no resumable cursor matches
          ``STUCK_HEAL`` (the narrower zombie the reconciler cannot
          recover). The stall sweep would also match the same row;
          both sweeps rely on
          :func:`aila.platform.services.recovery_claim.try_claim_recovery`
          for mutual exclusion at execution time.
        * Otherwise ``created`` / ``running`` / ``stalled`` matches
          ``STALL_REENQUEUE`` (the broader Cancelled-error backstop).
        * Anything else -> ``None`` (paused / cancelled / completed /
          failed / abandoned rows are operator terminals or belong
          to another sweep).
        """
        if has_live_task:
            return None
        if (
            status in stuck_running_statuses
            and not has_resumable_cursor
        ):
            return RecoveryStrategy.STUCK_HEAL
        if status in stall_sweepable_statuses:
            return RecoveryStrategy.STALL_REENQUEUE
        return None

    # ---- Eligibility SELECTs -------------------------------------------

    @staticmethod
    async def fetch_stall_candidates(
        *,
        investigations_table: str,
        sweepable_kinds: tuple[str, ...],
        cutoff: datetime,
        limit: int,
    ) -> list[dict[str, Any]]:
        """SELECT rows eligible for :attr:`RecoveryStrategy.STALL_REENQUEUE`.

        Returns rows whose::

            status IN ('created', 'running', 'stalled')
            AND pause_reason IS NULL
            AND kind = ANY(:kinds)
            AND (status = 'stalled' OR updated_at < :cutoff)
            AND NO in-flight ``taskrecord`` references this inv

        Cursor state is intentionally NOT filtered here: a running row
        whose task died still needs recovery even if its cursor is
        resumable (the task-level reconciler owns the resumable-cursor
        path, but it only runs when a taskrecord still exists).

        The ``investigations_table`` identifier is a trusted module
        constant interpolated into the SQL body -- Postgres disallows
        bind parameters for identifiers.
        """
        stmt = _sql_text(
            f"""
            SELECT inv.id::text AS id,
                   inv.kind AS kind,
                   inv.status AS status,
                   inv.team_id::text AS team_id,
                   inv.updated_at AS updated_at
            FROM {investigations_table} inv
            WHERE inv.status IN ('created', 'running', 'stalled')
              AND inv.pause_reason IS NULL
              AND inv.kind = ANY(:kinds)
              AND (inv.status = 'stalled' OR inv.updated_at < :cutoff)
              AND NOT EXISTS (
                  SELECT 1
                  FROM taskrecord t
                  WHERE t.kwargs_json::jsonb->>'investigation_id'
                        = inv.id::text
                    AND t.status = ANY(:live_task_statuses)
              )
            ORDER BY inv.updated_at ASC
            LIMIT :limit
            """,
        ).bindparams(
            kinds=list(sweepable_kinds),
            cutoff=cutoff,
            live_task_statuses=list(LIVE_TASK_STATUSES),
            limit=limit,
        )
        async with async_session_scope() as session:
            return [
                dict(r)
                for r in (await session.execute(stmt)).mappings().all()
            ]

    @staticmethod
    async def fetch_stuck_candidates(
        *,
        investigations_table: str,
        running_status_values: tuple[str, ...],
        inv_timestamp_column: str,
        cutoff: datetime,
        limit: int,
    ) -> list[tuple[str, datetime]]:
        """SELECT rows eligible for :attr:`RecoveryStrategy.STUCK_HEAL`.

        Returns ``(id, timestamp)`` pairs whose::

            status = ANY(:running_values)
            AND <inv_timestamp_column> < :cutoff
            AND NO in-flight ``taskrecord`` references this inv
            AND NO ``workflow_state_cursor`` for this inv is resumable

        The paired timestamp is the caller's compare-and-set guard for
        :func:`try_claim_recovery` so the mutual exclusion with the
        stall sweep needs no second SELECT round-trip.

        Both identifiers (table name + timestamp column) are trusted
        module constants -- see ``fetch_stall_candidates`` for the
        identifier-interpolation rationale.
        """
        stmt = _sql_text(
            f"""
            SELECT inv.id::text AS id,
                   inv.{inv_timestamp_column} AS seen_ts
            FROM {investigations_table} inv
            WHERE inv.status = ANY(:running_values)
              AND inv.{inv_timestamp_column} < :cutoff
              AND NOT EXISTS (
                  SELECT 1
                  FROM taskrecord t
                  WHERE t.kwargs_json::jsonb->>'investigation_id'
                        = inv.id::text
                    AND t.status = ANY(:live_task_statuses)
              )
              AND NOT EXISTS (
                  SELECT 1
                  FROM workflow_state_cursor c
                  WHERE c.investigation_id = inv.id::text
                    AND c.current_state <> ALL(:non_resumable_states)
              )
            ORDER BY inv.{inv_timestamp_column} ASC
            LIMIT :lim
            """,
        ).bindparams(
            running_values=list(running_status_values),
            cutoff=cutoff,
            live_task_statuses=list(LIVE_TASK_STATUSES),
            non_resumable_states=list(NON_RESUMABLE_CURSOR_STATES),
            lim=limit,
        )
        async with async_session_scope() as session:
            return [
                (r["id"], r["seen_ts"])
                for r in (await session.execute(stmt)).mappings().all()
            ]

    # ---- Claim primitives ---------------------------------------------

    @staticmethod
    async def try_claim(
        *,
        inv_table: str,
        timestamp_column: str,
        inv_id: str,
        seen_timestamp: datetime,
    ) -> bool:
        """Compare-and-set on the row's timestamp column.

        Thin passthrough to
        :func:`aila.platform.services.recovery_claim.try_claim_recovery`
        so callers that reach the service surface do not also need a
        second import. The primitive itself is unchanged (issue #121
        mutual exclusion contract is preserved verbatim).
        """
        return await try_claim_recovery(
            inv_table=inv_table,
            timestamp_column=timestamp_column,
            inv_id=inv_id,
            seen_timestamp=seen_timestamp,
        )

    @staticmethod
    async def try_stalled_status_flip(
        *,
        investigations_table: str,
        inv_id: str,
    ) -> bool | None:
        """Atomic ``status='stalled' -> 'running'`` flip.

        Returns ``True`` when this caller flipped the row (owns the
        recovery), ``False`` when a concurrent racer beat us to the
        flip (skip this tick), and ``None`` on a transport-layer error
        (also skip -- the caller logs and continues). The
        ``WHERE status='stalled'`` clause matches at most one racer, so
        ``rowcount == 1`` is the winning-claim signal.

        Only relevant to :attr:`RecoveryStrategy.STALL_REENQUEUE` rows
        whose ``status='stalled'`` -- the stalled state needs its
        status flipped before the setup handler will accept a fresh
        submit, and the flip itself doubles as the mutual-exclusion
        claim for that path.
        """
        stmt = _sql_text(
            f"""
            UPDATE {investigations_table}
            SET status = 'running',
                updated_at = NOW()
            WHERE id = :inv_id
              AND status = 'stalled'
            """,
        ).bindparams(inv_id=inv_id)
        try:
            async with async_session_scope() as session:
                result = await session.execute(stmt)
                await session.commit()
        except (OSError, RuntimeError, SQLAlchemyError):
            _log.warning(
                "recovery_service: stalled->running flip failed inv=%s",
                inv_id, exc_info=True,
            )
            return None
        return bool(result.rowcount or 0)
