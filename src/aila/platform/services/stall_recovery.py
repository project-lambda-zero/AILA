"""Generic periodic sweep that re-enqueues stalled investigations.

Module bindings supply the eligibility SQL identifiers (table names for
the investigations + branches), the sweepable-kind set, the env-var
prefix that tunes rate/idle threshold, and the concrete submitter that
knows how to enqueue a task for that module. See ``branch_reaper`` for
the same pattern applied to the orphan-branch reaper: each module
wraps this callable via a module-level ``functools.partial`` so the
callable identity is stable across imports (the periodic-sweep
registry keys re-registration on identity, so an inline partial at
the registration site would break the re-registration no-op).

Context (unchanged from the pre-lift module docstrings):

When a task gets killed mid-execution -- ``CancelledError`` from ARQ's
``max_job_time``, worker process restart, host kernel kill -- no
exception handler runs, no cursor is written, no ``AUTO_CONTINUE``
fires. The investigation row stays at ``status='running'`` (or
``status='created'`` if the very first enqueue was lost) with
branches in ``status='active'`` forever, with zero in-flight tasks
pointing at it. Every other cutover fix assumes the task body
returns or raises through ``Exception``; a sequence of
``CancelledError`` (inherits from ``BaseException``, escapes broad
``except Exception`` handlers) is the recovery gap this sweep closes.

Eligibility, dispatch, rate model
---------------------------------

Eligibility lives on the unified
:class:`aila.platform.services.recovery_service.PlatformRecoveryService`
(:meth:`PlatformRecoveryService.fetch_stall_candidates`) alongside the
sibling stuck-healer SELECT. This module orchestrates the STALLED /
CREATED / RUNNING recovery path documented in
:class:`aila.platform.services.recovery_service.RecoveryStrategy`
(``STALL_REENQUEUE``).

Re-enqueue dispatch:

* ``inv.kind`` in ``single_submit_kinds`` -> single inv-level submit,
  no branch fan-out. Used by module kinds that own their own branch
  lifecycle internally (VR's ``n_day``); the caller's submitter
  routes these to the appropriate task function.
* everything else -> if the inv has ``status='active'`` branches, fan
  out one submit per branch with ``branch_id`` set; otherwise submit
  once with only ``investigation_id`` (``investigation_setup`` will
  spawn branches on first turn).

Rate model:

``rate_per_tick`` caps **total task submits** in one sweep call --
NOT investigation count. The unit matters: one investigation with 6
active personas produces 6 submits; six 1-branch investigations also
produce 6. The cap is what bounds the downstream LLM request rate.
Default 6.

Operator tunes via env vars derived from ``env_prefix``:

* ``<PREFIX>_LIMIT`` -- submits per tick (default 6)
* ``<PREFIX>_IDLE_MIN`` -- idle threshold in minutes (default 15)
"""
from __future__ import annotations

import logging
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import text as _sql_text
from sqlalchemy.exc import SQLAlchemyError

from aila.platform.services.recovery_service import (
    PlatformRecoveryService,
    RecoveryStrategy,
)
from aila.storage.database import async_session_scope

__all__ = [
    "StallRecoveryResult",
    "SubmitFn",
    "sweep_stalled_investigations",
]

_log = logging.getLogger(__name__)

# Default idle threshold (minutes). Slow turns shouldn't be mistaken as
# stalls; 15 minutes is wider than any legitimate turn timing observed
# in worker logs.
_DEFAULT_IDLE_MIN = 15

# Default task submits per sweep tick. Calibrated so one full
# 6-persona investigation's branch fan-out fits in a single tick, but
# never enough to risk overrunning a 40 RPM LLM provider's steady-
# state budget. Operator tunes via ``<PREFIX>_LIMIT``.
_DEFAULT_RATE_PER_TICK = 6

# Reserved sentinel for "no branch_id, inv-level enqueue" path. Used
# in the per-row result accounting only -- never sent to the queue.
_INV_LEVEL = "__inv_level__"


@dataclass
class StallRecoveryResult:
    """Outcome of one sweep call."""

    examined: int = 0
    """Investigation rows that matched eligibility (before branch fan-out)."""

    enqueued: int = 0
    """Number of ``task_queue.submit`` calls actually performed."""

    skipped_rate_cap: int = 0
    """Eligible rows whose entire branch fan-out would push us over the
    rate cap. Counted at row granularity (not branch); informs operator
    how much backlog remains."""

    by_kind_enqueued: dict[str, int] = field(default_factory=dict)
    """Per-kind count of submits."""

    investigations_recovered: list[str] = field(default_factory=list)
    """Investigation IDs that produced at least one submit this tick."""


# Mock-friendly type for tests. Args: (kind, inv_id, branch_id_or_None,
# team_id_or_None). Returns None (submitted task_id is unused, but the
# type keeps ARQ signature compatibility).
SubmitFn = Callable[
    [str, str, str | None, str | None],
    Awaitable[None],
]


def _env_int(key: str, default: int) -> int:
    raw = os.environ.get(key)
    if raw is None or raw == "":
        return default
    try:
        return int(raw)
    except ValueError:
        _log.warning(
            "stall_recovery: %s is not an int (%r), using default=%d",
            key, raw, default,
        )
        return default


async def _fetch_active_branches(
    *,
    branches_table: str,
    inv_id: str,
) -> list[str]:
    """Return active-branch ids for an investigation."""
    stmt = _sql_text(
        f"""
        SELECT id::text AS id
        FROM {branches_table}
        WHERE investigation_id = :inv
          AND status = 'active'
        ORDER BY created_at
        """,
    ).bindparams(inv=inv_id)
    async with async_session_scope() as session:
        return [
            r["id"]
            for r in (await session.execute(stmt)).mappings().all()
        ]


async def sweep_stalled_investigations(
    *,
    submit_fn: SubmitFn,
    sweepable_kinds: tuple[str, ...],
    single_submit_kinds: tuple[str, ...],
    env_prefix: str,
    investigations_table: str,
    branches_table: str,
    idle_minutes: int | None = None,
    rate_per_tick: int | None = None,
) -> StallRecoveryResult:
    """Re-enqueue investigations that have stalled without progress.

    See the module docstring for the eligibility, dispatch, and
    rate-model contracts. Module bindings wrap this callable via
    ``functools.partial`` with the binding args pre-supplied; callers
    see the same public signature as the pre-lift module files
    (``idle_minutes``, ``rate_per_tick``, ``submit_fn``) plus the
    ability for tests to override the bound submitter.

    Eligibility + strategy classification delegate to
    :class:`aila.platform.services.recovery_service.PlatformRecoveryService`;
    the loop body owns only the STALL_REENQUEUE-specific dispatch (the
    ``stalled -> running`` atomic flip, the non-stalled timestamp claim,
    and the branch fan-out).

    Args:
        submit_fn: module-provided task submitter. Called for each
            re-enqueue. Bound at module level via ``functools.partial``;
            tests override with a capture-style mock.
        sweepable_kinds: kinds the sweep handles. Rows whose kind is
            not in this tuple are ignored at the SQL level.
        single_submit_kinds: subset of ``sweepable_kinds`` that own
            their own branch lifecycle. Rows with these kinds get one
            inv-level submit; no branch fan-out. Empty tuple for
            modules with no such kinds.
        env_prefix: env-var prefix. ``<PREFIX>_LIMIT`` overrides
            ``rate_per_tick``; ``<PREFIX>_IDLE_MIN`` overrides
            ``idle_minutes``.
        investigations_table: SQL identifier for the module's
            investigations table (trusted constant, not user input).
        branches_table: SQL identifier for the module's investigation
            branches table (trusted constant, not user input).
        idle_minutes: how long an investigation must have gone without
            ``updated_at`` change before it's considered stalled. None
            reads ``<env_prefix>_IDLE_MIN`` (default 15).
        rate_per_tick: max TASK SUBMITS per call (NOT investigations).
            None reads ``<env_prefix>_LIMIT`` (default 6).

    Returns:
        ``StallRecoveryResult`` summarizing the tick.
    """
    idle = idle_minutes if idle_minutes is not None else _env_int(
        f"{env_prefix}_IDLE_MIN", _DEFAULT_IDLE_MIN,
    )
    cap = rate_per_tick if rate_per_tick is not None else _env_int(
        f"{env_prefix}_LIMIT", _DEFAULT_RATE_PER_TICK,
    )

    if cap <= 0:
        # Defensive: misconfigured env. Log and no-op.
        _log.warning("stall_recovery: rate_per_tick=%d <= 0; skipping tick", cap)
        return StallRecoveryResult()

    cutoff = datetime.now(UTC) - timedelta(minutes=idle)
    result = StallRecoveryResult()

    # Over-fetch eligible rows so the loop has enough headroom when
    # some rows turn out to have zero active branches (creates 1
    # submit each, not the per-row average). Capped at ``max(cap*3, 30)``
    # to keep the SELECT bounded under unusual backlog conditions.
    try:
        eligible = await PlatformRecoveryService.fetch_stall_candidates(
            investigations_table=investigations_table,
            sweepable_kinds=sweepable_kinds,
            cutoff=cutoff,
            limit=max(cap * 3, 30),
        )
    except SQLAlchemyError as exc:
        _log.warning(
            "stall_recovery: eligibility SELECT failed: %s", exc,
        )
        return result
    result.examined = len(eligible)

    for row in eligible:
        if result.enqueued >= cap:
            # Per-investigation skip count (not per-branch). One inv
            # that would have produced 6 submits still counts as 1.
            result.skipped_rate_cap += 1
            continue

        inv_id = row["id"]
        inv_kind = row["kind"]
        inv_status = row.get("status", "running")
        team_id = row["team_id"]
        seen_updated_at = row["updated_at"]

        # Sanity: the SELECT already applied the sweepable-kind and
        # status filters, but the classifier is where the unified
        # eligibility contract lives -- run it so a future SELECT edit
        # cannot silently diverge from the platform decision. Cursor
        # state is not consulted at the SELECT level for this path;
        # ``has_resumable_cursor`` is treated as True (the classifier
        # then routes running-with-cursor rows to STALL_REENQUEUE
        # rather than STUCK_HEAL, matching pre-lift behavior). The
        # stuck-healer sweep owns the narrower cursor-absent zombie.
        strategy = PlatformRecoveryService.classify(
            status=inv_status,
            has_live_task=False,
            has_resumable_cursor=True,
        )
        if strategy is not RecoveryStrategy.STALL_REENQUEUE:
            continue

        # Issue #121: shared mutual exclusion with stuck_healer (and
        # cross-process cron ticks). Both sweeps can independently
        # match the same investigation in one tick and would submit
        # twice without a claim. The claim is either the atomic
        # ``status = 'stalled' -> 'running'`` flip below (whose
        # ``WHERE status='stalled'`` clause matches at most one racer,
        # so rowcount == 1 means we won) or, for non-stalled rows, a
        # compare-and-set on ``updated_at`` via
        # :meth:`PlatformRecoveryService.try_claim`. The losing
        # racer's UPDATE affects zero rows and the loop skips its
        # submit for this tick.
        if inv_status == "stalled":
            # Stalled investigations need their status flipped back to
            # running before the workflow setup handler will accept
            # them. The replan ledger entries are superseded by
            # reenqueue_investigation (called by the API); here we do
            # the minimal direct flip so the setup handler re-spawns
            # branches. The flip itself is the recovery claim (see
            # above).
            flip = await PlatformRecoveryService.try_stalled_status_flip(
                investigations_table=investigations_table,
                inv_id=inv_id,
            )
            if flip is None:
                # Transport error -- service logs; skip this row.
                continue
            if not flip:
                # Another sweep (this process or another worker) beat
                # us to the atomic flip. The winner owns the submit.
                _log.info(
                    "stall_recovery: inv=%s stalled->running flip lost "
                    "to concurrent claim; skipping",
                    inv_id,
                )
                continue
            _log.info(
                "stall_recovery: flipped stalled->running inv=%s",
                inv_id,
            )
        else:
            # Non-stalled eligible row: bump updated_at as the claim.
            # Compare-and-set on ``updated_at = seen_updated_at`` so
            # racers observing the same SELECT window converge on
            # exactly one winner.
            if not await PlatformRecoveryService.try_claim(
                inv_table=investigations_table,
                timestamp_column="updated_at",
                inv_id=inv_id,
                seen_timestamp=seen_updated_at,
            ):
                _log.info(
                    "stall_recovery: inv=%s lost claim to concurrent "
                    "recovery sweep; skipping",
                    inv_id,
                )
                continue

        if inv_kind in single_submit_kinds:
            # Single inv-level submit; the submitter routes this kind
            # to a task body that owns its own branch lifecycle.
            await _safe_submit(
                submit_fn, inv_kind, inv_id, None, team_id, result,
            )
            continue

        branches = await _fetch_active_branches(
            branches_table=branches_table, inv_id=inv_id,
        )
        if not branches:
            # status=created investigations that never spawned, OR
            # status=running investigations whose every branch
            # terminated but the inv-level rollup didn't fire.
            # Either way the inv-level submit lets the setup state
            # re-evaluate.
            await _safe_submit(
                submit_fn, inv_kind, inv_id, None, team_id, result,
            )
            continue

        # Fan out one submit per active branch. STOP at the cap mid-
        # fan-out -- partial recovery is fine; next tick continues.
        for branch_id in branches:
            if result.enqueued >= cap:
                break
            await _safe_submit(
                submit_fn, inv_kind, inv_id, branch_id, team_id, result,
            )

    if result.enqueued or result.skipped_rate_cap:
        _log.info(
            "stall_recovery: examined=%d enqueued=%d skipped_rate_cap=%d "
            "by_kind=%s recovered=%d",
            result.examined, result.enqueued, result.skipped_rate_cap,
            dict(result.by_kind_enqueued),
            len(result.investigations_recovered),
        )

    return result


async def _safe_submit(
    submit: SubmitFn,
    inv_kind: str,
    inv_id: str,
    branch_id: str | None,
    team_id: str | None,
    result: StallRecoveryResult,
) -> None:
    """Wrap ``submit_fn`` with narrow-exception logging.

    A submit failure (Redis blip, ARQ serialization, dedup race) MUST
    NOT abort the sweep. Log, increment failure visibility, continue.
    """
    try:
        await submit(inv_kind, inv_id, branch_id, team_id)
    except (OSError, TimeoutError, RuntimeError, ValueError) as exc:
        _log.warning(
            "stall_recovery: submit failed inv=%s kind=%s branch=%s err=%s",
            inv_id, inv_kind, branch_id or _INV_LEVEL, exc,
        )
        return
    result.enqueued += 1
    result.by_kind_enqueued[inv_kind] = (
        result.by_kind_enqueued.get(inv_kind, 0) + 1
    )
    if inv_id not in result.investigations_recovered:
        result.investigations_recovered.append(inv_id)
