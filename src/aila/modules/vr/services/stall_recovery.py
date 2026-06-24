"""Periodic sweep that re-enqueues stalled VR investigations.

When a VR task gets killed mid-execution — ``CancelledError`` from
ARQ's ``max_job_time``, worker process restart, host kernel kill — no
exception handler runs, no cursor is written, no ``AUTO_CONTINUE``
fires. The investigation row stays at ``status='running'`` (or
``status='created'`` if the very first enqueue was lost) with branches
in ``status='active'`` forever, with zero in-flight tasks pointing at
it.

The cutover Phase B / C / engine fixes all assume the task body either
returns or raises through a normal ``Exception`` path. None handle
``CancelledError``, which inherits from ``BaseException`` (not
``Exception``) and is therefore not caught by the ``except Exception``
handlers around AUTO_CONTINUE. This sweep is the recovery backstop.

Companion to ``cursor_reaper.sweep_orphan_crashed_cursors`` (which
deletes orphan terminal cursors). That helper handles cleanup; this
one handles recovery.

Eligibility (every clause MUST hold):

* ``inv.status IN ('created', 'running')`` — only non-terminal
  investigations can recover.
* ``inv.pause_reason IS NULL`` — operator and self-paused
  investigations (``operator`` / ``low_confidence`` / ``cost_budget``
  / ``awaiting_campaign`` / ``awaiting_mcp``) are intentional waits
  and MUST NOT be auto-resumed by this sweep. M3.R-6 resumer owns
  the auto-resume cases; operator owns the operator case.
* ``inv.kind != 'masvs_audit'`` — the MASVS parent's lifecycle is
  owned by ``parent_reconciler``. The parent's child investigations
  are regular ``audit`` kind and ARE eligible.
* ``inv.updated_at < NOW() - <idle threshold>`` — slow turns
  (8-minute semantic searches, long reasoning) MUST not be double-
  fired. The threshold distinguishes "legitimately slow" from
  "really stalled".
* **No in-flight task** references this investigation. A row in
  ``taskrecord`` with status ``queued`` / ``running`` / ``waiting``
  whose ``kwargs_json::jsonb->>'investigation_id'`` equals this
  ``inv.id`` blocks re-enqueue. The worker's ``reaper.stale_in_
  progress_reconciled`` sweep will eventually flip dead-worker
  tasks to ``cancelled``; the next sweep tick after that picks
  them up.

Re-enqueue dispatch table:

* ``n_day`` → ``run_vr_nday(investigation_id=...)``. Single submit
  per inv; the nday task body manages its own internal branching.
* all other sweepable kinds (``audit`` / ``discovery`` /
  ``variant_hunt`` / ``triage``) → ``run_vr_investigate``. If the
  inv has any ``status='active'`` branches, fan out one submit
  per active branch with ``branch_id`` set. If no active branches
  exist (typically ``status='created'`` invs that never spawned),
  submit once with only ``investigation_id`` — the
  ``investigation_setup`` state will spawn branches on first turn.

Rate model:

``rate_per_tick`` caps **total task submits** in one sweep call —
NOT investigation count. The unit matters: one investigation with 6
active personas produces 6 submits, six 1-branch investigations also
produce 6. The cap is what bounds the downstream LLM request rate.

Default 6. Rationale: with ~4 vr workers and the LLM client doing
~1 request per turn, the steady-state LLM rate is roughly
``min(workers, submits-per-min) × calls-per-turn``. A burst of 6
new submits per tick keeps the sweep contribution comfortably under
NVIDIA NIM's 40 RPM free-tier ceiling, leaving headroom for non-
sweep traffic (operator-triggered new investigations, finalize and
synthesis tasks, etc.).

Operator tunes via env vars:

* ``AILA_VR_STALL_RECOVERY_LIMIT`` — submits per tick (default 6)
* ``AILA_VR_STALL_RECOVERY_IDLE_MIN`` — idle threshold in minutes
  (default 15)

``bypass_dedup=True`` on every submit so a stale running-status
``TaskRecord`` from a dead worker doesn't block the §72 partial
unique-hash index that would otherwise short-circuit recovery.

No re-enqueue counter cap: per operator decision, investigations
that keep stalling SHOULD keep getting re-enqueued. If an
investigation is permanently broken (e.g. infinite parse-failure
loop on a single turn), it will eventually accumulate enough
``status='failed'`` TaskRecord rows that the operator notices in
the worker log volume and intervenes.
"""
from __future__ import annotations

import logging
import os
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text as _sql_text

from aila.storage.database import async_session_scope

__all__ = [
    "StallRecoveryResult",
    "SubmitFn",
    "sweep_stalled_investigations",
]

_log = logging.getLogger(__name__)

# Default idle threshold (minutes). Slow turns shouldn't be mistaken
# as stalls; 15 minutes is wider than any legitimate turn timing
# observed in worker logs.
_DEFAULT_IDLE_MIN = 15

# Default task submits per sweep tick. Calibrated so one full
# 6-persona investigation's branch fan-out fits in a single tick,
# but never enough to risk overrunning a 40 RPM LLM provider's
# steady-state budget. Operator tunes via
# ``AILA_VR_STALL_RECOVERY_LIMIT``.
_DEFAULT_RATE_PER_TICK = 6

# Kinds the sweep handles. ``masvs_audit`` is intentionally absent:
# parent_reconciler owns its lifecycle. The parent's child
# investigations are regular ``audit`` kind and ARE handled here.
_SWEEPABLE_KINDS: tuple[str, ...] = (
    "audit", "discovery", "variant_hunt", "triage", "n_day",
)

# Reserved sentinel for "no branch_id, inv-level enqueue" path. Used
# in the per-row result accounting only — never sent to the queue.
_INV_LEVEL = "__inv_level__"


@dataclass
class StallRecoveryResult:
    """Outcome of one sweep call."""

    examined: int = 0
    """Investigation rows that matched eligibility (before branch
    fan-out)."""

    enqueued: int = 0
    """Number of ``task_queue.submit`` calls actually performed."""

    skipped_rate_cap: int = 0
    """Eligible rows whose entire branch fan-out would push us over
    the rate cap. Counted at row granularity (not branch); informs
    operator how much backlog remains."""

    by_kind_enqueued: dict[str, int] = field(default_factory=dict)
    """Per-kind count of submits."""

    investigations_recovered: list[str] = field(default_factory=list)
    """Investigation IDs that produced at least one submit this tick."""


# Mock-friendly type for tests. Args: (kind, inv_id, branch_id_or_None,
# team_id_or_None). Returns the submitted task_id (unused, but ARQ
# signature compatibility).
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


async def _default_submit_fn(
    inv_kind: str,
    inv_id: str,
    branch_id: str | None,
    team_id: str | None,
) -> None:
    """Production submitter — binds to ``default_task_queue``.

    Deferred imports because this module sits in the worker boot
    path; we MUST not pull the task queue / module loader surface
    during the recovery-sweep import.
    """
    from aila.modules.vr._task_queue import default_task_queue
    from aila.modules.vr.workflow.task import (
        run_vr_investigate,
        run_vr_nday,
    )

    fn: Any
    kwargs: dict[str, object]
    if inv_kind == "n_day":
        fn = run_vr_nday
        # nday entry takes investigation_id only; the task body owns
        # its own branch lifecycle internally.
        kwargs = {"investigation_id": inv_id}
    else:
        fn = run_vr_investigate
        kwargs = {"investigation_id": inv_id}
        if branch_id:
            kwargs["branch_id"] = branch_id

    task_queue = default_task_queue()
    await task_queue.submit(
        track="vr",
        fn=fn,
        kwargs=kwargs,
        user_id="system",
        group_id="vr_stall_recovery",
        team_id=team_id,
        # Without this flag, the dedup query matches either:
        #  (a) the killed task's stale running-status row whose
        #      reaper hasn't fired yet, OR
        #  (b) any other recovery attempt in the same tick that
        #      happens to share kwargs.
        # bypass_dedup mixes a uuid into the hash input so neither
        # collision fires.
        bypass_dedup=True,
    )


async def _fetch_eligible(
    *,
    cutoff: datetime,
    over_fetch: int,
) -> list[dict[str, Any]]:
    """Single eligibility SELECT against the configured DB."""
    stmt = _sql_text(
        """
        SELECT inv.id::text AS id,
               inv.kind AS kind,
               inv.status AS status,
               inv.team_id::text AS team_id,
               inv.updated_at AS updated_at
        FROM vr_investigations inv
        WHERE inv.status IN ('created', 'running')
          AND inv.pause_reason IS NULL
          AND inv.kind = ANY(:kinds)
          AND inv.updated_at < :cutoff
          AND NOT EXISTS (
              SELECT 1
              FROM taskrecord t
              WHERE t.kwargs_json::jsonb->>'investigation_id'
                    = inv.id::text
                AND t.status IN ('queued', 'running', 'waiting')
          )
        ORDER BY inv.updated_at ASC
        LIMIT :limit
        """,
    ).bindparams(
        kinds=list(_SWEEPABLE_KINDS),
        cutoff=cutoff,
        limit=over_fetch,
    )
    async with async_session_scope() as session:
        return [
            dict(r) for r in
            (await session.execute(stmt)).mappings().all()
        ]


async def _fetch_active_branches(inv_id: str) -> list[str]:
    """Return active-branch ids for an investigation."""
    stmt = _sql_text(
        """
        SELECT id::text AS id
        FROM vr_investigation_branches
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
    idle_minutes: int | None = None,
    rate_per_tick: int | None = None,
    submit_fn: SubmitFn | None = None,
) -> StallRecoveryResult:
    """Re-enqueue investigations that have stalled without progress.

    Args:
        idle_minutes: how long an investigation must have gone without
            ``updated_at`` change before it's considered stalled. None
            reads ``AILA_VR_STALL_RECOVERY_IDLE_MIN`` (default 15).
        rate_per_tick: max TASK SUBMITS per call (NOT investigations).
            None reads ``AILA_VR_STALL_RECOVERY_LIMIT`` (default 6).
        submit_fn: injected for tests. Production passes None and the
            sweep binds to ``default_task_queue().submit`` via
            ``_default_submit_fn``.

    Returns:
        ``StallRecoveryResult`` summarizing the tick.
    """
    idle = idle_minutes if idle_minutes is not None else _env_int(
        "AILA_VR_STALL_RECOVERY_IDLE_MIN", _DEFAULT_IDLE_MIN,
    )
    cap = rate_per_tick if rate_per_tick is not None else _env_int(
        "AILA_VR_STALL_RECOVERY_LIMIT", _DEFAULT_RATE_PER_TICK,
    )
    submit = submit_fn if submit_fn is not None else _default_submit_fn

    if cap <= 0:
        # Defensive: misconfigured env. Log and no-op.
        _log.warning("stall_recovery: rate_per_tick=%d <= 0; skipping tick", cap)
        return StallRecoveryResult()

    cutoff = datetime.now(UTC) - timedelta(minutes=idle)
    result = StallRecoveryResult()

    # Over-fetch eligible rows so the loop has enough headroom when
    # some rows turn out to have zero active branches (creates 1
    # submit each, not the per-row average). Capped at 50 to keep
    # the SELECT bounded under unusual backlog conditions.
    eligible = await _fetch_eligible(
        cutoff=cutoff,
        over_fetch=max(cap * 3, 30),
    )
    result.examined = len(eligible)

    for row in eligible:
        if result.enqueued >= cap:
            # Per-investigation skip count (not per-branch). One inv
            # that would have produced 6 submits still counts as 1.
            result.skipped_rate_cap += 1
            continue

        inv_id = row["id"]
        inv_kind = row["kind"]
        team_id = row["team_id"]

        if inv_kind == "n_day":
            # Single inv-level submit; nday handles its own branches.
            await _safe_submit(
                submit, inv_kind, inv_id, None, team_id, result,
            )
            continue

        branches = await _fetch_active_branches(inv_id)
        if not branches:
            # status=created investigations that never spawned, OR
            # status=running investigations whose every branch
            # terminated but the inv-level rollup didn't fire.
            # Either way the inv-level submit lets the setup state
            # re-evaluate.
            await _safe_submit(
                submit, inv_kind, inv_id, None, team_id, result,
            )
            continue

        # Fan out one submit per active branch. STOP at the cap mid-
        # fan-out — partial recovery is fine; next tick continues.
        for branch_id in branches:
            if result.enqueued >= cap:
                break
            await _safe_submit(
                submit, inv_kind, inv_id, branch_id, team_id, result,
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
    """Wrap submit_fn with narrow-exception logging.

    A submit failure (Redis blip, ARQ serialization, dedup race) MUST
    NOT abort the sweep. Log, increment failure visibility, continue.
    """
    try:
        await submit(inv_kind, inv_id, branch_id, team_id)
    except (OSError, TimeoutError, RuntimeError, ValueError) as exc:
        _log.warning(
            "stall_recovery: submit failed inv=%s kind=%s branch=%s "
            "err=%s",
            inv_id, inv_kind, branch_id or _INV_LEVEL, exc,
        )
        return
    result.enqueued += 1
    result.by_kind_enqueued[inv_kind] = (
        result.by_kind_enqueued.get(inv_kind, 0) + 1
    )
    if inv_id not in result.investigations_recovered:
        result.investigations_recovered.append(inv_id)
