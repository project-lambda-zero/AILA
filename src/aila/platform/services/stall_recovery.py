"""Back-compat wrapper for the STALL_REENQUEUE recovery strategy.

The eligibility SELECT, per-row classification, atomic claim, and
rate-limited fan-out submit now live on the unified
:class:`aila.platform.services.recovery_service.PlatformRecoveryService`
(:meth:`PlatformRecoveryService.recover` +
:meth:`PlatformRecoveryService.sweep`). This module keeps
:func:`sweep_stalled_investigations` importable with its pre-lift
signature so module bindings and tests that already import it continue
to work unchanged; the body is a thin wrapper that constructs a
:class:`RecoveryBinding` populated with only the STALL branch and calls
the unified sweep filtered to :attr:`RecoveryStrategy.STALL_REENQUEUE`.

Guarantees preserved verbatim (see the unified service docstring for
the full rationale):

* Idle threshold + rate cap resolve through ``<env_prefix>_IDLE_MIN`` /
  ``<env_prefix>_LIMIT`` with the same defaults (15 minutes / 6 submits
  per tick).
* ``status='stalled'`` rows: atomic ``stalled -> running`` flip is both
  the operational fix AND the mutual-exclusion claim.
* Non-stalled eligible rows: compare-and-set on ``updated_at`` is the
  claim (issue #121 double-submit race stays neutralized via
  :func:`try_claim_recovery`).
* Fan-out is capped at the total ``rate_per_tick`` submit count, with a
  mid-fan-out break when the remaining budget is exhausted.
* ``skipped_rate_cap`` counts investigations (not branches) whose fan-
  out was cut short.
* ``bypass_dedup=True`` on the module submitter mixes a uuid into the
  dedup hash input so a killed-but-not-purged task row does not swallow
  the recovery submit.

Context (unchanged from the pre-lift module docstring):

When a task gets killed mid-execution -- ``CancelledError`` from ARQ's
``max_job_time``, worker process restart, host kernel kill -- no
exception handler runs, no cursor is written, no ``AUTO_CONTINUE``
fires. The investigation row stays at ``status='running'`` (or
``status='created'`` if the very first enqueue was lost) with branches
in ``status='active'`` forever, with zero in-flight tasks pointing at
it. Every other cutover fix assumes the task body returns or raises
through ``Exception``; a sequence of ``CancelledError`` (inherits from
``BaseException``, escapes broad ``except Exception`` handlers) is the
recovery gap this sweep closes.
"""
from __future__ import annotations

import logging

from aila.platform.services.recovery_service import (
    DEFAULT_STALL_IDLE_MIN as _DEFAULT_IDLE_MIN,
)
from aila.platform.services.recovery_service import (
    DEFAULT_STALL_RATE_PER_TICK as _DEFAULT_RATE_PER_TICK,
)
from aila.platform.services.recovery_service import (
    PlatformRecoveryService,
    RecoveryBinding,
    RecoveryStrategy,
    StallBinding,
    StallRecoveryResult,
    SubmitFn,
)

__all__ = [
    "StallRecoveryResult",
    "SubmitFn",
    "sweep_stalled_investigations",
]

_log = logging.getLogger(__name__)

# Kept for back-compat with any external import of the pre-lift defaults.
_ = _DEFAULT_IDLE_MIN, _DEFAULT_RATE_PER_TICK


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

    Thin back-compat wrapper -- see the module docstring and the unified
    :meth:`PlatformRecoveryService.sweep` for the full contract. Every
    kwarg is pre-lift compatible; the wrapper folds them into a
    :class:`RecoveryBinding` populated with only the STALL branch and
    calls the unified sweep filtered to
    :attr:`RecoveryStrategy.STALL_REENQUEUE`.

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
        ``StallRecoveryResult`` summarizing the tick (identical shape
        to the pre-lift return value).
    """
    binding = RecoveryBinding(
        investigations_table=investigations_table,
        stall=StallBinding(
            submit_fn=submit_fn,
            sweepable_kinds=sweepable_kinds,
            single_submit_kinds=single_submit_kinds,
            env_prefix=env_prefix,
            branches_table=branches_table,
            idle_minutes=idle_minutes,
            rate_per_tick=rate_per_tick,
        ),
        stuck=None,
    )
    result = await PlatformRecoveryService.sweep(
        binding=binding,
        only_strategy=RecoveryStrategy.STALL_REENQUEUE,
    )
    return result.stall
