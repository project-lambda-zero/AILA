"""Generic periodic-sweep registry for the platform reaper cron.

Modules register their per-tick maintenance sweeps via
:func:`register_periodic_sweep`. The platform worker's reaper block
(``_run_reaper_block``) iterates this registry on every cron tick -- the
worker has no awareness of which modules own which sweeps. This closes
the layering violation where ``aila.platform.tasks.worker`` used to
hardcode imports from ``aila.modules.vr.*``.

Contract:

* Sweep name is a unique string, conventionally ``"<module>.<sweep>"``
  (e.g. ``"vr.stage_tracker"``). Names appear in operator-facing log
  messages so the convention helps the operator correlate a failing
  sweep to its module.
* Sweep callable is an async no-arg function returning anything
  JSON-loggable. The worker logs the result at INFO when truthy.
* Sweep failures are swallowed by the worker per the existing
  best-effort cron policy (``_run_reaper_block`` catches
  :class:`Exception` per sweep). Each sweep is responsible for its
  own retry / counter / alert escalation.

Registration is module-load-time. Each module's top-level
``__init__.py`` (or ``module.py`` factory) calls
:func:`register_periodic_sweep` for every sweep it owns. The registry
is process-local; ARQ workers and FastAPI processes each populate it
via the same import side-effect.

Ordering
--------

Insertion order alone is not enough: sweeps register from three
independent module ``create_module()`` factories, so the order they
appear in ``_PERIODIC_SWEEPS`` depends on which module was imported
first. That is not a contract we can rely on. In particular, the
cap-exceeded stage reaper (``*.stage_tracker``) MUST run BEFORE the
no-finding finalize sweep (``*.finalize``) so finalize does not
synthesize an outcome for an investigation whose stages the reaper
would have flipped to FAILED in the same tick.

:func:`register_periodic_sweep` accepts a keyword-only ``order`` int
declaring the sweep's category. :class:`SweepPriority` names the
seven canonical bins in the RFC #208 recovery pipeline. Ties break
on insertion index, so the default value (``SweepPriority.DEFAULT``)
preserves the pre-existing insertion-order behavior for any caller
that does not upgrade.

Deregistration is intentionally not exposed: sweeps are static
declarations, not runtime state. Tests that need to isolate one
sweep should monkeypatch :data:`_PERIODIC_SWEEPS` directly.
"""
from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from enum import IntEnum
from typing import Any

__all__ = [
    "PeriodicSweep",
    "SweepPriority",
    "all_periodic_sweeps",
    "register_periodic_sweep",
    "run_periodic_sweeps",
]


PeriodicSweep = Callable[[], Awaitable[Any]]


class SweepPriority(IntEnum):
    """Canonical priority bins for the RFC #208 recovery pipeline.

    The categories run in the order the reaper actually needs them:

    1. :attr:`CAP_EXCEEDED_REAPER` -- stage-level cap / timeout reaper.
       Runs first so a stuck stage flips to FAILED before finalize
       inspects the investigation.
    2. :attr:`STALE_BRANCH_ABANDONMENT` -- parent-state reconciler that
       abandons batches whose children are all done.
    3. :attr:`ORPHAN_BRANCH_REAPER` -- flips orphan ACTIVE branches
       whose parent investigation is already terminal.
    4. :attr:`NO_FINDING_SYNTHESIS` -- Phase C finalize chokepoint.
       Depends on (1)-(3) having converged branch / stage state.
    5. :attr:`STALL_RECOVERY` -- rate-limited re-enqueue backstop.
    6. :attr:`STUCK_HEALER` -- narrow "RUNNING with no live task AND
       no cursor" zombie healer, sibling of stall recovery.
    7. :attr:`CURSOR_REAPER` -- reserved for the terminal-cursor
       cleanup step. Currently lives in ``worker.py`` outside the
       registry; this constant is defined for parity so a future
       migration into the registry keeps the ordering intact.
    8. :attr:`RECONCILE` -- the investigation-scoped reconciler
       authority pass (RFC-07 reconcile wave, L3.4). Runs AFTER
       stall(500) / stuck(600) as the LAST-RESORT convergence step: it
       reconciles every task + cursor of each non-terminal, non-paused
       investigation and drives recovery (same-job-id resume or full
       re-enqueue) when the row is dead, so no path can leave an
       investigation RUNNING-with-nothing-enqueued even when every
       earlier sweep's eligibility window missed it.

    :attr:`DEFAULT` (500) is what an unclassified registration lands
    on. It ties numerically with :attr:`STALL_RECOVERY`; the
    insertion-index tiebreaker in :func:`all_periodic_sweeps` then
    preserves the order the sweep was registered relative to its
    peers, which is the pre-existing contract.
    """

    CAP_EXCEEDED_REAPER = 100
    STALE_BRANCH_ABANDONMENT = 200
    ORPHAN_BRANCH_REAPER = 300
    NO_FINDING_SYNTHESIS = 400
    STALL_RECOVERY = 500
    STUCK_HEALER = 600
    CURSOR_REAPER = 700
    RECONCILE = 800
    DEFAULT = 500


# Internal row: (order, insertion_index, sweep). The insertion index
# is assigned monotonically at registration time and used as the
# secondary sort key so ties on ``order`` fall back to registration
# order -- matching the pre-ordering contract.
_PERIODIC_SWEEPS: dict[str, tuple[int, int, PeriodicSweep]] = {}
_NEXT_INSERTION_INDEX = 0

_log = logging.getLogger(__name__)


def register_periodic_sweep(
    name: str,
    sweep: PeriodicSweep,
    *,
    order: int = SweepPriority.DEFAULT,
) -> None:
    """Register a periodic sweep under ``name`` at priority ``order``.

    Lower ``order`` runs first on each cron tick. Callers should
    prefer a :class:`SweepPriority` member so the recovery pipeline
    stays legible; a raw int is accepted for on-demand tests and
    for slotting between the canonical bins.

    Re-registering the SAME callable under the SAME name is idempotent
    (a no-op): a module's ``__init__.py`` running twice in a test
    fixture, or the same module reached through two import paths, is
    benign and must not crash import-time registration. An idempotent
    re-registration MAY pass a different ``order``; the recorded row
    is left unchanged (the first declared priority wins, matching how
    a "same callable" re-register is a no-op in every other respect).
    Registering a DIFFERENT callable under a name already in use is a
    genuine collision and raises :class:`ValueError`.
    """
    global _NEXT_INSERTION_INDEX

    if not name:
        raise ValueError(
            f"register_periodic_sweep: name must be a non-empty string, got {name!r}",
        )
    if not callable(sweep):
        raise ValueError(
            f"register_periodic_sweep: sweep for {name!r} must be callable, "
            f"got {type(sweep).__name__}",
        )
    existing = _PERIODIC_SWEEPS.get(name)
    if existing is not None:
        if existing[2] is sweep:
            return
        raise ValueError(
            f"register_periodic_sweep: name {name!r} already registered to a "
            f"different callable {existing[2]!r}; a name collision across sweeps is a bug",
        )
    _PERIODIC_SWEEPS[name] = (int(order), _NEXT_INSERTION_INDEX, sweep)
    _NEXT_INSERTION_INDEX += 1


def all_periodic_sweeps() -> dict[str, PeriodicSweep]:
    """Return the registered sweeps sorted by (order, insertion_index).

    Lower ``order`` first; ties break on registration order so
    callers that never declare an ``order`` get the pre-existing
    insertion-order behavior. Callers iterate the returned dict; the
    platform reaper block must NOT mutate ``_PERIODIC_SWEEPS``
    directly so a fresh sorted dict is handed out each call.
    """
    ordered = sorted(
        _PERIODIC_SWEEPS.items(),
        key=lambda item: (item[1][0], item[1][1]),
    )
    return {name: row[2] for name, row in ordered}


async def run_periodic_sweeps(
    *,
    logger: logging.Logger | None = None,
) -> dict[str, Any]:
    """Run every registered sweep in priority order with failure isolation.

    Each sweep gets its own ``try/except`` so one raising sweep does
    not abort the rest of the tick. This mirrors the pattern
    ``aila.platform.tasks.worker._run_reaper_block`` open-codes for
    the ARQ cron entry and is exposed here as the canonical runner
    for on-demand callers and tests. The worker's inline loop and
    this helper are behavior-equivalent; both preserve the
    single-transaction-per-sweep boundary (each sweep opens and
    commits its own session inside its callable).

    Returns a ``{name: result_or_exception}`` map -- truthy results
    for sweeps that reported work, and the raised :class:`Exception`
    instance for sweeps that failed. Callers may use this for
    structured logging; the worker's inline loop currently just
    logs and discards.
    """
    log = logger or _log
    results: dict[str, Any] = {}
    for name, sweep_fn in all_periodic_sweeps().items():
        try:
            result = await sweep_fn()
        except Exception as exc:
            log.warning("reaper.%s: failed: %s", name, exc, exc_info=True)
            results[name] = exc
            continue
        if result:
            log.info("reaper.%s: %s", name, result)
        results[name] = result
    return results
