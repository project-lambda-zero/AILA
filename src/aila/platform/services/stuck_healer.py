"""Back-compat wrapper for the STUCK_HEAL recovery strategy (RFC-07 #31).

The eligibility SELECT, per-row classification, atomic claim, full
:func:`reenqueue_investigation` reset, and durable
``kind='recovery'`` ledger event now live on the unified
:class:`aila.platform.services.recovery_service.PlatformRecoveryService`
(:meth:`PlatformRecoveryService.recover` +
:meth:`PlatformRecoveryService.sweep`). This module keeps
:func:`sweep_stuck_investigations` importable with its pre-lift
signature so module bindings and tests that already import it continue
to work unchanged; the body is a thin wrapper that constructs a
:class:`RecoveryBinding` populated with only the STUCK branch and calls
the unified sweep filtered to :attr:`RecoveryStrategy.STUCK_HEAL`.

Guarantees preserved verbatim (see the unified service docstring for
the full rationale):

* Idle grace + per-tick cap resolve through :class:`ModuleConfigReader`
  under the ``<module_id>`` namespace on the well-known keys
  :data:`CONFIG_KEY_IDLE_GRACE_S` +
  :data:`CONFIG_KEY_MAX_HEALS_PER_TICK` (defaults 600 seconds /
  5 heals per tick).
* Timestamp compare-and-set claim (issue #121 mutual exclusion).
* Full :func:`reenqueue_investigation` four-source-of-truth reset:
  cancel stale ``taskrecord`` rows, wipe ``__crashed__``
  ``workflow_state_cursor`` rows, reset the row to ``CREATED``, commit,
  submit fresh worker task(s).
* Durable ``kind='recovery'`` ledger event via
  :func:`ResilienceLayer.emit_recovery_event` after a successful
  re-enqueue (RFC-07 #31 audit trail).
* Best-effort per id: one failing heal logs and the sweep continues.

Context (unchanged from the pre-lift module docstring):

The task-level sweeps
(:mod:`aila.platform.tasks.worker._sweep_orphan_running_tasks` +
:mod:`aila.platform.tasks.state_reconciler`) cover one recovery gap
only: a ``taskrecord`` row still in ``queued`` / ``running`` /
``waiting`` whose worker died AND whose ``workflow_state_cursor`` is
still resumable. They do NOT cover the sibling zombie: an
investigation whose ``status`` is still ``running``, whose tasks are
ALL terminal (or absent), AND whose cursor is absent or terminal
(``__crashed__`` / ``__failed__`` / ``__cancelled__`` /
``__succeeded__``). No resumable cursor means the task-level sweep
leaves it alone; the ``running`` status projection means finalize will
not close it either. Without this automated healer the row sits
``running`` forever until an operator manually calls ``/re-enqueue``.
"""
from __future__ import annotations

import logging
from typing import Any

from aila.platform.services.recovery_service import (
    CONFIG_KEY_IDLE_GRACE_S,
    CONFIG_KEY_MAX_HEALS_PER_TICK,
    PlatformRecoveryService,
    RecoveryBinding,
    RecoveryStrategy,
    StuckBinding,
    SubmitOneFn,
)
from aila.platform.services.recovery_service import (
    DEFAULT_STUCK_IDLE_GRACE_S as DEFAULT_IDLE_GRACE_S,
)
from aila.platform.services.recovery_service import (
    DEFAULT_STUCK_MAX_HEALS_PER_TICK as DEFAULT_MAX_HEALS_PER_TICK,
)

__all__ = [
    "CONFIG_KEY_IDLE_GRACE_S",
    "CONFIG_KEY_MAX_HEALS_PER_TICK",
    "DEFAULT_IDLE_GRACE_S",
    "DEFAULT_MAX_HEALS_PER_TICK",
    "SubmitOneFn",
    "sweep_stuck_investigations",
]

_log = logging.getLogger(__name__)


async def sweep_stuck_investigations(
    *,
    inv_model: type[Any],
    running_status_values: tuple[str, ...],
    fn_path_pattern: str,
    module_id: str,
    submit_one: SubmitOneFn,
    branch_model: type[Any] | None = None,
    branch_status_active: str | None = None,
    idle_grace_s: int | None = None,
    max_heals_per_tick: int | None = None,
    inv_timestamp_column: str = "updated_at",
) -> dict[str, Any]:
    """Detect + heal investigations stuck at ``running`` with no worker path.

    Thin back-compat wrapper -- see the module docstring and the unified
    :meth:`PlatformRecoveryService.sweep` for the full contract. Every
    kwarg is pre-lift compatible; the wrapper folds them into a
    :class:`RecoveryBinding` populated with only the STUCK branch and
    calls the unified sweep filtered to
    :attr:`RecoveryStrategy.STUCK_HEAL`.

    Module bindings supply the concrete investigation model, the
    running-status values that count as "should be making progress",
    the ``fn_path`` LIKE pattern used to cancel stale tasks in the
    re-enqueue reset, the module id (for config lookup + recovery
    event provenance), and the atomic submit primitive. The optional
    ``branch_model`` / ``branch_status_active`` mirror
    :func:`reenqueue_investigation`'s fan-out contract; ``None`` keeps
    the VR-style single-submit behavior.

    Returns a small dict summary (identical shape to the pre-lift
    return value)::

        {"examined": int, "healed": int, "ids": list[str]}

    ``examined`` is the number of stuck rows the SELECT returned in
    this tick (before the per-heal cap). ``healed`` counts successful
    re-enqueue + journal pairs. ``ids`` lists the investigation ids
    that actually healed (a per-row failure keeps the id off this
    list).
    """
    binding = RecoveryBinding(
        investigations_table=inv_model.__tablename__,
        stall=None,
        stuck=StuckBinding(
            inv_model=inv_model,
            running_status_values=running_status_values,
            fn_path_pattern=fn_path_pattern,
            module_id=module_id,
            submit_one=submit_one,
            branch_model=branch_model,
            branch_status_active=branch_status_active,
            inv_timestamp_column=inv_timestamp_column,
            idle_grace_s=idle_grace_s,
            max_heals_per_tick=max_heals_per_tick,
        ),
    )
    result = await PlatformRecoveryService.sweep(
        binding=binding,
        only_strategy=RecoveryStrategy.STUCK_HEAL,
    )
    return result.stuck.as_dict()
