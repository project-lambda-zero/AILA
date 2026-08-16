"""RFC-07 criterion 6 -- automatic INVESTIGATION-level stuck healer.

The task-level sweeps
(:mod:`aila.platform.tasks.worker._sweep_orphan_running_tasks` +
:mod:`aila.platform.tasks.state_reconciler`) cover one recovery gap
only: a ``taskrecord`` row still in ``queued`` / ``running`` /
``waiting`` whose worker died AND whose ``workflow_state_cursor`` is
still resumable. The reconciler flips the stale task row to
``CANCELLED`` and the next worker sweep re-enqueues from the
resumable cursor.

They do NOT cover the sibling zombie: an investigation whose
``status`` is still ``running``, whose tasks are ALL terminal (or
absent), AND whose cursor is absent or terminal (``__crashed__`` /
``__failed__`` / ``__cancelled__`` / ``__succeeded__``). No resumable
cursor means the task-level sweep leaves it alone; the ``running``
status projection means finalize will not close it either. Without an
automated healer the row sits ``running`` forever until an operator
manually calls ``/re-enqueue``.

Eligibility, dispatch
---------------------

Eligibility lives on the unified
:class:`aila.platform.services.recovery_service.PlatformRecoveryService`
(:meth:`PlatformRecoveryService.fetch_stuck_candidates`) alongside the
sibling stall SELECT. The non-resumable cursor sentinel set lives at
:data:`aila.platform.services.recovery_service.NON_RESUMABLE_CURSOR_STATES`
so a future sentinel addition does not drift between call sites.

Per-row dispatch stays here: this module owns the
:attr:`RecoveryStrategy.STUCK_HEAL` execution path, which is the full
:func:`aila.platform.services.investigation_lifecycle.reenqueue_investigation`
four-source-of-truth reset (cancel stale tasks, wipe crashed cursors,
reset row to CREATED, commit, submit fresh) plus a durable
``kind='recovery'`` ledger event via
:func:`ResilienceLayer.emit_recovery_event` so the heal is itself
auditable (RFC-07 #31 + honesty rule 54).

Best-effort per id: one failing re-enqueue logs and the sweep
continues with the next id; a whole-sweep failure never blocks other
periodic sweeps in the same tick.
"""
from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy.exc import SQLAlchemyError

from aila.platform.config_base import ModuleConfigReader
from aila.platform.services.investigation_lifecycle import (
    ReenqueueInvestigationError,
    reenqueue_investigation,
)
from aila.platform.services.recovery_service import PlatformRecoveryService
from aila.platform.services.resilience import get_default_resilience_layer

__all__ = [
    "CONFIG_KEY_IDLE_GRACE_S",
    "CONFIG_KEY_MAX_HEALS_PER_TICK",
    "DEFAULT_IDLE_GRACE_S",
    "DEFAULT_MAX_HEALS_PER_TICK",
    "SubmitOneFn",
    "sweep_stuck_investigations",
]

_log = logging.getLogger(__name__)

# ``ModuleConfigReader.get_int`` keys the operator-tunable knobs land at.
# One key per knob; each module's ``config_schema.py`` declares a matching
# field with the same default. An operator DB override resolves through
# ``ConfigRegistry.get`` (env -> DB); when unset, ``get`` returns None (it
# does not fall through to the Pydantic schema default for module keys --
# the existing stall-recovery knobs behave the same), so the code default
# below is the real fallback and matches the schema value.
CONFIG_KEY_IDLE_GRACE_S = "stuck_healer_idle_grace_s"
CONFIG_KEY_MAX_HEALS_PER_TICK = "stuck_healer_max_heals_per_tick"

# Fallback defaults used when a module has NOT declared these fields on its
# config schema yet (``ConfigRegistry.get`` would then return ``None``).
# Generous idle grace so a legitimately slow turn is never mistaken for a
# stall; small per-tick cap so a mass zombie backlog does not saturate the
# task queue in one tick.
DEFAULT_IDLE_GRACE_S: int = 600
DEFAULT_MAX_HEALS_PER_TICK: int = 5


# Same shape ``reenqueue_investigation`` accepts for its ``submit_one``:
# the module supplies an atomic single-task submit primitive. The healer
# never inspects the return value; a per-row failure is caught around the
# whole ``reenqueue_investigation`` call.
SubmitOneFn = Callable[[str, str | None], Awaitable[None]]


async def _resolve_int_config(
    module_id: str, key: str, default: int,
) -> int:
    """Resolve a positive int config value with a code-default fallback.

    ``ModuleConfigReader.get_int`` coerces ``ConfigRegistry.get``'s value.
    An UNSET key (no env / no DB override) yields None -> ``int(None)``
    raises ``TypeError``: that is the NORMAL path (the code default equals
    the schema value), logged at DEBUG so a per-tick sweep does not spam
    the worker log. A MALFORMED override (a non-numeric DB / env value)
    raises ``ValueError``: that is a real operator misconfiguration and is
    logged at WARNING. Either way the conservative code default is used.
    """
    reader = ModuleConfigReader(module_id)
    try:
        value = await reader.get_int(key)
    except TypeError:
        # Unset key -- the expected fallback, not a fault.
        _log.debug(
            "stuck_healer: config %s/%s unset; using default=%d",
            module_id, key, default,
        )
        return default
    except ValueError as exc:
        _log.warning(
            "stuck_healer: config %s/%s malformed (%s); using default=%d",
            module_id, key, exc, default,
        )
        return default
    if value <= 0:
        _log.warning(
            "stuck_healer: config %s/%s=%d is non-positive; using default=%d",
            module_id, key, value, default,
        )
        return default
    return value


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

    Module bindings supply the concrete investigation model, the
    running-status values that count as "should be making progress",
    the ``fn_path`` LIKE pattern used to cancel stale tasks in the
    re-enqueue reset, the module id (for config lookup + recovery
    event provenance), and the atomic submit primitive. The optional
    ``branch_model`` / ``branch_status_active`` mirror
    ``reenqueue_investigation``'s fan-out contract; ``None`` keeps the
    VR-style single-submit behavior.

    Eligibility SELECT + non-resumable cursor set live on
    :class:`aila.platform.services.recovery_service.PlatformRecoveryService`;
    this loop owns only the ``STUCK_HEAL`` execution path (atomic
    claim -> ``reenqueue_investigation`` -> journal a
    ``kind='recovery'`` ledger event).

    Config knobs resolve through :class:`ModuleConfigReader` under the
    module namespace; every module's ``config_schema.py`` declares
    :data:`CONFIG_KEY_IDLE_GRACE_S` and
    :data:`CONFIG_KEY_MAX_HEALS_PER_TICK` so an operator ``PUT /config``
    override lands on the next call without a worker restart. Explicit
    kwargs win over config resolution -- the test path passes them
    directly to keep tests hermetic.

    Returns a small dict summary::

        {"examined": int, "healed": int, "ids": list[str]}

    ``examined`` is the number of stuck rows the SELECT returned in
    this tick (before the per-heal cap). ``healed`` counts successful
    re-enqueue + journal pairs. ``ids`` lists the investigation ids
    that actually healed (a per-row failure keeps the id off this
    list).

    Best-effort per id: a re-enqueue or journal failure is logged and
    the sweep continues with the next id. A whole-sweep failure would
    abort the surrounding periodic-sweep block, so nothing here is
    allowed to raise unless the SELECT itself fails (which the
    caller's ``_run_reaper_block`` handles per the existing
    best-effort cron policy).
    """
    grace_s = idle_grace_s if idle_grace_s is not None else (
        await _resolve_int_config(
            module_id, CONFIG_KEY_IDLE_GRACE_S, DEFAULT_IDLE_GRACE_S,
        )
    )
    cap = max_heals_per_tick if max_heals_per_tick is not None else (
        await _resolve_int_config(
            module_id, CONFIG_KEY_MAX_HEALS_PER_TICK, DEFAULT_MAX_HEALS_PER_TICK,
        )
    )
    if cap <= 0:
        _log.warning(
            "stuck_healer[%s]: max_heals_per_tick=%d <= 0; skipping tick",
            module_id, cap,
        )
        return {"examined": 0, "healed": 0, "ids": []}

    investigations_table = inv_model.__tablename__
    cutoff = datetime.now(UTC) - timedelta(seconds=grace_s)

    try:
        stuck_ids = await PlatformRecoveryService.fetch_stuck_candidates(
            investigations_table=investigations_table,
            running_status_values=running_status_values,
            inv_timestamp_column=inv_timestamp_column,
            cutoff=cutoff,
            limit=cap,
        )
    except SQLAlchemyError as exc:
        _log.warning(
            "stuck_healer[%s]: eligibility SELECT failed: %s",
            module_id, exc,
        )
        return {"examined": 0, "healed": 0, "ids": []}

    if not stuck_ids:
        return {"examined": 0, "healed": 0, "ids": []}

    healed_ids: list[str] = []
    resilience = get_default_resilience_layer()
    for inv_id, seen_ts in stuck_ids:
        # Issue #121: shared mutual exclusion with stall_recovery (and
        # cross-process cron ticks). Both sweeps' eligibility clauses
        # overlap on ``status=running, no live task, past idle grace``,
        # so the same investigation can appear in both. The atomic
        # compare-and-set on the timestamp column ensures only one
        # racer proceeds; the loser's UPDATE affects zero rows and
        # this iteration skips. Bumping the timestamp also hides the
        # row from the next tick's SELECT until the fresh re-enqueue
        # drives a turn that settles the row.
        if not await PlatformRecoveryService.try_claim(
            inv_table=investigations_table,
            timestamp_column=inv_timestamp_column,
            inv_id=inv_id,
            seen_timestamp=seen_ts,
        ):
            _log.info(
                "stuck_healer[%s]: inv=%s lost claim to concurrent "
                "recovery sweep; skipping",
                module_id, inv_id,
            )
            continue
        try:
            await reenqueue_investigation(
                inv_id,
                inv_model=inv_model,
                fn_path_pattern=fn_path_pattern,
                submit_one=submit_one,
                branch_model=branch_model,
                branch_status_active=branch_status_active,
            )
        except ReenqueueInvestigationError as exc:
            # Investigation row vanished between SELECT and lock. Log
            # and skip; the next tick's SELECT will not surface it
            # again.
            _log.info(
                "stuck_healer[%s]: inv=%s no longer present: %s",
                module_id, inv_id, exc,
            )
            continue
        except (SQLAlchemyError, OSError, RuntimeError, ValueError) as exc:
            _log.warning(
                "stuck_healer[%s]: re-enqueue failed inv=%s err=%s",
                module_id, inv_id, exc,
            )
            continue

        # Journal the heal AFTER a successful re-enqueue. The signal
        # inside ``emit_recovery_event`` always fires; the durable
        # ledger append is best-effort inside the same call so a
        # journal failure never rolls the heal back.
        await resilience.emit_recovery_event(
            investigation_id=inv_id,
            action="stuck_reenqueue",
            detail={
                "module_id": module_id,
                "reason": "running_no_task_no_cursor",
            },
            source="stuck_healer",
        )
        healed_ids.append(inv_id)

    if healed_ids:
        _log.info(
            "stuck_healer[%s]: examined=%d healed=%d ids=%s",
            module_id, len(stuck_ids), len(healed_ids), healed_ids,
        )
    return {
        "examined": len(stuck_ids),
        "healed": len(healed_ids),
        "ids": healed_ids,
    }
