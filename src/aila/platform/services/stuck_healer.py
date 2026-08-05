"""RFC-07 criterion 6 -- automatic INVESTIGATION-level stuck healer.

The task-level sweeps (:mod:`aila.platform.tasks.worker._sweep_orphan_running_tasks`
+ :mod:`aila.platform.tasks.state_reconciler`) cover one recovery gap only:
a ``taskrecord`` row still in ``queued`` / ``running`` / ``waiting`` whose
worker died AND whose ``workflow_state_cursor`` is still resumable. The
reconciler flips the stale task row to ``CANCELLED`` and the next worker
sweep re-enqueues from the resumable cursor.

They do NOT cover the sibling zombie: an investigation whose ``status`` is
still ``running``, whose tasks are ALL terminal (or absent), AND whose
cursor is absent or terminal (``__crashed__`` / ``__failed__`` /
``__cancelled__`` / ``__succeeded__``). No resumable cursor means the
task-level sweep leaves it alone; the ``running`` status projection means
finalize will not close it either. Without an automated healer the row sits
``running`` forever until an operator manually calls ``/re-enqueue``.

This module owns that healer. It is parameterised so each module binds one
partial with its own investigation model, running-status vocabulary,
investigate-task ``fn_path`` pattern, and per-tick config namespace. The
platform sweep:

* selects investigations whose ``status`` is in ``running_status_values``
  (never touching ``PAUSED`` / ``CANCELLED`` / ``COMPLETED`` /
  ``FAILED`` / ``ABANDONED`` / ``STALLED``);
* filters to rows whose ``<inv_timestamp_column>`` is older than the
  configured idle grace so a just-started run is never touched;
* excludes rows with any live ``taskrecord`` (``kwargs_json`` carries the
  ``investigation_id``, status in ``queued`` / ``running`` / ``waiting``);
* excludes rows with any resumable ``workflow_state_cursor``
  (denormalised ``investigation_id`` join key, ``current_state`` NOT in the
  reserved-terminal + ``__paused__`` set) -- the task-level sweep owns
  those;
* for each survivor (bounded by ``max_heals_per_tick``), calls
  :func:`aila.platform.services.investigation_lifecycle.reenqueue_investigation`
  to drive the four-source-of-truth reset + fresh submit, then journals a
  durable ``kind='recovery'`` ledger entry via
  :func:`ResilienceLayer.emit_recovery_event` so the heal is itself
  auditable (RFC-07 #31 + honesty rule 54).

Best-effort per id: one failing re-enqueue logs and the sweep continues
with the next id; a whole-sweep failure never blocks other periodic
sweeps in the same tick.
"""
from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import text as _sql_text
from sqlalchemy.exc import SQLAlchemyError

from aila.platform.config_base import ModuleConfigReader
from aila.platform.services.investigation_lifecycle import (
    ReenqueueInvestigationError,
    reenqueue_investigation,
)
from aila.platform.services.resilience import get_default_resilience_layer
from aila.storage.database import async_session_scope

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
# One key per knob; each module's ``config_schema.py`` declares matching
# fields with the same defaults so ``ConfigRegistry.get`` resolves the
# fallback without ever returning None.
CONFIG_KEY_IDLE_GRACE_S = "stuck_healer_idle_grace_s"
CONFIG_KEY_MAX_HEALS_PER_TICK = "stuck_healer_max_heals_per_tick"

# Fallback defaults used when a module has NOT declared these fields on its
# config schema yet (``ConfigRegistry.get`` would then return ``None``).
# Generous idle grace so a legitimately slow turn is never mistaken for a
# stall; small per-tick cap so a mass zombie backlog does not saturate the
# task queue in one tick.
DEFAULT_IDLE_GRACE_S: int = 600
DEFAULT_MAX_HEALS_PER_TICK: int = 5

# Reserved cursor states that count as NON-resumable. Kept in sync with
# :data:`aila.platform.tasks.state_reconciler._TERMINAL_CURSOR_STATES`
# plus the ``__paused__`` operator sentinel; a cursor row in any of these
# states does not gate the healer because the task-level sweep will not
# re-enqueue from it (terminal cursors are dead, ``__paused__`` is
# operator-owned).
_NON_RESUMABLE_CURSOR_STATES: tuple[str, ...] = (
    "__crashed__", "__failed__", "__cancelled__", "__succeeded__",
    "__paused__",
)


# Same shape ``reenqueue_investigation`` accepts for its ``submit_one``:
# the module supplies an atomic single-task submit primitive. The healer
# never inspects the return value; a per-row failure is caught around the
# whole ``reenqueue_investigation`` call.
SubmitOneFn = Callable[[str, str | None], Awaitable[None]]


async def _resolve_int_config(
    module_id: str, key: str, default: int,
) -> int:
    """Resolve a positive int config value with a schema-default fallback.

    ``ModuleConfigReader.get_int`` raises ``TypeError`` when the resolved
    value is not coercible (unregistered schema returns None). Callers
    tolerate that by falling back to :data:`DEFAULT_IDLE_GRACE_S` /
    :data:`DEFAULT_MAX_HEALS_PER_TICK`; the fallback is logged once per
    resolution so an operator can spot a missing schema field without
    trawling the DB.
    """
    reader = ModuleConfigReader(module_id)
    try:
        value = await reader.get_int(key)
    except (TypeError, ValueError) as exc:
        _log.warning(
            "stuck_healer: config %s/%s unresolved (%s); using default=%d",
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


async def _fetch_stuck_ids(
    *,
    investigations_table: str,
    running_status_values: tuple[str, ...],
    inv_timestamp_column: str,
    cutoff: datetime,
    limit: int,
) -> list[str]:
    """Return investigation ids that match the stuck-but-dead criteria.

    Every clause below MUST hold for a row to appear:

    * ``status`` is in the module's running vocabulary (never a paused,
      cancelled, or terminal row);
    * the row's chosen timestamp column is older than the cutoff (so a
      brand-new run is never healed);
    * no live ``taskrecord`` references this investigation (any queued /
      running / waiting task blocks the heal so we do not double-submit);
    * no ``workflow_state_cursor`` row for this investigation is
      resumable (a resumable cursor is the task-level sweep's territory).

    The two table identifiers (``investigations_table`` and the timestamp
    column name) are trusted platform / module constants -- never user
    input -- so they interpolate into the SQL body directly. Postgres
    disallows bind parameters for identifiers, and the module-owned
    identifier surface is small enough that a whitelist would only add
    noise.
    """
    stmt = _sql_text(
        f"""
        SELECT inv.id::text AS id
        FROM {investigations_table} inv
        WHERE inv.status = ANY(:running_values)
          AND inv.{inv_timestamp_column} < :cutoff
          AND NOT EXISTS (
              SELECT 1
              FROM taskrecord t
              WHERE t.kwargs_json::jsonb->>'investigation_id'
                    = inv.id::text
                AND t.status IN ('queued', 'running', 'waiting')
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
        non_resumable_states=list(_NON_RESUMABLE_CURSOR_STATES),
        lim=limit,
    )
    async with async_session_scope() as session:
        return [
            r["id"] for r in (await session.execute(stmt)).mappings().all()
        ]


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

    Module bindings supply the concrete investigation model, the running-
    status values that count as "should be making progress", the
    ``fn_path`` LIKE pattern used to cancel stale tasks in the re-enqueue
    reset, the module id (for config lookup + recovery event provenance),
    and the atomic submit primitive. The optional ``branch_model`` /
    ``branch_status_active`` mirror ``reenqueue_investigation``'s fan-out
    contract; ``None`` keeps the VR-style single-submit behavior.

    Config knobs resolve through :class:`ModuleConfigReader` under the
    module namespace; every module's ``config_schema.py`` declares
    :data:`CONFIG_KEY_IDLE_GRACE_S` and
    :data:`CONFIG_KEY_MAX_HEALS_PER_TICK` so an operator ``PUT /config``
    override lands on the next call without a worker restart. Explicit
    kwargs win over config resolution -- the test path passes them
    directly to keep tests hermetic.

    Returns a small dict summary::

        {"examined": int, "healed": int, "ids": list[str]}

    ``examined`` is the number of stuck rows the SELECT returned in this
    tick (before the per-heal cap). ``healed`` counts successful
    re-enqueue + journal pairs. ``ids`` lists the investigation ids that
    actually healed (a per-row failure keeps the id off this list).

    Best-effort per id: a re-enqueue or journal failure is logged and the
    sweep continues with the next id. A whole-sweep failure would abort
    the surrounding periodic-sweep block, so nothing here is allowed to
    raise unless the SELECT itself fails (which the caller's
    ``_run_reaper_block`` handles per the existing best-effort cron
    policy).
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
        stuck_ids = await _fetch_stuck_ids(
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
    for inv_id in stuck_ids:
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
            # Investigation row vanished between SELECT and lock. Log and
            # skip; the next tick's SELECT will not surface it again.
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
