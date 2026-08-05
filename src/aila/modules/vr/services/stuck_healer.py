"""VR binding of the platform stuck-investigation healer (RFC-07 #31).

Binds :func:`aila.platform.services.stuck_healer.sweep_stuck_investigations`
to VR's investigation model, the VR running-status vocabulary
(``InvestigationStatus.RUNNING`` -- ``created`` is the pre-dispatch state
the ``vr.stall_recovery`` sweep already handles, so the healer stays
narrow on ``running``), the VR investigate-task ``fn_path`` pattern used
by the operator ``/re-enqueue`` endpoint, and a submitter that enqueues
``run_vr_investigate`` on the ``vr`` track.

``sweep_stuck_investigations`` is a module-level ``functools.partial`` so
the periodic-sweep registry (which keys re-registration on callable
identity) sees a stable object across re-imports -- mirrors the
``stall_recovery`` binding pattern.

Idle grace + per-tick cap resolve through :class:`ModuleConfigReader`
under the ``vr`` namespace on the well-known keys
``stuck_healer_idle_grace_s`` + ``stuck_healer_max_heals_per_tick``.
See :class:`VRConfigSchema` for the field defaults.
"""
from __future__ import annotations

from functools import partial

from aila.modules.vr.db_models import VRInvestigationRecord
from aila.platform.contracts.enums import InvestigationStatus
from aila.platform.services.stuck_healer import (
    sweep_stuck_investigations as _platform_sweep,
)

__all__ = ["sweep_stuck_investigations"]

# LIKE pattern the re-enqueue path uses to cancel any stale ``taskrecord``
# still in queued/running/waiting for this investigation. Matches the VR
# operator ``/re-enqueue`` endpoint verbatim so the healer and the
# manual re-enqueue converge on the same stale-task cancel set.
_VR_INVESTIGATE_FN_PATTERN = "%run_vr_investigate%"

_VR_RUNNING_STATUSES: tuple[str, ...] = (
    InvestigationStatus.RUNNING.value,
)


async def _submit_one(inv_id: str, branch_id: str | None) -> None:
    """Enqueue one ``run_vr_investigate`` task, matching the VR ``/re-enqueue``.

    VR submits once per investigation and lets the setup state respawn /
    reuse the persona branches on dispatch -- ``branch_id`` is dropped
    here on purpose. ``bypass_dedup=True`` mirrors ``stall_recovery``'s
    default submitter: without it the platform ``TaskQueue`` input-hash
    dedup would collide with the CANCELLED-but-not-yet-purged row this
    heal just cancelled.

    Deferred imports because this module sits on the worker boot path;
    pulling the task queue + module task surface at import time would
    load domain code the platform reaper never needs directly.
    """
    del branch_id  # VR submits once; setup owns branch spawn
    from aila.modules.vr._task_queue import default_task_queue
    from aila.modules.vr.workflow.task import run_vr_investigate

    task_queue = default_task_queue()
    await task_queue.submit(
        track="vr",
        fn=run_vr_investigate,
        kwargs={"investigation_id": inv_id},
        user_id="system",
        group_id="vr_stuck_healer",
        team_id=None,
        bypass_dedup=True,
    )


sweep_stuck_investigations = partial(
    _platform_sweep,
    inv_model=VRInvestigationRecord,
    running_status_values=_VR_RUNNING_STATUSES,
    fn_path_pattern=_VR_INVESTIGATE_FN_PATTERN,
    module_id="vr",
    submit_one=_submit_one,
    # VR uses submit-once mode (setup respawns branches), matching the
    # operator ``/re-enqueue`` endpoint at
    # ``vr/api_router.py::reenqueue_investigation``.
    branch_model=None,
    branch_status_active=None,
)
