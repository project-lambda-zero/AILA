"""VR binding of the investigation-scoped reconciler authority (RFC-07
reconcile wave, L3.3 / L3.4).

Binds :func:`aila.platform.tasks.state_reconciler.sweep_investigations_reconcile`
to VR's investigation model, track, fn-path pattern, and the submit
primitive -- the same data the operator ``/re-enqueue`` endpoint binds,
so the periodic reconcile pass and the manual re-enqueue converge on the
same stale-task cancel set and the same submit-once fan-out.

``sweep_investigations_reconcile`` is a module-level ``functools.partial``
so the periodic-sweep registry (which keys re-registration on callable
identity) sees a stable object across re-imports -- mirrors the
``stall_recovery`` / ``stuck_healer`` binding pattern.

The pass itself is gated at runtime by
``platform.investigation_reconciler_periodic_enabled`` (default True)
inside the platform sweep callable; this file only declares the binding.
"""
from __future__ import annotations

from functools import partial

from aila.modules.vr.db_models.investigation import VRInvestigationRecord
from aila.platform.tasks.state_reconciler import (
    InvestigationRecoveryBinding,
)
from aila.platform.tasks.state_reconciler import (
    sweep_investigations_reconcile as _platform_sweep,
)

__all__ = ["sweep_investigations_reconcile"]

# LIKE pattern the reconciler's re-enqueue fallback uses to cancel any
# stale ``taskrecord`` still in queued/running/waiting for this
# investigation. Matches the VR operator ``/re-enqueue`` endpoint
# verbatim so the automatic pass and the manual re-enqueue converge on
# the same stale-task cancel set.
_VR_INVESTIGATE_FN_PATTERN = "%run_vr_investigate%"


async def _submit_one(inv_id: str, branch_id: str | None) -> None:
    """Enqueue one ``run_vr_investigate`` task, matching the VR ``/re-enqueue``.

    VR submits once per investigation and lets the setup state respawn /
    reuse the persona branches on dispatch -- ``branch_id`` is dropped
    here on purpose. ``bypass_dedup=True`` mirrors ``stuck_healer``'s
    submitter: the reconciler's re-enqueue fallback just cancelled the
    stale rows and the fresh submit must never dedup against them (the
    deeper dedup hardening is an explicit non-goal of the reconcile
    wave).

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
        group_id="vr_investigation_reconciler",
        team_id=None,
        bypass_dedup=True,
    )


_VR_RECONCILE_BINDING = InvestigationRecoveryBinding(
    module_id="vr",
    investigations_table="vr_investigations",
    track="vr",
    fn_path_pattern=_VR_INVESTIGATE_FN_PATTERN,
    inv_model=VRInvestigationRecord,
    submit_one=_submit_one,
    # VR uses submit-once mode (setup respawns branches), matching the
    # operator ``/re-enqueue`` endpoint at
    # ``vr/api_router.py::reenqueue_investigation``.
    branch_model=None,
    branch_status_active=None,
)

sweep_investigations_reconcile = partial(
    _platform_sweep,
    binding=_VR_RECONCILE_BINDING,
)
