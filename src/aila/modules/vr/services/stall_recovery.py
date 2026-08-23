"""VR binding of the platform stall-recovery sweep.

Binds the platform generic to VR's investigations + branches tables, the
VR sweepable-kind set (with ``n_day`` marked as a single-submit kind so
the sweep skips branch fan-out for it), the VR env-var prefix, and the
VR task submitter.

``_default_submit_fn`` stays module-side because it imports the VR-owned
task functions (``run_vr_investigate`` + ``run_vr_nday``) with the
``n_day`` dispatch branch. The imports are deferred so the sweep module
can be imported from the worker boot path without pulling the module
loader / task queue surface.

``sweep_stalled_investigations`` is a module-level ``async def`` that
gates the bound platform sweep on model-node health (skip the tick
while the node is down, see VR-8FD8) and forwards any kwargs through.
The periodic-sweep registry keys re-registration on callable identity,
so a stable module-level name is what it needs -- the bound sweep it
delegates to lives in ``_stall_sweep_bound``.

Rate model, eligibility semantics, and the recovery rationale are
documented on the platform sweep -- see
``aila.platform.services.stall_recovery``.

Env-var knobs (operator-tunable, unchanged from pre-lift):

* ``AILA_VR_STALL_RECOVERY_LIMIT`` -- submits per tick (default 6)
* ``AILA_VR_STALL_RECOVERY_IDLE_MIN`` -- idle threshold in minutes
  (default 15)
"""
from __future__ import annotations

import logging
from functools import partial
from typing import Any

from aila.platform.services.stall_recovery import (
    StallRecoveryResult,
    SubmitFn,
)
from aila.platform.services.stall_recovery import (
    sweep_stalled_investigations as _platform_sweep,
)

__all__ = [
    "StallRecoveryResult",
    "SubmitFn",
    "sweep_stalled_investigations",
]

_log = logging.getLogger(__name__)

# Kinds the sweep handles. ``masvs_audit`` is intentionally absent:
# parent_reconciler owns its lifecycle. The parent's child
# investigations are regular ``audit`` kind and ARE handled here.
_SWEEPABLE_KINDS: tuple[str, ...] = (
    "audit", "discovery", "variant_hunt", "triage", "n_day",
)

# Kinds whose task body owns its own branch lifecycle -- the sweep
# emits a single inv-level submit and skips branch fan-out. ``n_day``'s
# task body manages its own internal branching, so the sweep hands it
# only the investigation id.
_SINGLE_SUBMIT_KINDS: tuple[str, ...] = ("n_day",)


async def _default_submit_fn(
    inv_kind: str,
    inv_id: str,
    branch_id: str | None,
    team_id: str | None,
) -> None:
    """Production submitter -- binds to ``default_task_queue``.

    Deferred imports because this module sits in the worker boot path;
    we MUST not pull the task queue / module loader surface during the
    recovery-sweep import.
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


_stall_sweep_bound = partial(
    _platform_sweep,
    submit_fn=_default_submit_fn,
    sweepable_kinds=_SWEEPABLE_KINDS,
    single_submit_kinds=_SINGLE_SUBMIT_KINDS,
    env_prefix="AILA_VR_STALL_RECOVERY",
    investigations_table="vr_investigations",
    branches_table="vr_investigation_branches",
)


async def sweep_stalled_investigations(**overrides: Any) -> StallRecoveryResult:
    """VR stall-recovery tick, gated on model-node health (VR-8FD8).

    The VR investigate loop makes zero progress while the model node is
    down: a resubmit into a dead node burns one empty turn, exits
    ``after_turn=0``, and the emit path demotes the row straight back to
    ``stalled`` (see the OUTAGE_HOLD guard in
    ``investigation_emit_base``). Firing that resubmit on every 1-minute
    reaper tick during an outage is pure churn. Skip the tick while the
    model has been unhealthy in the trailing 10 minutes with no
    more-recent success; the first tick after the node answers a health
    probe resumes recovery. Mirrors the outage guards in
    ``investigation_emit_base`` + ``investigation_finalizers``.

    ``**overrides`` forwards to the bound platform sweep unchanged, so
    the reaper's zero-arg call and the test suite's kwargs-override
    calls (``submit_fn=``, ``idle_minutes=``, ``rate_per_tick=``) both
    keep working. Passing ``submit_fn`` overrides the production
    submitter as before.
    """
    from aila.platform.llm.client import is_llm_recently_unhealthy

    if is_llm_recently_unhealthy(600.0):
        _log.info(
            "vr.stall_recovery: skipping tick -- model node unhealthy in "
            "trailing 10min with no more-recent success; deferring "
            "resubmit until the node recovers",
        )
        return StallRecoveryResult()
    return await _stall_sweep_bound(**overrides)
