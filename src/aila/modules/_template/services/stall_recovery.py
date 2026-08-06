"""Template binding of the platform stall-recovery sweep.

Mirrors :mod:`aila.modules.vr.services.stall_recovery`. Binds the
platform generic to the template investigations + branches tables, a
placeholder sweepable-kind set, the template env-var prefix, and the
template task submitter.

``_default_submit_fn`` stays module-side because it imports the
template-owned task function (``run_template_investigate``). The
imports are deferred so the sweep module can be imported from the
worker boot path without pulling the module loader / task queue
surface.

``sweep_stalled_investigations`` is a module-level ``functools.partial``
so the periodic-sweep registry (which keys re-registration on callable
identity) sees a stable object across re-imports -- mirrors the pattern
in ``branch_reaper.py``.

Env-var knobs (operator-tunable, following the vr / malware shape):

* ``AILA_TEMPLATE_STALL_RECOVERY_LIMIT`` -- submits per tick (default 6)
* ``AILA_TEMPLATE_STALL_RECOVERY_IDLE_MIN`` -- idle threshold in minutes
  (default 15)
"""
from __future__ import annotations

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

# Placeholder: the template scaffold does not declare investigation
# kinds of its own yet. A copier fills this tuple with the module's
# real kind vocabulary (see vr's ``("audit", "discovery", ...)`` and
# malware's ``("full_analysis", "triage", ...)`` for shape). An empty
# tuple keeps the sweep a well-formed no-op until then -- the SQL
# ``kind = ANY(:kinds)`` filter simply matches nothing.
_SWEEPABLE_KINDS: tuple[str, ...] = ()

# Template ships no kinds that own their own branch lifecycle -- the
# NDay-style single-submit dispatch VR uses does not exist here. A
# copier adds any single-submit kinds their module's task body owns
# internally (see vr's ``("n_day",)`` for the concrete shape).
_SINGLE_SUBMIT_KINDS: tuple[str, ...] = ()


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
    from aila.modules._template._task_queue import default_task_queue
    from aila.modules._template.workflow.task import run_template_investigate

    fn: Any = run_template_investigate
    kwargs: dict[str, object] = {"investigation_id": inv_id}
    if branch_id:
        kwargs["branch_id"] = branch_id
    del inv_kind  # eligibility already pinned this to a sweepable kind

    task_queue = default_task_queue()
    await task_queue.submit(
        track="template",
        fn=fn,
        kwargs=kwargs,
        user_id="system",
        group_id="template_stall_recovery",
        team_id=team_id,
        # bypass_dedup mixes a uuid into the hash input so the sweep
        # neither collides with (a) the killed task's stale
        # running-status row whose reaper has not yet fired nor
        # (b) another recovery attempt in the same tick sharing kwargs.
        bypass_dedup=True,
    )


sweep_stalled_investigations = partial(
    _platform_sweep,
    submit_fn=_default_submit_fn,
    sweepable_kinds=_SWEEPABLE_KINDS,
    single_submit_kinds=_SINGLE_SUBMIT_KINDS,
    env_prefix="AILA_TEMPLATE_STALL_RECOVERY",
    investigations_table="template_investigations",
    branches_table="template_investigation_branches",
)
