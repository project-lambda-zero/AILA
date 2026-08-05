"""Forensics binding of the platform stuck-investigation healer (RFC-07 #31).

Binds :func:`aila.platform.services.stuck_healer.sweep_stuck_investigations`
to forensics's :class:`InvestigationRunRecord`, its running-status value
(``InvestigationStatus.RUNNING`` -- ``pending`` is the pre-dispatch state,
never a stall), and a submitter that enqueues
``run_forensics_panel_investigate`` per active panel branch on the
``forensics`` track.

The forensics investigate surface has two task shapes:

* ``run_forensics_panel_investigate`` -- panel (#18), takes only
  ``investigation_id`` + ``branch_id`` per persona sibling. This is the
  path the healer covers.
* ``run_forensics_investigation`` -- freeflow, requires ``project_id`` /
  ``question`` / ``integration`` / ``analyzer_os`` /
  ``evidence_directory`` reconstructed from the project row. The healer
  does NOT reconstruct that surface -- a freeflow inv with no active
  panel branch falls through the ``_submit_one`` fallback path and
  raises, which the per-id catch in the platform sweep logs and skips.
  Operator remediation for a stuck freeflow stays the ``rerun``
  endpoint (creates a fresh row) rather than an in-place resubmit.

The ``fn_path`` LIKE pattern uses ``investigat`` (no trailing character)
so ``taskrecord`` rows for either shape (``run_forensics_investigation``
AND ``run_forensics_panel_investigate``) are cancelled by
``reenqueue_investigation``'s stale-task reset, matching the intent of
the vr / malware operator ``/re-enqueue`` endpoints.

``sweep_stuck_investigations`` is a module-level ``functools.partial`` so
the periodic-sweep registry (which keys re-registration on callable
identity) sees a stable object across re-imports.

Idle grace + per-tick cap resolve through :class:`ModuleConfigReader`
under the ``forensics`` namespace on the well-known keys
``stuck_healer_idle_grace_s`` + ``stuck_healer_max_heals_per_tick``.
See :class:`ForensicsConfigSchema` for the field defaults.
"""
from __future__ import annotations

from functools import partial

from aila.modules.forensics.contracts.status import InvestigationStatus
from aila.modules.forensics.db_models import (
    ForensicsInvestigationBranchRecord,
    InvestigationRunRecord,
)
from aila.platform.services.stuck_healer import (
    sweep_stuck_investigations as _platform_sweep,
)

__all__ = ["sweep_stuck_investigations"]

# LIKE pattern catches both ``run_forensics_investigation`` (freeflow) and
# ``run_forensics_panel_investigate`` (panel) -- ``investigat`` sits inside
# both spellings so the stale-task cancel step reaches every in-flight
# forensics investigate task for this investigation.
_FORENSICS_INVESTIGATE_FN_PATTERN = "%run_forensics%investigat%"

_FORENSICS_RUNNING_STATUSES: tuple[str, ...] = (
    InvestigationStatus.RUNNING.value,
)

# ``ForensicsInvestigationBranchRecord.status`` is a plain string column
# (branches predate the platform BranchStatus StrEnum for this module).
# The active value matches the string every other write site here uses.
_FORENSICS_BRANCH_ACTIVE = "active"


async def _submit_one(inv_id: str, branch_id: str | None) -> None:
    """Enqueue one ``run_forensics_panel_investigate`` task for a branch.

    The panel task takes only ``investigation_id`` + ``branch_id``; every
    other kwarg the freeflow surface needs (project fields, SSH
    integration) is not part of the panel entry contract.

    A ``branch_id=None`` call means the row had no active panel branch
    when :func:`_fan_out_reenqueue_submit` inspected it. That is the
    freeflow shape, which this healer does not reconstitute -- raise so
    the platform sweep's per-id catch logs and moves on. The row stays
    ``running`` until the operator picks it up manually.

    ``bypass_dedup=True`` mirrors the malware submitter: without it the
    platform ``TaskQueue`` input-hash dedup would collide with the
    CANCELLED-but-not-yet-purged row this heal just cancelled.

    Deferred imports because this module sits on the worker boot path.
    """
    if branch_id is None:
        raise RuntimeError(
            f"forensics stuck_healer: investigation {inv_id!r} has no "
            "active panel branch; freeflow re-enqueue is not automated "
            "here -- operator can call the /rerun endpoint instead."
        )
    from aila.modules.forensics._task_queue import default_task_queue
    from aila.modules.forensics.workflow.panel.task import (
        run_forensics_panel_investigate,
    )

    task_queue = default_task_queue()
    await task_queue.submit(
        track="forensics",
        fn=run_forensics_panel_investigate,
        kwargs={"investigation_id": inv_id, "branch_id": branch_id},
        user_id="system",
        group_id="forensics_stuck_healer",
        team_id=None,
        bypass_dedup=True,
    )


sweep_stuck_investigations = partial(
    _platform_sweep,
    inv_model=InvestigationRunRecord,
    running_status_values=_FORENSICS_RUNNING_STATUSES,
    fn_path_pattern=_FORENSICS_INVESTIGATE_FN_PATTERN,
    module_id="forensics",
    submit_one=_submit_one,
    branch_model=ForensicsInvestigationBranchRecord,
    branch_status_active=_FORENSICS_BRANCH_ACTIVE,
    # ``InvestigationRunRecord`` predates the platform
    # ``InvestigationRecordBase`` and carries no ``updated_at`` column;
    # ``created_at`` is the only timestamp available for the idle-grace
    # filter. A run whose row is older than the grace still counts as
    # stuck because the panel task's own writes touch the branch /
    # message / outcome tables, not this row.
    inv_timestamp_column="created_at",
)
