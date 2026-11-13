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
  is re-driven from the project row by the shared
  :func:`~aila.modules.forensics.services.recovery_submit.prepare_recovery_submit`
  builder. A branched investigation with no active panel branch is
  refused (the per-id catch in the platform sweep logs and skips it).

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
from aila.modules.forensics.services.recovery_submit import prepare_recovery_submit
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


sweep_stuck_investigations = partial(
    _platform_sweep,
    inv_model=InvestigationRunRecord,
    running_status_values=_FORENSICS_RUNNING_STATUSES,
    fn_path_pattern=_FORENSICS_INVESTIGATE_FN_PATTERN,
    module_id="forensics",
    prepare_submit=prepare_recovery_submit,
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
