"""Forensics binding of the investigation-scoped reconciler authority
(RFC-07 reconcile wave, L3.3 / L3.4).

Binds :func:`aila.platform.tasks.state_reconciler.sweep_investigations_reconcile`
to forensics's :class:`InvestigationRunRecord`, track, fn-path pattern,
and the submit primitive -- the same data the stuck healer binds. The
reconciler's per-task healing applies to every forensics investigate
task shape; its re-enqueue fallback uses the shared dispatch builder
:func:`~aila.modules.forensics.services.recovery_submit.prepare_recovery_submit`.
A stuck freeflow is re-driven from its project row; a branched
investigation with no active panel branch is refused and the reconciler
logs + skips the row.

``InvestigationRunRecord`` predates the platform ``InvestigationRecordBase``
and carries no ``updated_at`` column, so this binding claims rows on
``created_at`` (``timestamp_column``), mirroring the stuck-healer binding.

``sweep_investigations_reconcile`` is a module-level ``functools.partial``
so the periodic-sweep registry (which keys re-registration on callable
identity) sees a stable object across re-imports.

The pass itself is gated at runtime by
``platform.investigation_reconciler_periodic_enabled`` (default True)
inside the platform sweep callable; this file only declares the binding.
"""
from __future__ import annotations

from functools import partial

from aila.modules.forensics.db_models import (
    ForensicsInvestigationBranchRecord,
    InvestigationRunRecord,
)
from aila.modules.forensics.services.recovery_submit import prepare_recovery_submit
from aila.platform.tasks.state_reconciler import (
    InvestigationRecoveryBinding,
)
from aila.platform.tasks.state_reconciler import (
    sweep_investigations_reconcile as _platform_sweep,
)

__all__ = ["sweep_investigations_reconcile"]

# LIKE pattern catches both ``run_forensics_investigation`` (freeflow) and
# ``run_forensics_panel_investigate`` (panel) -- ``investigat`` sits inside
# both spellings so the stale-task cancel step reaches every in-flight
# forensics investigate task for this investigation (matches the stuck
# healer's cancel set).
_FORENSICS_INVESTIGATE_FN_PATTERN = "%run_forensics%investigat%"

# ``ForensicsInvestigationBranchRecord.status`` is a plain string column
# (branches predate the platform BranchStatus StrEnum for this module).
# The active value matches the string every other write site here uses.
_FORENSICS_BRANCH_ACTIVE = "active"


_FORENSICS_RECONCILE_BINDING = InvestigationRecoveryBinding(
    module_id="forensics",
    investigations_table="forensics_investigations",
    track="forensics",
    fn_path_pattern=_FORENSICS_INVESTIGATE_FN_PATTERN,
    inv_model=InvestigationRunRecord,
    prepare_submit=prepare_recovery_submit,
    # Fan out per active panel branch. With none active, the platform sends one
    # inv-level dispatch: prepare_recovery_submit re-drives a branchless row as
    # freeflow and refuses a row that has branch rows.
    branch_model=ForensicsInvestigationBranchRecord,
    branch_status_active=_FORENSICS_BRANCH_ACTIVE,
    # ``InvestigationRunRecord`` has no ``updated_at`` column; claim on
    # ``created_at`` (matches the stuck-healer binding).
    timestamp_column="created_at",
    # Forensics' status vocabulary diverges from the platform enum
    # (``pending`` / ``exhausted`` / ``cancelled``). The periodic sweep
    # claims ONLY ``running`` rows so non-live rows are never selected
    # and their ``created_at`` never drifts, and direct reconcile calls
    # refuse the forensics terminal statuses the platform enum does not
    # name.
    sweepable_statuses=("running",),
    extra_terminal_statuses=("cancelled", "exhausted"),
)

sweep_investigations_reconcile = partial(
    _platform_sweep,
    binding=_FORENSICS_RECONCILE_BINDING,
)
