"""VR binding of the platform orphan-branch reaper.

Binds the platform sweep to the VR record models. Kept as a module-level
``functools.partial`` so the registered periodic-sweep callable is a stable
object across re-imports (the sweep registry keys re-registration on callable
identity, so an inline partial at the registration site would break the
re-registration no-op).
"""
from __future__ import annotations

from functools import partial

from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationRecord,
)
from aila.platform.services.branch_reaper import (
    sweep_orphan_active_branches as _platform_sweep,
)

__all__ = ["sweep_orphan_active_branches"]

sweep_orphan_active_branches = partial(
    _platform_sweep,
    branch_model=VRInvestigationBranchRecord,
    investigation_model=VRInvestigationRecord,
)
