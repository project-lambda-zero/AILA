"""VR branch manager -- thin binding of the platform BranchPool (RFC-03 Phase 3).

The branch-tree transitions (fork / merge / promote / abandon / pause /
resume) and the fork cap live once in
``aila.platform.agents.branch_pool``. This module binds the VR record
models and config namespace; ``BranchManagerError`` and ``BranchOpResult``
are re-exported so existing callers keep their import surface.
"""
from __future__ import annotations

from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationRecord,
)
from aila.platform.agents.branch_pool import (
    BranchManagerError,
    BranchOpResult,
    BranchPool,
)

__all__ = [
    "BranchManager",
    "BranchManagerError",
    "BranchOpResult",
]


class BranchManager(BranchPool):
    """VR-bound per-investigation branch operations."""

    def __init__(self, investigation_id: str) -> None:
        super().__init__(
            investigation_id,
            branch_model=VRInvestigationBranchRecord,
            investigation_model=VRInvestigationRecord,
            module_id="vr",
        )
