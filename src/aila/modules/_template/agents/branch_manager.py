"""Template branch manager -- thin binding of the platform BranchPool.

The 6 branch-tree transitions (fork / merge / promote / abandon / pause
/ resume) and the fork cap live on
:mod:`aila.platform.agents.branch_pool`. This module binds the template
record models + config namespace; ``BranchManagerError`` and
``BranchOpResult`` are re-exported so callers keep their import surface.
"""
from __future__ import annotations

from aila.modules._template.db_models import (
    TemplateInvestigationBranchRecord,
    TemplateInvestigationRecord,
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
    """Template-bound per-investigation branch operations."""

    def __init__(self, investigation_id: str) -> None:
        super().__init__(
            investigation_id,
            branch_model=TemplateInvestigationBranchRecord,
            investigation_model=TemplateInvestigationRecord,
            module_id="template",
        )
