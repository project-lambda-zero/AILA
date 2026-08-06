"""Panel investigation branch -- forensics concrete (#18).

All columns come from the shared platform base; see
:mod:`aila.platform.contracts.branch_base`. ``parent_branch_id`` and
``merged_into_branch_id`` are self-referential foreign keys derived against
this table's own name.

Added in #18 (forensics: workflow is outdated) to give the forensics module
the same panel-of-roles + sibling-review-quorum spine that VR and malware
run on. The existing ``forensics_investigations`` row is the parent
investigation; each panel role runs on its own branch row here.
"""
from __future__ import annotations

from aila.platform.contracts.branch_base import BranchRecordBase

__all__ = ["ForensicsInvestigationBranchRecord"]


class ForensicsInvestigationBranchRecord(BranchRecordBase, table=True):
    """One branch within a forensics panel investigation (#18)."""

    __tablename__ = "forensics_investigation_branches"
    __investigation_tablename__ = "forensics_investigations"
