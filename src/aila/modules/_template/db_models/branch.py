"""Investigation-branch table scaffold demonstrating the RFC-01 base-subclass pattern.

Shared columns live on ``aila.platform.contracts.branch_base``; the
concrete below sets ``__tablename__`` + ``__investigation_tablename__``.
The ``parent_branch_id`` / ``merged_into_branch_id`` FKs are
self-referential and derived by the base against this class's own
``__tablename__`` -- no ClassVars needed for them.
"""
from __future__ import annotations

from typing import ClassVar

from aila.platform.contracts.branch_base import BranchRecordBase

__all__ = ["TemplateInvestigationBranchRecord"]


class TemplateInvestigationBranchRecord(BranchRecordBase, table=True):
    """Scaffold: one branch within an investigation."""

    __tablename__ = "template_investigation_branches"
    __investigation_tablename__: ClassVar[str] = "template_investigations"
