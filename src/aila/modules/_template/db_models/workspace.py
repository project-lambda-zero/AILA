"""Workspace table scaffold demonstrating the RFC-01 base-subclass pattern.

Shared columns live on ``aila.platform.contracts.workspace_base``; the
concrete below only sets ``__tablename__``. No FK tablename ClassVars
and no residue -- the workspace base needs neither.
"""
from __future__ import annotations

from aila.platform.contracts.workspace_base import WorkspaceRecordBase

__all__ = ["TemplateWorkspaceRecord"]


class TemplateWorkspaceRecord(WorkspaceRecordBase, table=True):
    """Scaffold: a thematic project grouping related template targets."""

    __tablename__ = "template_workspaces"
