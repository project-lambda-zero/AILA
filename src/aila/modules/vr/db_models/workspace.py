"""Workspace table definition for the vulnerability research module.

Per D-49: a VRWorkspace groups related VRTargets under a thematic project
(browser engines, linux kernel, container runtimes, etc.). It owns the
scope for pattern promotion (D-43 GA-41) above the single-investigation
level.

Written by: POST /api/vr/workspaces.
Consumed by: workspace dashboard, target list per workspace, cross-target
pattern surfacing, investigation creation flow.

The shared columns live on the platform base (RFC-01); this module only
sets the concrete table name. VR carries no workspace residue.
"""
from __future__ import annotations

from aila.platform.contracts.workspace_base import WorkspaceRecordBase

__all__ = ["VRWorkspaceRecord"]


class VRWorkspaceRecord(WorkspaceRecordBase, table=True):
    """A thematic project grouping related VR targets (D-49)."""

    __tablename__ = "vr_workspaces"
