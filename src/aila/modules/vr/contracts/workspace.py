"""Workspace contracts for the vulnerability research module.

A VRWorkspace is a thematic project (D-49) — e.g. "Browser engines",
"Linux kernel", "Industrial controllers". It owns one or more VRTargets
and is the unit at which patterns/audit-memos can be scoped above the
single-investigation level.
"""
from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "VRWorkspaceCreate",
    "VRWorkspacePatch",
    "VRWorkspaceSummary",
    "WorkspaceStatus",
    "WorkspaceTheme",
]


class WorkspaceStatus(StrEnum):
    """Lifecycle states for a workspace."""

    ACTIVE = "active"
    ARCHIVED = "archived"


class WorkspaceTheme(StrEnum):
    """Suggested theme buckets for grouping related targets (D-49).

    The set is open — operators can create CUSTOM workspaces for any
    thematic area. The pre-seeded themes match the default workspace
    suggestions in D-49 so the UI can pre-fill icons/colors.
    """

    BROWSER_ENGINES = "browser_engines"
    LINUX_KERNEL = "linux_kernel"
    CONTAINER_RUNTIMES = "container_runtimes"
    INDUSTRIAL_SCADA = "industrial_scada"
    MOBILE_BASEBAND = "mobile_baseband"
    CUSTOM = "custom"


class VRWorkspaceCreate(BaseModel):
    """Input payload for creating a workspace via POST /api/vr/workspaces."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)
    slug: str = Field(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z0-9][a-z0-9_-]*$",
        description="URL-safe identifier. Lowercase alphanumeric + hyphen/underscore.",
    )
    description: str = Field(default="", max_length=4096)
    theme: WorkspaceTheme = Field(default=WorkspaceTheme.CUSTOM)


class VRWorkspaceSummary(BaseModel):
    """Read-only projection of a workspace for list + detail views."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    slug: str
    description: str
    theme: WorkspaceTheme
    status: WorkspaceStatus
    target_count: int = 0
    active_investigation_count: int = 0
    created_at: str | None = None
    updated_at: str | None = None


class VRWorkspacePatch(BaseModel):
    """Partial-update payload for PATCH /api/vr/workspaces/{id}.

    Slug is immutable (URL-safe identifier is contract). Theme can be
    re-themed for UI grouping. Status flips between active / archived.
    """

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, min_length=1, max_length=255)
    description: str | None = Field(default=None, max_length=4096)
    theme: WorkspaceTheme | None = None
    status: WorkspaceStatus | None = None
