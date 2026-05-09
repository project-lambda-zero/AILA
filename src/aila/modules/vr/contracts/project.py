"""Project-level contract models for the vulnerability research module."""
from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "TargetClass",
    "VRProjectCreate",
    "VRProjectStatus",
    "VRProjectSummary",
    "VRTarget",
]


class TargetClass(StrEnum):
    """Runtime/language family of the analysis target (D-03)."""

    NATIVE = "native"
    KERNEL = "kernel"
    HYPERVISOR = "hypervisor"
    JVM = "jvm"
    PYTHON = "python"
    JAVASCRIPT = "javascript"
    PHP = "php"
    GO = "go"
    RUST = "rust"


class VRTarget(BaseModel):
    """Pointer to a single analysis target (binary, source tree, or URL)."""

    model_config = ConfigDict(extra="forbid")

    path: str = Field(description="Filesystem path or URL of the target.")
    target_class: TargetClass = Field(default=TargetClass.NATIVE)
    source_available: bool = Field(default=False)
    binary_id: str | None = Field(
        default=None,
        description="MCP handle returned after upload to the analysis backend.",
    )


class VRProjectCreate(BaseModel):
    """Input payload for creating a new VR project."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)
    cve_id: str | None = Field(
        default=None,
        description="Existing CVE identifier (CVE-YYYY-NNNNN) when reproducing a known issue.",
    )
    target: VRTarget
    patched_target: VRTarget | None = Field(
        default=None,
        description="Optional patched build used for differential analysis and PoC validation.",
    )
    context_notes: str = Field(
        default="",
        description="Operator-supplied free-form context for the agent.",
    )


class VRProjectStatus(StrEnum):
    """Lifecycle states for a VR project run."""

    CREATED = "created"
    ANALYZING = "analyzing"
    COMPLETED = "completed"
    FAILED = "failed"
    STALLED = "stalled"


class VRProjectSummary(BaseModel):
    """Read-only summary of a VR project."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    cve_id: str | None = None
    status: VRProjectStatus
    target_class: TargetClass
    finding_count: int = 0
    created_at: str | None = None
