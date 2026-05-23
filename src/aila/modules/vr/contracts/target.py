"""Target contracts (v0.4.5 — backend-managed ingestion).

The operator never provides or sees MCP-internal ids. Per-kind
descriptor carries only what the operator actually knows:

  source_repo:      repo_url, ref
  native_binary:    binary_path (or uploaded file ref)
  kernel_image:     image_path, kernel_version, arch
  kernel_module:    ko_path, module_name
  hypervisor_image: binary_path, hypervisor_kind, version
  cve:              cve_id, vendor
  protocol_capture: pcap_path, protocol
  crash_input:      crash_artifact_path, parent_finding_id
  patch_diff:       vulnerable_ref, patched_ref, repo_url

The backend ingests the artifact via TargetAnalysisService (calls
audit_mcp.index_codebase / ida.upload / etc.), stores the resulting
internal handles privately, and surfaces analysis_state to the UI.
"""
from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "AnalysisState",
    "TargetKind",
    "TargetStatus",
    "TargetTag",
    "TargetTagSource",
    "VRTargetCreate",
    "VRTargetPatch",
    "VRTargetSummary",
]


class TargetKind(StrEnum):
    """What kind of artifact the target represents (D-45, v0.5 GA-54)."""

    NATIVE_BINARY = "native_binary"
    SOURCE_REPO = "source_repo"
    CVE = "cve"
    PROTOCOL_CAPTURE = "protocol_capture"
    CRASH_INPUT = "crash_input"
    PATCH_DIFF = "patch_diff"
    APK = "apk"
    IPA = "ipa"
    JAR = "jar"
    DOTNET_ASSEMBLY = "dotnet_assembly"
    # v0.5 GA-54 — kernel + hypervisor target kinds
    KERNEL_IMAGE = "kernel_image"
    KERNEL_MODULE = "kernel_module"
    HYPERVISOR_IMAGE = "hypervisor_image"


class TargetStatus(StrEnum):
    """Operator lifecycle state."""

    ACTIVE = "active"
    ARCHIVED = "archived"
    QUARANTINED = "quarantined"


class AnalysisState(StrEnum):
    """Backend ingestion + capability-profile lifecycle (v0.4.5).

    Operator-facing — the UI renders each value as a clear sentence
    ('Pulling from GitHub…' / 'Analyzing in IDA…' / 'Ready' /
    'Failed: <reason>'). Code reads the enum; UI never shows the
    raw value.
    """

    PENDING = "pending"        # created, ingestion not yet started
    INGESTING = "ingesting"    # uploading / cloning / indexing in progress
    READY = "ready"            # backend handles populated, ready for use
    FAILED = "failed"          # ingestion errored; analysis_state_message has the reason


class TargetTagSource(StrEnum):
    """Provenance of a tag attached to a target (D-52)."""

    OPERATOR = "operator"
    SYSTEM = "system"
    PATTERN = "pattern"


class TargetTag(BaseModel):
    """One tag entry — combines string label with provenance."""

    model_config = ConfigDict(extra="forbid")

    tag: str = Field(min_length=1, max_length=128)
    source: TargetTagSource = TargetTagSource.OPERATOR


class VRTargetCreate(BaseModel):
    """Operator-supplied fields for a new target.

    The descriptor carries ONLY operator-known fields. Backend ingests
    via TargetAnalysisService asynchronously.
    """

    model_config = ConfigDict(extra="forbid")

    workspace_id: str = Field(min_length=1, max_length=64)
    display_name: str = Field(min_length=1, max_length=255)
    kind: TargetKind
    descriptor: dict[str, Any] = Field(
        default_factory=dict,
        description=(
            "Kind-specific operator-known fields. NEVER contains "
            "backend MCP ids — those are populated automatically."
        ),
    )
    primary_language: str | None = Field(
        default=None,
        max_length=32,
        description=(
            "Optional — backend auto-detects post-ingestion when omitted."
        ),
    )
    secondary_languages: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)


class VRTargetSummary(BaseModel):
    """Read-only projection."""

    model_config = ConfigDict(extra="forbid")

    id: str
    workspace_id: str
    workspace_name: str | None = None
    display_name: str
    kind: TargetKind
    descriptor: dict[str, Any] = Field(default_factory=dict)
    uploaded_filename: str | None = Field(
        default=None,
        description=(
            "When the operator uploaded a binary via POST /vr/targets/{id}/upload, "
            "this is the original filename. None otherwise. Projected from "
            "the backend-internal mcp_handles_json — never settable directly."
        ),
    )
    primary_language: str | None = None
    secondary_languages: list[str] = Field(default_factory=list)
    status: TargetStatus
    analysis_state: AnalysisState
    analysis_state_message: str | None = None
    analysis_started_at: str | None = None
    analysis_completed_at: str | None = None
    analysis_stages: dict[str, Any] | None = Field(
        default=None,
        description=(
            "Per-stage analysis status — ingestion / capability_profile / "
            "function_ranking. Each stage carries its own state (pending / "
            "running / done / failed), started_at, completed_at, attempts, "
            "and error message. UI uses this to show progress + offer "
            "stage-level resume. Migration 060 + StageTracker."
        ),
    )
    tags: list[TargetTag] = Field(default_factory=list)
    created_at: str | None = None
    updated_at: str | None = None


class VRTargetPatch(BaseModel):
    """Operator-mutable fields. ``workspace_id``, ``kind``, ``descriptor``
    are immutable after creation — recreate the target instead."""

    model_config = ConfigDict(extra="forbid")

    display_name: str | None = Field(default=None, min_length=1, max_length=255)
    primary_language: str | None = Field(default=None, max_length=32)
    secondary_languages: list[str] | None = None
    status: TargetStatus | None = None
    tags: list[str] | None = None
