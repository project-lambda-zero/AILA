"""Target contracts for the vulnerability research module.

A VRTarget is a first-class persistent target identity (D-49/D-50). It
lives inside a workspace and is referenced by investigations, fuzzing
campaigns, findings, and disclosures. Capability profile (D-51) and
tags (D-52) are stored as JSON on the target record.

Note: this is distinct from the v0.1 ``VRTarget`` ingestion payload in
``contracts/project.py``, which describes HOW a binary gets onto the
analysis workstation. The v0.1 ingestion payload is being phased out as
part of the M3.T-1 -> M3.T-4 refactor: the new persistent
``VRTargetRecord`` owns target identity, while ingestion concerns will
move to a dedicated TargetIngestionSpec contract.
"""
from __future__ import annotations

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "EnrichmentStatus",
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
    """Lifecycle states for a target."""

    ACTIVE = "active"
    ARCHIVED = "archived"
    QUARANTINED = "quarantined"


class EnrichmentStatus(StrEnum):
    """State of the M3.T enrichment pipeline for this target."""

    UNENRICHED = "unenriched"
    RUNNING = "running"
    COMPLETE = "complete"
    FAILED = "failed"


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
    """Input payload for creating a persistent target.

    The ``descriptor`` field shape depends on ``kind``:
      - NATIVE_BINARY: {"binary_path": str, "version": str | None}
      - SOURCE_REPO:   {"repo_url": str, "ref": str | None}
      - CVE:           {"cve_id": str, "vendor": str | None}
      - PROTOCOL_CAPTURE: {"pcap_path": str, "protocol": str}
      - CRASH_INPUT:   {"crash_artifact_path": str, "parent_finding_id": str | None}
      - PATCH_DIFF:    {"vulnerable_ref": str, "patched_ref": str, "repo_url": str}

    The shape is validated kind-by-kind in the runtime layer, not in the
    contract, because the kind set will grow over time and per-kind
    Pydantic discriminated unions create churn we don't want yet.
    """

    model_config = ConfigDict(extra="forbid")

    workspace_id: str = Field(min_length=1, max_length=64)
    display_name: str = Field(min_length=1, max_length=255)
    kind: TargetKind
    descriptor: dict[str, Any] = Field(
        default_factory=dict,
        description="Kind-specific identification fields. Shape depends on kind.",
    )
    primary_language: str | None = Field(default=None, max_length=32)
    secondary_languages: list[str] = Field(default_factory=list)
    tags: list[str] = Field(
        default_factory=list,
        description="Operator-supplied tags at creation time. System + pattern tags are added later by enrichment.",
    )


class VRTargetSummary(BaseModel):
    """Read-only projection of a target for list + detail views."""

    model_config = ConfigDict(extra="forbid")

    id: str
    workspace_id: str
    display_name: str
    kind: TargetKind
    descriptor: dict[str, Any] = Field(default_factory=dict)
    primary_language: str | None = None
    secondary_languages: list[str] = Field(default_factory=list)
    status: TargetStatus
    enrichment_status: EnrichmentStatus
    last_enriched_at: str | None = None
    tags: list[TargetTag] = Field(default_factory=list)
    created_at: str | None = None
    updated_at: str | None = None


class VRTargetPatch(BaseModel):
    """Partial-update payload for PATCH /api/vr/targets/{id}.

    Immutable after creation: ``workspace_id`` (move-between-workspaces
    needs a separate endpoint), ``kind`` (would invalidate
    capability_profile + ranking + investigations), ``descriptor``
    (identity field of the target — rebuild instead).

    Mutable here:
      - display_name: rename for UX
      - primary_language / secondary_languages: re-tag once detected
      - status: archive / quarantine / reactivate
      - tags: replace operator-supplied tag set (system + pattern tags
        survive via tag_index regen)
    """

    model_config = ConfigDict(extra="forbid")

    display_name: str | None = Field(default=None, min_length=1, max_length=255)
    primary_language: str | None = Field(default=None, max_length=32)
    secondary_languages: list[str] | None = None
    status: TargetStatus | None = None
    tags: list[str] | None = None
