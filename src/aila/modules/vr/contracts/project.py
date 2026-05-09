"""Project-level contract models for the vulnerability research module."""
from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "InputSource",
    "TargetClass",
    "TargetFormat",
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
    ANDROID = "android"
    IOS = "ios"
    DOTNET = "dotnet"


class TargetFormat(StrEnum):
    """Concrete container/binary format of an ingested target."""

    ELF = "elf"
    PE_EXE = "pe_exe"
    PE_DLL = "pe_dll"
    PE_SYS = "pe_sys"
    MACHO = "macho"
    APK = "apk"
    IPA = "ipa"
    JAR = "jar"
    WAR = "war"
    AAR = "aar"
    DOTNET = "dotnet"
    SOURCE_ARCHIVE = "source_archive"
    SOURCE_TREE = "source_tree"
    GIT_REPO = "git_repo"
    RAW_BINARY = "raw_binary"


class InputSource(StrEnum):
    """How the target reaches AILA before transfer to the analysis workstation."""

    UPLOAD = "upload"
    GIT_REPO = "git_repo"
    HTTP_URL = "http_url"


class VRTarget(BaseModel):
    """Description of a single analysis target across all supported input modes."""

    model_config = ConfigDict(extra="forbid")

    input_source: InputSource = Field(description="How the target is provided to AILA.")
    target_format: TargetFormat | None = Field(
        default=None,
        description="Binary/archive format. Auto-detected from content if not set.",
    )
    target_class: TargetClass = Field(default=TargetClass.NATIVE)
    source_available: bool = Field(default=False)

    # Upload input — set after multipart file lands on AILA server
    upload_filename: str | None = Field(
        default=None,
        description="Server-side filename after upload. Set by the API, not the caller.",
    )
    upload_sha256: str | None = Field(
        default=None,
        description="SHA256 of uploaded content. Set by the API.",
    )

    # Git repo input
    repo_url: str | None = Field(
        default=None,
        description="Git repository URL (https or ssh). Required when input_source=git_repo.",
    )
    vulnerable_ref: str | None = Field(
        default=None,
        description="Git ref (commit, tag, branch) for the vulnerable version.",
    )
    patched_ref: str | None = Field(
        default=None,
        description="Git ref for the patched version. Enables differential analysis.",
    )
    build_command: str | None = Field(
        default=None,
        description="Shell command to build the target from source (e.g., 'make -j4').",
    )
    build_artifact: str | None = Field(
        default=None,
        description="Relative path to the built binary within the repo (e.g., 'src/.libs/libfoo.so').",
    )

    # HTTP URL input
    download_url: str | None = Field(
        default=None,
        description="HTTPS URL to download the target from. Required when input_source=http_url.",
    )

    # Pre-existing MCP handle (skip upload entirely)
    binary_id: str | None = Field(
        default=None,
        description="Existing MCP binary_id. When set, skips upload/transfer.",
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
    analysis_system_id: int = Field(
        description="ManagedSystem ID for the IDA analysis workstation.",
    )
    poc_system_id: int | None = Field(
        default=None,
        description="ManagedSystem ID for PoC execution. Defaults to analysis_system_id if not set.",
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
    input_source: str | None = None
    target_format: str | None = None
    finding_count: int = 0
    created_at: str | None = None
