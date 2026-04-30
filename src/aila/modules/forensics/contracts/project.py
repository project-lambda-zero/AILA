"""Project-level contract models for the forensics module."""
from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "AnalyzerOS",
    "EvidenceItem",
    "EvidenceType",
    "ProjectCreate",
    "ProjectKind",
    "ProjectSummary",
]


class AnalyzerOS(str, Enum):
    """Operating system of the analyzer machine."""

    LINUX = "linux"
    WINDOWS = "windows"


class ProjectKind(str, Enum):
    """High-level shape of the evidence the project points at.

    ``disk_evidence`` is the default: the evidence directory contains
    disk images, memory dumps, pcaps, etc. and the full-analysis
    pipeline (intake -> collection -> deep_analysis -> promotion) runs.

    ``raw_directory`` means the evidence directory itself IS the
    artefact (a Linux rootfs copy, a loose bag of logs, an exported
    container filesystem). Intake enumerates the files, the
    pre/full-analysis lanes are skipped entirely, and the free-flow
    investigator reads files directly off the analyzer filesystem.
    """

    DISK_EVIDENCE = "disk_evidence"
    RAW_DIRECTORY = "raw_directory"


class EvidenceType(str, Enum):
    """Classification of forensic evidence files."""

    DISK_IMAGE = "disk_image"
    MEMORY_DUMP = "memory_dump"
    PCAP = "pcap"
    EXTRACTED_DIR = "extracted_dir"
    LOG_FILE = "log_file"
    CONTAINER_DUMP = "container_dump"
    FIRMWARE = "firmware"
    TEXT_FILE = "text_file"
    RAW_FILE = "raw_file"
    ARCHIVE = "archive"
    UNKNOWN = "unknown"


class ProjectCreate(BaseModel):
    """Input payload for creating a new forensics project."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=255)
    description: str = Field(default="")
    system_id: int = Field(description="ID of the registered analyzer machine.")
    evidence_directory: str = Field(
        min_length=1,
        description="Absolute path to evidence on the analyzer machine.",
    )
    analyzer_os: AnalyzerOS = Field(
        default=AnalyzerOS.LINUX,
        description="Operating system of the analyzer machine.",
    )
    project_kind: ProjectKind = Field(
        default=ProjectKind.DISK_EVIDENCE,
        description=(
            "Shape of the evidence. Use raw_directory to skip "
            "disk-image parsing and pre/full-analysis entirely."
        ),
    )


class EvidenceItem(BaseModel):
    """Summary of a single evidence file discovered during intake."""

    model_config = ConfigDict(extra="forbid")

    id: str
    file_path: str
    evidence_type: EvidenceType
    file_hash_sha256: str | None = None
    size_bytes: int | None = None


class ProjectSummary(BaseModel):
    """Read-only summary of a forensics project."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    description: str
    system_id: int
    system_name: str | None = None
    evidence_directory: str
    analyzer_os: str = "linux"
    project_kind: str = "disk_evidence"
    status: str
    evidence_count: int = 0
    artifact_count: int = 0
    lead_count: int = 0
    investigation_count: int = 0
    created_at: datetime | None = None
    updated_at: datetime | None = None
