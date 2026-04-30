"""Artifact contract models for the forensics module."""
from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "ArtifactFamily",
    "NormalizedArtifact",
    "PromotedLead",
]


class ArtifactFamily(str, Enum):
    """Top-level classification of normalized artifacts."""

    HOST = "host"
    USER = "user"
    EXECUTION = "execution"
    BROWSER = "browser"
    NETWORK = "network"
    MEMORY = "memory"
    MALWARE = "malware"
    LOG = "log"
    FILESYSTEM = "filesystem"
    CONTAINER = "container"
    CLOUD = "cloud"
    MOBILE = "mobile"
    FIRMWARE = "firmware"


class NormalizedArtifact(BaseModel):
    """A single normalized artifact extracted from evidence."""

    model_config = ConfigDict(extra="forbid")

    id: str
    project_id: str
    artifact_family: ArtifactFamily
    artifact_type: str
    source_tool: str
    source_evidence_id: str | None = None
    # Set when the artifact was emitted by the investigator agent at
    # answer-submission time. NULL for intake/full-analysis rows.
    source_investigation_id: str | None = None
    data: dict[str, object] = Field(default_factory=dict)
    lead_score: float | None = None


class LeadEvidence(BaseModel):
    """A single concrete evidence match backing a lead's reason."""

    model_config = ConfigDict(extra="forbid")

    keyword: str
    path: str
    excerpt: str


class PromotedLead(BaseModel):
    """A scored lead promoted from artifact analysis."""

    model_config = ConfigDict(extra="forbid")

    id: str
    project_id: str
    artifact_id: str
    score: float = Field(ge=0.0, le=100.0)
    reason: str
    artifact_family: ArtifactFamily
    artifact_type: str = ""
    source_tool: str | None = None
    evidence: list[LeadEvidence] = Field(default_factory=list)
    related_artifact_ids: list[str] = Field(default_factory=list)
    question_families: list[str] = Field(default_factory=list)
