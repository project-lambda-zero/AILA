"""Workflow-internal types for the forensics module.

These types are shared between state handlers and the workflow services
but are NOT part of the module's public contract surface.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "CollectionOutput",
    "EvidenceClassification",
    "FreeflowOutput",
    "IntakeOutput",
    "PromotionOutput",
    "ResolutionOutput",
    "WriteupOutput",
]


@dataclass(slots=True)
class EvidenceClassification:
    """Classification of a single evidence file."""

    file_path: str
    evidence_type: str
    size_bytes: int = 0
    file_hash: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class IntakeOutput:
    """Output from the evidence intake state."""

    project_id: str
    evidence_files: list[EvidenceClassification] = field(default_factory=list)
    active_lanes: list[str] = field(default_factory=list)


@dataclass(slots=True)
class CollectionOutput:
    """Output from the artifact collection state."""

    project_id: str
    artifact_count: int = 0
    artifacts_by_family: dict[str, int] = field(default_factory=dict)


@dataclass(slots=True)
class PromotionOutput:
    """Output from the lead promotion state."""

    project_id: str
    lead_count: int = 0
    top_leads: list[dict[str, Any]] = field(default_factory=list)


@dataclass(slots=True)
class ResolutionOutput:
    """Output from the question resolution state."""

    project_id: str
    answers_found: int = 0
    questions_mapped: int = 0


@dataclass(slots=True)
class FreeflowOutput:
    """Output from the free-flow investigation state."""

    investigation_id: str
    project_id: str
    question: str
    attempts_used: int = 0
    answer: str | None = None
    confidence: str = "caveated"
    steps: list[dict[str, Any]] = field(default_factory=list)


@dataclass(slots=True)
class WriteupOutput:
    """Output from the write-up generation state."""

    writeup_id: str
    project_id: str
    title: str = ""
