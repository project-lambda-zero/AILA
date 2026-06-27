"""Typed Pydantic input models for every workflow state.

Replaces the implicit `input.get("foo", default)` pattern where missing kwargs
silently degraded to empty strings or wrong types -- the bug class that caused
the runaway `Get-ChildItem -Recurse -Path ''` wedge and the forever-pending
investigations. Each state handler now parses its input into one of these
models up-front, so a missing field raises ValidationError with a clear
message instead of hanging later.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "IntakeInput",
    "CollectionInput",
    "DeepAnalysisInput",
    "FreeFlowInput",
    "WriteUpInput",
]


class _WorkflowInputBase(BaseModel):
    # Allow unknown keys so upstream dispatchers can pass extra context without
    # breaking, but keep the declared fields typed.
    model_config = ConfigDict(extra="allow")


class IntakeInput(_WorkflowInputBase):
    project_id: str = Field(min_length=1)
    evidence_directory: str = Field(
        min_length=1,
        description="Absolute path on the analyzer. Empty/whitespace values "
        "are rejected to prevent runaway recursive scans.",
    )
    integration: dict[str, Any] = Field(default_factory=dict)
    analyzer_os: str = Field(default="linux")
    project_kind: str = Field(default="disk_evidence")


class CollectionInput(_WorkflowInputBase):
    project_id: str = Field(min_length=1)
    evidence_files: list[dict[str, Any]] = Field(default_factory=list)
    active_lanes: list[str] = Field(default_factory=list)
    integration: dict[str, Any] = Field(default_factory=dict)
    analyzer_os: str = Field(default="linux")
    evidence_directory: str = ""


class DeepAnalysisInput(_WorkflowInputBase):
    project_id: str = Field(min_length=1)
    evidence_files: list[dict[str, Any]] = Field(default_factory=list)
    integration: dict[str, Any] = Field(default_factory=dict)
    analyzer_os: str = Field(default="linux")
    evidence_directory: str = ""


class FreeFlowInput(_WorkflowInputBase):
    investigation_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    question: str = Field(min_length=1)
    max_attempts: int = Field(default=10, ge=1, le=100)
    integration: dict[str, Any] = Field(default_factory=dict)
    analyzer_os: str = Field(default="linux")
    # Set when this investigation was started via "Rerun (enriched)".
    # The investigator boots, hydrates self.observables from the parent's
    # persisted artifact rows, and prepends a one-shot prior-attempt
    # summary into the first turn's prompt.
    parent_investigation_id: str | None = None


class WriteUpInput(_WorkflowInputBase):
    investigation_id: str = Field(min_length=1)
    project_id: str = Field(min_length=1)
    answer: str | None = None
    confidence: str = "caveated"
    attempts_used: int = 0
    steps: list[dict[str, Any]] = Field(default_factory=list)
