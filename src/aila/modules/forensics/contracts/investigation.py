"""Investigation contract models for the forensics module."""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from aila.platform.contracts.reasoning import (
    ReasoningEvidenceGraph,
    ReasoningGraphDiff,
 )

__all__ = [
    "AgentStep",
    "ForensicsOptions",
    "ForensicsPayload",
    "InvestigationRequest",
    "ReasoningGraphDiffResult",
    "ReasoningGraphSnapshot",
    "WriteUp",
]


class ForensicsPayload(BaseModel):
    """Input payload for a forensics module action request."""

    model_config = ConfigDict(extra="forbid")

    project_id: str = Field(default="")
    question: str = Field(default="")


class ForensicsOptions(BaseModel):
    """Runtime options for a forensics module action."""

    model_config = ConfigDict(extra="forbid")

    max_attempts: int = Field(default=10, ge=1, le=50)
    force_refresh: bool = False


class InvestigationRequest(BaseModel):
    """Request to start a free-flow investigation."""

    model_config = ConfigDict(extra="forbid")

    question: str = Field(min_length=1)
    max_attempts: int = Field(default=10, ge=1, le=50)


class AgentStep(BaseModel):
    """A single step taken by the free-flow agent.

    The honest investigator persists its case-model snapshot inside the
    ``reasoning`` column as JSON. The API layer parses that blob and
    surfaces the structured fields below to the frontend so the UI can
    render contract/hypotheses/observables panels without re-parsing.
    """

    model_config = ConfigDict(extra="forbid")

    id: str
    step_number: int
    action: str
    script_content: str | None = None
    command: str | None = None
    stdout: str | None = None
    stderr: str | None = None
    exit_code: int | None = None
    reasoning: str
    created_at: datetime | None = None
    contract: dict | None = None
    hypotheses: list[dict] = Field(default_factory=list)
    rejected: list[dict] = Field(default_factory=list)
    observables: dict | None = None
    provenance: dict | None = None
    expected_observation: str | None = None
    submitted: bool = False


class ReasoningGraphSnapshot(BaseModel):
    """One durable reasoning graph snapshot for an investigation turn."""

    model_config = ConfigDict(extra="forbid")

    id: str
    run_id: str | None = None
    module_id: str
    subject_kind: str
    subject_id: str
    step_number: int
    strategy_family: str
    graph: ReasoningEvidenceGraph
    created_at: datetime | None = None
    updated_at: datetime | None = None


class ReasoningGraphDiffResult(BaseModel):
    """API-facing diff between two reasoning graph snapshots."""

    model_config = ConfigDict(extra="forbid")

    investigation_id: str
    diff: ReasoningGraphDiff


class WriteUp(BaseModel):
    """Professional forensic investigation write-up."""
    """Professional forensic investigation write-up."""

    model_config = ConfigDict(extra="forbid")

    id: str
    project_id: str
    investigation_id: str | None = None
    title: str
    content_markdown: str
    methodology: str
    artifacts_referenced: list[str] = Field(default_factory=list)
    created_at: datetime | None = None
