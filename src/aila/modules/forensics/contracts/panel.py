"""Read models for the forensics panel drill-down."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "ForensicsPanelBranch",
    "ForensicsPanelMessage",
    "ForensicsPanelOutcome",
    "ForensicsPanelReview",
    "ForensicsPanelView",
]


class ForensicsPanelBranch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    persona_voice: str
    status: str
    turn_count: int
    closed_reason: str | None = None
    created_at: datetime | None = None


class ForensicsPanelReview(BaseModel):
    model_config = ConfigDict(extra="forbid")

    reviewer_branch_id: str
    reviewer_persona: str
    vote: str
    comment: str


class ForensicsPanelOutcome(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    branch_id: str
    proposer_persona: str
    state: str
    confidence: str
    answer: str
    provenance: dict[str, Any] = Field(default_factory=dict)
    contributions: list[dict[str, Any]] = Field(default_factory=list)
    reviews: list[ForensicsPanelReview] = Field(default_factory=list)
    created_at: datetime | None = None


class ForensicsPanelMessage(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    branch_id: str
    persona_voice: str
    sender_kind: str
    payload_kind: str
    at_turn: int | None = None
    text: str
    action: str | None = None
    command: str | None = None
    stdout: str | None = None
    stderr: str | None = None
    exit_code: int | None = None
    created_at: datetime | None = None


class ForensicsPanelView(BaseModel):
    model_config = ConfigDict(extra="forbid")

    investigation_id: str
    branches: list[ForensicsPanelBranch] = Field(default_factory=list)
    outcomes: list[ForensicsPanelOutcome] = Field(default_factory=list)
    messages: list[ForensicsPanelMessage] = Field(default_factory=list)
