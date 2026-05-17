"""Public contracts for fuzz campaign proposals."""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "FuzzProposalDecideAccept",
    "FuzzProposalDecideReject",
    "FuzzProposalStatus",
    "SeedCorpusEntry",
    "VRFuzzCampaignProposalSummary",
]


class FuzzProposalStatus(StrEnum):
    """Lifecycle states of a fuzz campaign proposal."""

    PENDING = "pending"
    ACCEPTED = "accepted"
    REJECTED = "rejected"
    SUPERSEDED = "superseded"


class SeedCorpusEntry(BaseModel):
    """One seed corpus file the proposal ships."""

    model_config = ConfigDict(extra="forbid")

    filename: str = Field(min_length=1, max_length=255)
    content_base64: str = Field(min_length=1)
    notes: str = ""


class VRFuzzCampaignProposalSummary(BaseModel):
    """Read projection of one proposal — what the UI renders."""

    model_config = ConfigDict(extra="forbid")

    id: str
    investigation_id: str
    outcome_id: str
    target_id: str
    workspace_id: str

    profile: str
    rationale: str = ""
    confidence: str = "medium"
    target_descriptor: dict[str, Any] = Field(default_factory=dict)

    suggested_engine_id: str | None = None
    suggested_engine_config: dict[str, Any] = Field(default_factory=dict)
    suggested_strategy_id: str | None = None
    suggested_duration_hours: int | None = None

    # Pre-fuzz prep authored by the agent.
    harness_source: str | None = None
    harness_language: str | None = None
    harness_build_command: str | None = None
    harness_target_path: str | None = None
    seed_corpus: list[SeedCorpusEntry] = Field(default_factory=list)
    dictionary_content: str | None = None

    status: FuzzProposalStatus
    accepted_campaign_id: str | None = None
    decided_at: datetime | None = None
    decided_by: str | None = None
    decision_reason: str | None = None
    prepare_log: str | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None


class FuzzProposalDecideAccept(BaseModel):
    """Accept a proposal → ProposalPreparer SSHes the workstation,
    writes the harness + seeds, runs the build, creates a campaign,
    and optionally launches.

    Every field is optional — the resolved defaults come from:
      - the proposal's `suggested_*` columns
      - the target's `capability_profile` (engine + strategy)
      - the project's `analysis_system_id` (workstation)

    Operator overrides any of them only when they want to deviate.
    `auto_launch` (default true — the whole point is one-click prep)
    enqueues `run_fuzz_campaign_launch` after the campaign row exists.
    """

    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(default=None, max_length=255)
    engine_id: str | None = Field(default=None, max_length=32)
    strategy_id: str | None = Field(default=None, max_length=32)
    engine_config: dict[str, Any] | None = None
    strategy_config: dict[str, Any] | None = None
    duration_hours: int | None = Field(default=None, ge=1, le=720)
    analysis_system_id: int | None = Field(default=None, ge=1)
    auto_launch: bool = True
    skip_prepare: bool = Field(
        default=False,
        description=(
            "When true, skip the SCP/build step — operator already "
            "has the harness on the workstation. Useful for re-accepts "
            "after a transient SSH failure."
        ),
    )
    decision_reason: str | None = Field(default=None, max_length=2048)


class FuzzProposalDecideReject(BaseModel):
    """Reject a proposal — reason captured for the audit trail."""

    model_config = ConfigDict(extra="forbid")

    decision_reason: str = Field(min_length=1, max_length=2048)
