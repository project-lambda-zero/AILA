"""Per-stage target analysis status -- durable, recoverable, per-service (RFC-01).

Pre-this-contract every service that touched a target's analysis mutated the
single ``analysis_state`` column with "set ingesting -> do work -> set
ready/failed". That let a mid-work crash strand state at ``ingesting``, let a
later stage clear an earlier failure, and gave the operator no way to resume
from the last completed stage.

This contract replaces the single enum with a per-stage status struct. Each
service owns ONE stage and only touches that stage's record. The overall
``analysis_state`` becomes a derived roll-up (``failed`` if any stage failed,
``running`` if any stage running, ``pending`` if all pending, ``ready`` if
all done). Persisted as JSON on the target's ``analysis_stages_json`` column.
"""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from aila.platform.contracts.enums import AnalysisState, StageName, StageState

__all__ = [
    "StageName",
    "StageState",
    "StageStatus",
    "TargetAnalysisStages",
    "roll_up_overall_state",
]


class StageStatus(BaseModel):
    """Status of one analysis stage."""

    model_config = ConfigDict(frozen=False, extra="forbid")

    state: StageState = StageState.PENDING
    started_at: datetime | None = None
    completed_at: datetime | None = None
    attempts: int = 0
    error: str | None = None
    """The error message of the most recent failed attempt. Cleared when
    the stage transitions out of FAILED."""


class TargetAnalysisStages(BaseModel):
    """All stage statuses for one target.

    Persisted as JSON on the target's ``analysis_stages_json`` column.
    Operations on this struct are pure -- the persistence layer is in the
    module's StageTracker service.
    """

    model_config = ConfigDict(extra="ignore")

    ingestion: StageStatus = Field(default_factory=StageStatus)
    capability_profile: StageStatus = Field(default_factory=StageStatus)
    function_ranking: StageStatus = Field(default_factory=StageStatus)
    apk_decode: StageStatus = Field(default_factory=StageStatus)
    jadx_decompile: StageStatus = Field(default_factory=StageStatus)
    react_native_extract: StageStatus = Field(default_factory=StageStatus)
    index_decompiled: StageStatus = Field(default_factory=StageStatus)
    static_summary: StageStatus = Field(default_factory=StageStatus)
    mobsf_scan: StageStatus = Field(default_factory=StageStatus)

    def get(self, stage: StageName) -> StageStatus:
        return getattr(self, stage.value)

    def set(self, stage: StageName, status: StageStatus) -> None:
        setattr(self, stage.value, status)

    def all_stages(self) -> list[tuple[StageName, StageStatus]]:
        return [(s, self.get(s)) for s in StageName]


def roll_up_overall_state(stages: TargetAnalysisStages) -> AnalysisState:
    """Compute the overall ``analysis_state`` enum from per-stage states.

    Priority (highest precedence first):
      - FAILED if any stage is FAILED
      - INGESTING (= "running") if any stage is RUNNING
      - READY if all stages are DONE
      - PENDING otherwise

    ``AnalysisState.INGESTING`` is reused for "running" because the enum is
    the operator-facing contract value; the UI distinguishes by which stage
    is running via the per-stage breakdown.
    """
    statuses = [stages.get(s).state for s in StageName]
    if any(s == StageState.FAILED for s in statuses):
        return AnalysisState.FAILED
    if any(s == StageState.RUNNING for s in statuses):
        return AnalysisState.INGESTING
    if all(s == StageState.DONE for s in statuses):
        return AnalysisState.READY
    return AnalysisState.PENDING
