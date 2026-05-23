"""Per-stage target analysis status — durable, recoverable, per-service.

Pre-this-contract every service that touched a target's analysis
(`TargetAnalysisService`, `CapabilityProfileBuilder`, `FunctionRanker`)
mutated the single `vr_targets.analysis_state` column with the pattern
"set ingesting → do work → set ready/failed". Three problems:

  1. Any service that crashed mid-work left state stuck at `ingesting`
     forever. The firefox target hit this on 2026-05-22 — analysis ran
     successfully on audit_mcp's side but AILA's profile_builder lost
     the result and state never advanced, leaving the UI showing a
     fake "analyzing…" spinner 22 hours later.
  2. A successful later stage would CLEAR the failure of an earlier
     stage by overwriting state to `ready`, silently masking errors.
  3. The operator had no way to resume from the last-completed stage;
     re-running meant re-uploading + re-indexing from scratch.

This contract replaces the single enum with a per-stage status struct.
Each service owns ONE stage and only touches that one stage's record.
The overall `analysis_state` becomes a derived roll-up (`failed` if any
stage failed, `running` if any stage running, `pending` if all pending,
`ready` if all done).

Persisted as JSON on `vr_targets.analysis_stages_json` (migration 060).
"""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field

from aila.modules.vr.contracts.target import AnalysisState

__all__ = [
    "StageName",
    "StageState",
    "StageStatus",
    "TargetAnalysisStages",
    "roll_up_overall_state",
]


class StageName(StrEnum):
    """Three independent stages of target analysis pipeline.

    INGESTION: TargetAnalysisService — clone/upload + index registration
               with the right MCP, populates `mcp_handles_json`.
    CAPABILITY_PROFILE: CapabilityProfileBuilder — read MCP signals
               (checksec, classify_strings, capa_scan, etc.) and emit
               structured `capability_profile_json`.
    FUNCTION_RANKING: FunctionRanker — call audit_mcp.fuzzing_targets +
               ida_headless.assess_exploitability and persist a ranked
               function list under `capability_profile.function_ranking`.

    Stages run sequentially in this order. CAPABILITY_PROFILE depends
    on INGESTION (needs mcp_handles_json populated). FUNCTION_RANKING
    depends on INGESTION (needs index_id) but NOT on CAPABILITY_PROFILE.
    """

    INGESTION = "ingestion"
    CAPABILITY_PROFILE = "capability_profile"
    FUNCTION_RANKING = "function_ranking"


class StageState(StrEnum):
    """One stage's lifecycle.

    PENDING: never started — initial state.
    RUNNING: in flight on some worker since `started_at`. If `now -
             started_at > stage_timeout_s`, the reaper flips to FAILED
             with a 'timeout' message.
    DONE: finished successfully, output persisted.
    FAILED: errored, `error` carries the message. Operator can call
            the resume-analysis endpoint to retry (sets back to PENDING
            and re-runs only this stage and any downstream stages).
    """

    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


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

    Persisted as JSON on `vr_targets.analysis_stages_json`. Operations
    on this struct are pure — the persistence layer is in
    `services.stage_tracker.StageTracker`.
    """

    model_config = ConfigDict(extra="ignore")

    ingestion: StageStatus = Field(default_factory=StageStatus)
    capability_profile: StageStatus = Field(default_factory=StageStatus)
    function_ranking: StageStatus = Field(default_factory=StageStatus)

    def get(self, stage: StageName) -> StageStatus:
        return getattr(self, stage.value)

    def set(self, stage: StageName, status: StageStatus) -> None:
        setattr(self, stage.value, status)

    def all_stages(self) -> list[tuple[StageName, StageStatus]]:
        return [(s, self.get(s)) for s in StageName]


def roll_up_overall_state(stages: TargetAnalysisStages) -> AnalysisState:
    """Compute the overall `analysis_state` enum from per-stage states.

    Priority (highest precedence first):
      - FAILED if any stage is FAILED
      - INGESTING (= "running") if any stage is RUNNING
      - READY if all stages are DONE
      - PENDING otherwise

    Note `AnalysisState.INGESTING` is reused for "running" because the
    enum is the operator-facing contract value and we don't want to
    invent a new fifth state; the UI distinguishes by which stage is
    running via the per-stage breakdown.
    """
    statuses = [stages.get(s).state for s in StageName]
    if any(s == StageState.FAILED for s in statuses):
        return AnalysisState.FAILED
    if any(s == StageState.RUNNING for s in statuses):
        return AnalysisState.INGESTING
    if all(s == StageState.DONE for s in statuses):
        return AnalysisState.READY
    return AnalysisState.PENDING
