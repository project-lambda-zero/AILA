"""Per-stage target analysis status -- durable, recoverable, per-service.

Pre-this-contract every service that touched a target's analysis
(`TargetAnalysisService`, `CapabilityProfileBuilder`, `FunctionRanker`)
mutated the single `vr_targets.analysis_state` column with the pattern
"set ingesting → do work → set ready/failed". Three problems:

  1. Any service that crashed mid-work left state stuck at `ingesting`
     forever. The firefox target hit this on 2026-05-22 -- analysis ran
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

from aila.platform.contracts.target_stages import (
    StageName,
    StageState,
    StageStatus,
    TargetAnalysisStages,
    roll_up_overall_state,
)

__all__ = [
    "StageName",
    "StageState",
    "StageStatus",
    "TargetAnalysisStages",
    "roll_up_overall_state",
]
