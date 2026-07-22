"""Shared engine StrEnums, single source of truth (RFC-01).

The vr and malware modules each carried a byte-identical copy of these 19
enums. They encode engine vocabulary -- branch lifecycle, quorum confidence,
message sender, pattern scope -- not domain vocabulary, so they live on the
platform and both modules import them. ``WorkspaceTheme`` deliberately stays
module-owned: its value set differs per module by design.

Enum values are the durable contract (persisted to the DB, sent over the
wire); member names and string values here must stay identical to the copies
they replace so a re-export in a module is behavior-preserving.
"""
from __future__ import annotations

from enum import StrEnum

__all__ = [
    "AnalysisState",
    "BranchOperation",
    "BranchStatus",
    "HypothesisState",
    "InvestigationPauseReason",
    "InvestigationStatus",
    "OperatorIntent",
    "OutcomeConfidence",
    "OutcomeDispatchStatus",
    "PatternConfidence",
    "PatternScope",
    "PatternStatus",
    "PersonaVoice",
    "SenderKind",
    "StageName",
    "StageState",
    "TargetStatus",
    "TargetTagSource",
    "WorkspaceStatus",
]


class WorkspaceStatus(StrEnum):
    """Lifecycle states for a workspace."""

    ACTIVE = "active"
    ARCHIVED = "archived"


class TargetStatus(StrEnum):
    """Operator lifecycle state."""

    ACTIVE = "active"
    ARCHIVED = "archived"
    QUARANTINED = "quarantined"


class AnalysisState(StrEnum):
    """Backend ingestion + capability-profile lifecycle (v0.4.5).

    Operator-facing -- the UI renders each value as a clear sentence
    ('Pulling from GitHub…' / 'Analyzing in IDA…' / 'Ready' /
    'Failed: <reason>'). Code reads the enum; UI never shows the raw value.
    """

    PENDING = "pending"
    INGESTING = "ingesting"
    READY = "ready"
    FAILED = "failed"


class TargetTagSource(StrEnum):
    """Provenance of a tag attached to a target (D-52)."""

    OPERATOR = "operator"
    SYSTEM = "system"
    PATTERN = "pattern"


class BranchStatus(StrEnum):
    """Lifecycle states for one branch within an investigation."""

    ACTIVE = "active"
    PAUSED = "paused"
    MERGED = "merged"
    PROMOTED = "promoted"
    ABANDONED = "abandoned"
    COMPLETED = "completed"


class PersonaVoice(StrEnum):
    """Per-D-39 persona voice modifiers. Each is a prompt-prefix.

    Voices are not separate agents -- they're stylistic prompt prefixes
    that bias the reasoning toward a particular kind of skepticism /
    aggression / pattern-matching. The same model produces all of them.
    """

    HALVAR = "halvar"
    MADDIE = "maddie"
    YUKI = "yuki"
    RENZO = "renzo"
    NOOR = "noor"
    WEI = "wei"
    # Synthetic voices written by branch_manager when no agent persona is
    # meaningful. Migration 064 backfilled older rows to UNSPECIFIED and made
    # the persona column required; every stored value must round-trip through
    # this enum so the api_router serializer accepts it.
    UNSPECIFIED = "unspecified"
    MERGE_RESULT = "merge_result"
    FORK_UNNAMED = "fork_unnamed"


class BranchOperation(StrEnum):
    """Branch lifecycle operations (D-41).

    Recorded on every transition for audit trail. Triggered by engine (when
    confidence + evidence justify) OR operator (manual override via API).
    """

    FORK = "fork"
    MERGE = "merge"
    PROMOTE = "promote"
    ABANDON = "abandon"
    PAUSE = "pause"
    RESUME = "resume"
    SPAWN_STRATEGY = "spawn_strategy"


class InvestigationStatus(StrEnum):
    """Lifecycle states for an investigation."""

    CREATED = "created"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    ABANDONED = "abandoned"


class InvestigationPauseReason(StrEnum):
    """Why an investigation entered the PAUSED state.

    Used by the resumer worker (M3.R-6) to decide whether to auto-resume
    (e.g. awaiting_campaign once the campaign finishes) or wait for operator
    action.
    """

    OPERATOR = "operator"
    LOW_CONFIDENCE = "low_confidence"
    COST_BUDGET = "cost_budget"
    AWAITING_CAMPAIGN = "awaiting_campaign"
    AWAITING_MCP = "awaiting_mcp"


class OutcomeConfidence(StrEnum):
    """Engine's confidence in the outcome (matches ReasoningConfidence)."""

    EXACT = "exact"
    STRONG = "strong"
    MEDIUM = "medium"
    CAVEATED = "caveated"
    UNKNOWN = "unknown"


class OutcomeDispatchStatus(StrEnum):
    """State of downstream dispatch after the outcome is accepted."""

    PENDING = "pending"
    DISPATCHED = "dispatched"
    FAILED = "failed"
    SKIPPED = "skipped"


class SenderKind(StrEnum):
    """Who sent this message.

    fix §250 -- added ``SYSTEM`` so system-authored steering messages
    (outcome_review draft requests, future system notices) can be
    distinguished from human-typed OPERATOR messages by sender_kind alone.
    """

    ENGINE = "engine"
    OPERATOR = "operator"
    SYSTEM = "system"


class OperatorIntent(StrEnum):
    """How the engine should interpret an operator message (D-43 GA-30).

    Auto-classified by a cheap Haiku call at insertion time. Operator can
    override via the UI ('interpret as ___').
    """

    STEERING = "steering"
    QUESTION = "question"
    CORRECTION = "correction"
    DISMISSAL = "dismissal"
    OUTCOME_SELECTION = "outcome_selection"
    BRANCH_COMMAND = "branch_command"
    UNCLASSIFIED = "unclassified"


class PatternStatus(StrEnum):
    """Lifecycle states for a pattern (GA-43).

    - DRAFT: just extracted, not reviewed by operator yet
    - ACTIVE: operator approved; eligible for retrieval
    - ARCHIVED: deprecated; not retrieved by engine
    """

    DRAFT = "draft"
    ACTIVE = "active"
    ARCHIVED = "archived"


class PatternScope(StrEnum):
    """Visibility scope. Widening requires explicit operator promotion."""

    LOCAL = "local"          # visible only inside the originating investigation
    WORKSPACE = "workspace"  # visible across investigations in same workspace
    TEAM = "team"            # visible across workspaces within team
    GLOBAL = "global"        # cross-team; admin-gated


class PatternConfidence(StrEnum):
    """Engine-rated confidence at extraction time."""

    EXACT = "exact"
    STRONG = "strong"
    MEDIUM = "medium"
    CAVEATED = "caveated"
    UNKNOWN = "unknown"


class HypothesisState(StrEnum):
    """Lifecycle of a hypothesis across the branches it appears on."""

    LIVE = "live"          # still in case_state.hypotheses on >=1 branch
    REJECTED = "rejected"  # moved to case_state.rejected on >=1 branch
    RESOLVED = "resolved"  # auto-bucketed on terminal -- see canonical outcome
    MIXED = "mixed"        # state differs across branches


class StageState(StrEnum):
    """One target-analysis stage's lifecycle.

    PENDING: never started. RUNNING: in flight. DONE: finished, output
    persisted. FAILED: errored; the resume-analysis endpoint retries this
    stage and any downstream stages.
    """

    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"


class StageName(StrEnum):
    """Per-target analysis stages.

    Source-repo / native-binary kinds use the legacy three (ingestion,
    capability_profile, function_ranking); android_apk targets drive the
    five-stage android-mcp pipeline. Stages that do not apply to a target's
    kind are pre-marked DONE so the rollup still converges. See
    :mod:`aila.platform.contracts.target_stages` for the full pipeline docs.
    """

    INGESTION = "ingestion"
    CAPABILITY_PROFILE = "capability_profile"
    FUNCTION_RANKING = "function_ranking"
    APK_DECODE = "apk_decode"
    JADX_DECOMPILE = "jadx_decompile"
    REACT_NATIVE_EXTRACT = "react_native_extract"
    INDEX_DECOMPILED = "index_decompiled"
    STATIC_SUMMARY = "static_summary"
    MOBSF_SCAN = "mobsf_scan"
