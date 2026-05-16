"""Fuzzing campaign + crash contracts (Fuzzing plan GA-8..GA-12).

v1 ships the campaign lifecycle + crash registration + auto-triage by
stack hash. The actual engine processes (FUZZILLI / AFL++ / libfuzzer)
run out-of-band on dedicated workstations per D-33; AILA's role here
is to model the campaign metadata + ingest crashes that the operator
or worker forwards via API.

The plan calls for a worker pool + per-engine adapter spawn; that
defers to v1.1 once a real dedicated fuzz workstation is wired in.
"""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "CampaignStatus",
    "CrashSeverity",
    "CrashTriageVerdict",
    "FuzzEngineId",
    "FuzzStrategyId",
    "VRFuzzCampaignCreate",
    "VRFuzzCampaignPatch",
    "VRFuzzCampaignSummary",
    "VRFuzzCrashCreate",
    "VRFuzzCrashSummary",
]


class FuzzEngineId(StrEnum):
    """Built-in engine identifiers (GA-8)."""

    AFL_PLUSPLUS = "afl++"
    AFL_PLUSPLUS_QEMU = "afl++_qemu"
    LIBFUZZER = "libfuzzer"
    HONGGFUZZ = "honggfuzz"
    FUZZILLI_V8 = "fuzzilli_v8"
    V8_D8_SBX = "v8_d8_sbx"
    JAZZER = "jazzer"
    CARGO_FUZZ = "cargo-fuzz"
    GO_FUZZ = "go-fuzz"
    ATHERIS = "atheris"


class FuzzStrategyId(StrEnum):
    """Built-in strategy identifiers (GA-9)."""

    MUTATIONAL = "mutational"
    COVERAGE_GUIDED = "coverage_guided"
    DIFFERENTIAL = "differential"
    GENERATIVE = "generative"
    GRAMMAR = "grammar"


class CampaignStatus(StrEnum):
    """Lifecycle states for a fuzzing campaign."""

    CREATED = "created"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"


class CrashTriageVerdict(StrEnum):
    """Auto-triage verdict after stack hash + signature classification."""

    UNTRIAGED = "untriaged"
    SECURITY_RELEVANT = "security_relevant"
    LIKELY_HARMLESS = "likely_harmless"
    DUPLICATE = "duplicate"
    NEEDS_MANUAL_REVIEW = "needs_manual_review"


class CrashSeverity(StrEnum):
    """Engine-rated severity (informational; finding promotion is operator-driven)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"
    UNKNOWN = "unknown"


class VRFuzzCampaignCreate(BaseModel):
    """Operator-initiated campaign creation."""

    model_config = ConfigDict(extra="forbid")

    target_id: str = Field(min_length=1, max_length=64)
    workspace_id: str = Field(min_length=1, max_length=64)
    name: str = Field(min_length=1, max_length=255)
    engine_id: FuzzEngineId
    strategy_id: FuzzStrategyId
    engine_config: dict[str, Any] = Field(
        default_factory=dict,
        description="Engine-specific kwargs (e.g. dict_path, seed_corpus_path, parallel_jobs).",
    )
    strategy_config: dict[str, Any] = Field(
        default_factory=dict,
        description="Strategy-specific kwargs (e.g. mutator_weights, grammar_path).",
    )
    duration_hours: int | None = Field(
        default=None,
        ge=1,
        le=720,  # 30 days
        description="Soft cap. Operator stops manually for indefinite runs.",
    )
    workstation_host: str | None = Field(
        default=None,
        max_length=255,
        description=(
            "Dedicated fuzz workstation host (D-33). None = local dev only — "
            "campaign records still persist but no worker is spawned."
        ),
    )
    notes: str = ""


class VRFuzzCampaignPatch(BaseModel):
    """Operator updates: state transitions + result fields."""

    model_config = ConfigDict(extra="forbid")

    status: CampaignStatus | None = None
    notes: str | None = None
    duration_hours: int | None = Field(default=None, ge=1, le=720)
    execs_per_sec: float | None = Field(default=None, ge=0)
    total_execs: int | None = Field(default=None, ge=0)
    corpus_size: int | None = Field(default=None, ge=0)
    coverage_pct: float | None = Field(default=None, ge=0, le=100)
    crashes_found: int | None = Field(default=None, ge=0)


class VRFuzzCampaignSummary(BaseModel):
    """Read projection of one campaign."""

    model_config = ConfigDict(extra="forbid")

    id: str
    target_id: str
    workspace_id: str
    name: str
    engine_id: FuzzEngineId
    strategy_id: FuzzStrategyId
    engine_config: dict[str, Any] = Field(default_factory=dict)
    strategy_config: dict[str, Any] = Field(default_factory=dict)
    status: CampaignStatus
    duration_hours: int | None = None
    workstation_host: str | None = None
    execs_per_sec: float | None = None
    total_execs: int = 0
    corpus_size: int = 0
    coverage_pct: float | None = None
    crashes_found: int = 0
    started_at: datetime | None = None
    stopped_at: datetime | None = None
    last_progress_at: datetime | None = None
    notes: str = ""
    created_at: datetime | None = None
    updated_at: datetime | None = None


class VRFuzzCrashCreate(BaseModel):
    """Crash registration — engine worker or operator forwards a hit."""

    model_config = ConfigDict(extra="forbid")

    campaign_id: str = Field(min_length=1, max_length=64)
    stack_hash: str = Field(
        min_length=1,
        max_length=128,
        description="Stable hash for dedup (e.g. top-N frame signature).",
    )
    crash_type: str | None = Field(
        default=None,
        max_length=64,
        description="Engine-emitted type tag (e.g. 'heap-buffer-overflow', 'SIGSEGV').",
    )
    crash_signature: str | None = Field(
        default=None,
        max_length=512,
        description="One-line summary (top frame, fault address, primitive).",
    )
    severity: CrashSeverity = CrashSeverity.UNKNOWN
    reproducer_path: str | None = Field(
        default=None,
        max_length=1024,
        description=(
            "Path on the worker host to the minimized reproducer "
            "(forwarded via separate file-transfer flow)."
        ),
    )
    reproducer_size_bytes: int | None = Field(default=None, ge=0)
    stack_trace: str | None = Field(
        default=None,
        max_length=16384,
        description="Top-frames stack trace (truncated to fit a single row).",
    )
    extra: dict[str, Any] = Field(default_factory=dict)


class VRFuzzCrashSummary(BaseModel):
    """Read projection of one crash."""

    model_config = ConfigDict(extra="forbid")

    id: str
    campaign_id: str
    stack_hash: str
    crash_type: str | None = None
    crash_signature: str | None = None
    severity: CrashSeverity
    triage_verdict: CrashTriageVerdict
    triage_reason: str | None = None
    duplicate_of_crash_id: str | None = None
    promoted_to_finding_id: str | None = None
    reproducer_path: str | None = None
    reproducer_size_bytes: int | None = None
    stack_trace: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)
    discovered_at: datetime | None = None
    created_at: datetime | None = None
    updated_at: datetime | None = None
