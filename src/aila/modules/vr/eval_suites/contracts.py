"""Pydantic contracts for the VR benchmark-measurement harness.

``BenchmarkTaskSpec`` / ``SuiteManifest`` describe the on-disk manifest an
operator points the harness at (one published benchmark suite). The
``*Summary`` models are the read projections the admin API returns.

Supported suites are the three public academic cyber-agent benchmarks the
harness is wired for; an unknown suite name is rejected at load time so a
typo never silently produces an empty run.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "SUPPORTED_SUITES",
    "BenchmarkTaskSpec",
    "SuiteManifest",
    "TaskResultSummary",
    "SuiteRunSummary",
    "LeaderboardRow",
]

SUPPORTED_SUITES: frozenset[str] = frozenset({"cybench", "nyu_ctf", "htb_lite"})


class BenchmarkTaskSpec(BaseModel):
    """One published benchmark task with its known reference answer.

    ``target_id`` references a VR target the operator has already
    provisioned and ingested for the challenge (targets are heavyweight
    and ingested out-of-band through the normal target-intake path, then
    reused across measurement runs). The harness spins one investigation
    per task against this target.
    """

    model_config = ConfigDict(extra="forbid")

    suite: str
    task_id: str
    name: str
    category: str | None = None
    description: str = ""
    reference_answer: str
    target_id: str
    budget_usd: float = Field(default=50.0, gt=0.0)


class SuiteManifest(BaseModel):
    """A loaded benchmark suite: its name plus the tasks it contains."""

    model_config = ConfigDict(extra="forbid")

    suite: str
    tasks: list[BenchmarkTaskSpec] = Field(default_factory=list)


class TaskResultSummary(BaseModel):
    """Read projection of one scored benchmark task."""

    model_config = ConfigDict(extra="forbid")

    task_id: str
    name: str
    category: str | None
    investigation_id: str | None
    status: str
    solved: bool
    cost_usd: float
    polarity: str | None


class SuiteRunSummary(BaseModel):
    """Read projection of one measurement run with its aggregates."""

    model_config = ConfigDict(extra="forbid")

    id: str
    suite: str
    status: str
    solved_count: int
    total_count: int
    total_cost_usd: float
    created_at: str | None
    finished_at: str | None
    results: list[TaskResultSummary] = Field(default_factory=list)


class LeaderboardRow(BaseModel):
    """One suite's aggregate across its most recent measurement run."""

    model_config = ConfigDict(extra="forbid")

    suite: str
    solved_count: int
    total_count: int
    solve_rate: float
    avg_cost_usd: float
    last_run_at: str | None
