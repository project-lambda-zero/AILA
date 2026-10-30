"""Benchmark-suite result tables for the VR capability-measurement harness.

Two tables record how the VR investigation engine scores against a
published academic benchmark suite (cybench / nyu_ctf / htb_lite):

* ``vr_eval_suite_runs`` -- one row per measurement run (one suite).
* ``vr_eval_task_results`` -- one row per benchmark task in that run,
  linked to the VR investigation spun for the task and carrying the
  solved / cost / polarity score once the investigation is terminal.

Written by: ``eval_suites.suite_runner`` (start + collect).
Consumed by: ``eval_suites.api_router`` (runs list, run detail, leaderboard).
"""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, Text, UniqueConstraint
from sqlmodel import Field, SQLModel

from aila.platform.contracts import utc_now

__all__ = ["VREvalSuiteRunRecord", "VREvalTaskResultRecord"]


class VREvalSuiteRunRecord(SQLModel, table=True):
    """One capability-measurement run over a single benchmark suite."""

    __tablename__ = "vr_eval_suite_runs"

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    suite: str = Field(index=True, max_length=64)
    # pending -> running -> collected (or failed). ``running`` means the
    # per-task investigations are enqueued; ``collected`` means every
    # terminal investigation has been scored.
    status: str = Field(default="pending", index=True, max_length=16)
    requested_by: str | None = Field(default=None, max_length=128)
    team_id: str | None = Field(default=None, index=True)
    total_count: int = Field(default=0, sa_column=Column(Integer, nullable=False, server_default="0"))
    solved_count: int = Field(default=0, sa_column=Column(Integer, nullable=False, server_default="0"))
    total_cost_usd: float = Field(default=0.0, sa_column=Column(Float, nullable=False, server_default="0"))
    created_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    finished_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))


class VREvalTaskResultRecord(SQLModel, table=True):
    """One benchmark task inside a run, scored from its VR investigation."""

    __tablename__ = "vr_eval_task_results"
    __table_args__ = (
        UniqueConstraint("run_id", "task_id", name="uq_vr_eval_task_result_run_task"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    run_id: str = Field(
        sa_column=Column(
            "run_id",
            ForeignKey("vr_eval_suite_runs.id", ondelete="CASCADE"),
            nullable=False,
            index=True,
        ),
    )
    task_id: str = Field(max_length=128)
    name: str = Field(default="", sa_column=Column(Text))
    category: str | None = Field(default=None, max_length=64)
    investigation_id: str | None = Field(default=None, index=True, max_length=64)
    # pending -> scored (or error when the investigation could not be spun).
    status: str = Field(default="pending", index=True, max_length=16)
    solved: bool = Field(default=False, sa_column=Column(Boolean, nullable=False, server_default="false"))
    cost_usd: float = Field(default=0.0, sa_column=Column(Float, nullable=False, server_default="0"))
    polarity: str | None = Field(default=None, max_length=16)
    reference_answer: str = Field(default="", sa_column=Column(Text))
    started_at: datetime = Field(default_factory=utc_now, sa_type=DateTime(timezone=True))
    finished_at: datetime | None = Field(default=None, sa_type=DateTime(timezone=True))
