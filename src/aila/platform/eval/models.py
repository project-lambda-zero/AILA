"""Eval harness storage records (RFC-08 step 1).

Two SQLModel tables back the eval RUNNER:

- ``EvalBenchmarkRecord`` -- a named benchmark: a JSON blob of pre-scored
  ``CaseOutcome`` cases (predicted_verdict / verified_verdict / confidence
  per outcome_kind) plus a ``key`` naming the prompt these cases score. The
  cases are pre-supplied by the operator; this increment does not replay the
  agent loop.
- ``EvalRunRecord`` -- one scoring event: which candidate prompt version
  was scored against which benchmark, which production version served as
  the baseline (nullable for a first-ever eval), the serialized
  ``EvalReport`` for both bundles, and the promotion verdict ('pass' or
  'fail'). Actor and timestamp round out the audit trail.

Both tables carry a ``key`` column indexed together with ``created_at`` so
operator listings scoped to one prompt key page cheaply. Constraint and
index names are prefixed ``eval_`` to keep them unique across the schema
(Postgres constraint names are database-scoped, not table-scoped).
"""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, Index, Text
from sqlmodel import Field, SQLModel

from aila.platform.contracts._common import utc_now

__all__ = [
    "EvalBenchmarkRecord",
    "EvalRunRecord",
]


class EvalBenchmarkRecord(SQLModel, table=True):
    """A named benchmark of pre-scored ``CaseOutcome`` cases for one prompt key.

    ``cases_json`` is the JSON serialization of a list of case dicts with
    fields ``outcome_kind``, ``predicted_verdict``, ``verified_verdict``,
    ``confidence``. The runner deserializes and hands them to the pure
    scoring functions in ``platform/eval/metrics.py``.
    """

    __tablename__ = "eval_benchmarks"
    __table_args__ = (
        Index("ix_eval_benchmarks_key_created_at", "key", "created_at"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    key: str = Field(max_length=256, index=True)
    name: str = Field(max_length=256)
    cases_json: str = Field(sa_type=Text)
    created_by: str = Field(default="", max_length=128)
    created_at: datetime = Field(
        default_factory=utc_now, sa_type=DateTime(timezone=True),
    )


class EvalRunRecord(SQLModel, table=True):
    """One scoring event: candidate scored against a benchmark, with verdict.

    ``baseline_version`` is None for the first-ever run of a key (nothing
    to compare against). ``report_json`` embeds the candidate ``EvalReport``
    plus the baseline report (when present) so a later inspection needs no
    replay. ``verdict`` is 'pass' or 'fail'; auto-promotion (flipping the
    production alias) happens only on 'pass' AND when the caller opts in.
    """

    __tablename__ = "eval_runs"
    __table_args__ = (
        Index("ix_eval_runs_key_created_at", "key", "created_at"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    key: str = Field(max_length=256, index=True)
    candidate_version: str = Field(max_length=32)
    baseline_version: str | None = Field(default=None, max_length=32)
    benchmark_id: str = Field(foreign_key="eval_benchmarks.id", max_length=64)
    report_json: str = Field(sa_type=Text)
    verdict: str = Field(max_length=16)
    actor: str = Field(default="", max_length=128)
    created_at: datetime = Field(
        default_factory=utc_now, sa_type=DateTime(timezone=True),
    )
