"""Retrieval eval storage records (RFC-12 criterion 7).

Two SQLModel tables back the retrieval-eval RUNNER:

- ``RetrievalBenchmarkRecord`` -- a named benchmark of recorded queries
  and per-query known-relevant entry ids. ``cases_json`` is the JSON
  serialization of ``[{query_id, query, relevant_ids: [str]}, ...]``.
  ``k`` is the fixed retrieval depth at which precision, recall, and
  nDCG are evaluated for every replay of this benchmark.
- ``RetrievalRunRecord`` -- one scoring event: a benchmark replayed
  through a candidate ``retrieve_fn``, optionally against a baseline
  replay, plus the promotion verdict from the ``beats()`` gate. The
  serialized report bundle contains both candidate and baseline
  ``RetrievalReport`` payloads so a later inspection needs no replay.

Both tables carry a ``key`` column indexed together with ``created_at``
so operator listings scoped to one retrieval key page cheaply. Table,
constraint, and index names are prefixed ``retrieval_eval_`` to keep
them unique across the platform schema (Postgres constraint names are
database-scoped, not table-scoped).
"""
from __future__ import annotations

from datetime import datetime
from uuid import uuid4

from sqlalchemy import DateTime, Index, Text
from sqlmodel import Field, SQLModel

from aila.platform.contracts._common import utc_now

__all__ = [
    "RetrievalBenchmarkRecord",
    "RetrievalRunRecord",
]


class RetrievalBenchmarkRecord(SQLModel, table=True):
    """A named benchmark of recorded queries with ground-truth relevant ids.

    ``cases_json`` is a JSON list; each entry has ``query_id`` (stable
    string), ``query`` (the text passed to the retrieve function), and
    ``relevant_ids`` (a list of knowledge entry ids the operator has
    judged relevant). ``k`` fixes the retrieval depth so a rerun always
    scores against the same top-``k`` window.
    """

    __tablename__ = "retrieval_eval_benchmarks"
    __table_args__ = (
        Index(
            "ix_retrieval_eval_benchmarks_key_created_at",
            "key", "created_at",
        ),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    key: str = Field(max_length=256, index=True)
    name: str = Field(max_length=256)
    k: int = Field(default=10)
    cases_json: str = Field(sa_type=Text)
    created_by: str = Field(default="", max_length=128)
    created_at: datetime = Field(
        default_factory=utc_now, sa_type=DateTime(timezone=True),
    )


class RetrievalRunRecord(SQLModel, table=True):
    """One replay event: candidate scored against a benchmark, with verdict.

    ``baseline_label`` is None when the run has no comparison baseline
    (first-ever eval for the key, or a bootstrap replay). ``report_json``
    embeds the candidate ``RetrievalReport`` plus the baseline report
    (when present) so a later drill-in needs no replay.

    ``verdict`` is one of ``pass`` (candidate beats or is the first
    baseline), ``fail`` (candidate regressed or made no improvement),
    or ``baseline_only`` (a bootstrap replay with no baseline supplied
    and no auto-pass semantics requested by the caller).
    """

    __tablename__ = "retrieval_eval_runs"
    __table_args__ = (
        Index(
            "ix_retrieval_eval_runs_key_created_at",
            "key", "created_at",
        ),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    key: str = Field(max_length=256, index=True)
    benchmark_id: str = Field(
        foreign_key="retrieval_eval_benchmarks.id", max_length=64,
    )
    candidate_label: str = Field(max_length=64)
    baseline_label: str | None = Field(default=None, max_length=64)
    report_json: str = Field(sa_type=Text)
    verdict: str = Field(max_length=16)
    actor: str = Field(default="", max_length=128)
    created_at: datetime = Field(
        default_factory=utc_now, sa_type=DateTime(timezone=True),
    )
