"""RFC-10 shadow + canary assignment table.

A ``LifecycleCanaryAssignment`` row records the platform's intent to
route some traffic to a non-production candidate: a ``shadow``
assignment says "this candidate is being compared but never wins a real
turn"; a ``canary`` assignment says "route ``cohort_percent`` of new
investigations to this candidate deterministically by hash".

The table is mutable because a canary can be HELD when the drift or
cost signal breaches its ceiling, and a prior shadow / canary for the
same key is superseded on a new one. The append-only story lives on
``lifecycle_transitions``; this table is the routing-side lookup the
runtime consults on every new investigation.

Constraint and index names carry the ``lifecycle_canary_assignments_``
prefix so they stay unique across the platform schema (Postgres
constraint names are database-scoped, not table-scoped -- the same
lesson eval, prompt, and lifecycle-transition tables learned).
"""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import uuid4

from sqlalchemy import DateTime, Index, Text
from sqlmodel import Field, SQLModel

from aila.platform.contracts._common import utc_now

__all__ = [
    "AssignmentKind",
    "AssignmentState",
    "LifecycleCanaryAssignment",
]


class AssignmentKind(StrEnum):
    """The two live-routing intents this table records.

    ``SHADOW`` registers a candidate for off-path comparison; the router
    still hands production to every real turn. ``CANARY`` registers a
    cohort-scoped assignment; the router deterministically routes a
    hashed fraction of new investigations to the candidate.
    """

    SHADOW = "shadow"
    CANARY = "canary"


class AssignmentState(StrEnum):
    """Lifecycle of a single assignment row.

    ``ACTIVE`` is the row the router reads; ``SUPERSEDED`` is a prior
    row that a newer assignment for the same (key, kind) displaced;
    ``HELD`` is a canary that a drift or cost breach paused. A held
    canary never returns to routing without an explicit new canary
    call from an admin.
    """

    ACTIVE = "active"
    SUPERSEDED = "superseded"
    HELD = "held"


class LifecycleCanaryAssignment(SQLModel, table=True):
    """One shadow or canary assignment for a (key, kind) pair.

    The router consults this table with an ORDER BY ``created_at`` DESC
    LIMIT 1 filtered on ``kind`` and ``state='active'``. When a new
    shadow / canary is registered for the key, the controller flips
    every prior ``active`` row of the same kind to ``superseded`` in
    the same transaction so exactly one row per (key, kind) is active
    at a time. ``last_signal_json`` carries the most recent drift or
    cost breach snapshot so an operator inspecting a HELD canary sees
    what tripped the hold without replaying anything.
    """

    __tablename__ = "lifecycle_canary_assignments"
    __table_args__ = (
        Index(
            "ix_lifecycle_canary_assignments_key_kind_state",
            "key", "kind", "state",
        ),
        Index(
            "ix_lifecycle_canary_assignments_key_created_at",
            "key", "created_at",
        ),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    key: str = Field(max_length=256, index=True)
    kind: str = Field(max_length=16)
    version: str = Field(max_length=32)
    cohort_percent: int | None = Field(default=None)
    state: str = Field(default=AssignmentState.ACTIVE.value, max_length=16)
    actor: str = Field(default="", max_length=128)
    reason: str = Field(default="", sa_type=Text)
    last_signal_json: str | None = Field(default=None, sa_type=Text)
    created_at: datetime = Field(
        default_factory=utc_now, sa_type=DateTime(timezone=True),
    )
    updated_at: datetime = Field(
        default_factory=utc_now, sa_type=DateTime(timezone=True),
    )
