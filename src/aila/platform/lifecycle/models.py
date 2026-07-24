"""RFC-10 agent lifecycle: stage vocabulary + append-only transition journal.

The lifecycle control plane owns two things: the stage machine (this file's
``LifecycleStage`` StrEnum) and the append-only journal of stage moves
(``LifecycleTransitionRecord``). Every observed change to the operator
alias for a prompt key -- eval-verified promotion, rollback to a prior
production version, or a re-eval on a candidate that stayed in
``evaluated`` -- writes exactly one row here. The controller in
``platform/lifecycle/controller.py`` is the only writer.

Only ``built``, ``evaluated``, ``production``, and ``rolled_back`` are
wired in the first RFC-10 increment. ``shadow`` and ``canary`` are
reserved for a later increment that runs a live traffic-mirroring
comparison; declaring them now keeps the stage vocabulary stable so
downstream operator UIs need not migrate the enum on that increment.

Constraint and index names carry the ``lifecycle_transitions_`` prefix
so they stay unique across the platform schema (Postgres constraint
names are database-scoped, not table-scoped -- the same lesson eval
and prompt tables learned).
"""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import uuid4

from sqlalchemy import DateTime, Index, Text
from sqlmodel import Field, SQLModel

from aila.platform.contracts._common import utc_now

__all__ = ["LifecycleStage", "LifecycleTransitionRecord"]


class LifecycleStage(StrEnum):
    """Stages an agent prompt/version moves through under the control plane.

    Members ``BUILT``, ``EVALUATED``, ``PRODUCTION``, ``ROLLED_BACK`` are
    active in this increment. ``SHADOW`` and ``CANARY`` are reserved for
    a later live-mirroring increment; they are part of the vocabulary
    now so the enum does not need to migrate later.
    """

    BUILT = "built"
    EVALUATED = "evaluated"
    SHADOW = "shadow"
    CANARY = "canary"
    PRODUCTION = "production"
    ROLLED_BACK = "rolled_back"


class LifecycleTransitionRecord(SQLModel, table=True):
    """One append-only row per observed stage transition for a prompt version.

    ``from_stage`` and ``to_stage`` carry the ``LifecycleStage`` value
    strings; they are stored as plain strings so historical rows survive
    an enum extension without a data migration. ``metrics_snapshot_json``
    embeds the evidence for the transition: for evaluate rows it holds
    the eval verdict, eval run id, and the full ``EvalReport`` payload;
    for promote rows it holds the referenced eval run id and verdict; for
    rollback rows it holds the target version being restored. That
    self-contained snapshot lets a later inspection reason about a
    transition without replaying the runner.
    """

    __tablename__ = "lifecycle_transitions"
    __table_args__ = (
        Index("ix_lifecycle_transitions_key_created_at", "key", "created_at"),
        Index(
            "ix_lifecycle_transitions_key_version_to_stage",
            "key", "version", "to_stage",
        ),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)
    key: str = Field(max_length=256, index=True)
    version: str = Field(max_length=32)
    from_stage: str = Field(max_length=32)
    to_stage: str = Field(max_length=32)
    actor: str = Field(default="", max_length=128)
    reason: str = Field(default="", sa_type=Text)
    metrics_snapshot_json: str | None = Field(default=None, sa_type=Text)
    created_at: datetime = Field(
        default_factory=utc_now, sa_type=DateTime(timezone=True),
    )
