"""Investigation-target join record base shared by the investigation engine (RFC-01).

Zero-domain table: the vr and malware investigation-target join tables
(v0.4 multi-target, GA-49) carry the same columns and the same
``UNIQUE(investigation_id, target_id)`` guard. A concrete module join
row collapses to::

    class VRInvestigationTargetRecord(InvestigationTargetRecordBase, table=True):
        __tablename__ = "vr_investigation_targets"
        __investigation_tablename__ = "vr_investigations"
        __target_tablename__ = "vr_targets"

Many-to-many between the module's investigation table and target table with
a role column. The primary target stays redundant in
``<module>_investigations.target_id`` for backward compatibility + cost
attribution.

Team-scoped: rows are stamped with the owning team via ``TeamScopedMixin``
so the row-level scoping listener enforces the same guard the other
team-owned tables get (D-01 / D-07).
"""
from __future__ import annotations

from datetime import datetime
from typing import ClassVar
from uuid import uuid4

from sqlalchemy import DateTime, Text
from sqlmodel import Field, SQLModel

from aila.storage.mixins import TeamScopedMixin

from ._common import utc_now
from ._naming import TableDerivedConstraintsMixin, TabledFk, TabledUq

__all__ = ["InvestigationTargetRecordBase"]


class InvestigationTargetRecordBase(
    TableDerivedConstraintsMixin, TeamScopedMixin, SQLModel,
):
    """Shared columns for every module's investigation-target join table.

    A concrete subclass MUST set ``__tablename__``, ``__investigation_tablename__``,
    ``__target_tablename__``, and ``table=True``.
    """

    __investigation_tablename__: ClassVar[str]
    __target_tablename__: ClassVar[str]
    __table_args__ = (
        TabledUq("investigation_id", "target_id", suffix="investigation_target"),
        TabledFk("investigation_id", target_attr="__investigation_tablename__"),
        TabledFk("target_id", target_attr="__target_tablename__"),
    )

    id: str = Field(default_factory=lambda: str(uuid4()), primary_key=True)

    investigation_id: str = Field(index=True)
    target_id: str = Field(index=True)
    role: str = Field(default="comparison", max_length=32, index=True)
    rationale: str = Field(default="", sa_type=Text, sa_column_kwargs={"nullable": True})

    attached_at: datetime = Field(
        default_factory=utc_now,
        sa_type=DateTime(timezone=True),
    )
