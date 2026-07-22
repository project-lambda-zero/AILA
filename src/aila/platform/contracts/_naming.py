"""Table-derived constraint naming for platform record bases (RFC-01).

Postgres constraint names live in one namespace per schema, not per table,
so two modules that copy the same base and name a constraint identically
collide at ``CREATE TABLE`` time (RFC-00 Common Mistake #21). Deriving every
constraint name from the concrete ``__tablename__`` removes that class of
collision structurally: a base declares ``TabledUq("team_id", "slug",
suffix="team_slug")`` and a subclass with ``__tablename__ = "vr_workspaces"``
materializes ``UniqueConstraint(..., name="uq_vr_workspaces_team_slug")``.
"""
from __future__ import annotations

from sqlalchemy import UniqueConstraint

__all__ = ["TableDerivedConstraintsMixin", "TabledUq"]


class TabledUq:
    """Deferred UniqueConstraint whose name resolves against __tablename__.

    Placed in a base's ``__table_args__``; ``TableDerivedConstraintsMixin``
    materializes it into a real ``UniqueConstraint`` named
    ``uq_{__tablename__}_{suffix}`` when a concrete subclass is created::

        __table_args__ = (TabledUq("team_id", "slug", suffix="team_slug"),)
    """

    __slots__ = ("columns", "suffix")

    def __init__(self, *columns: str, suffix: str) -> None:
        self.columns = columns
        self.suffix = suffix


class TableDerivedConstraintsMixin:
    """Materialize TabledUq entries in __table_args__ using __tablename__.

    ``__init_subclass__`` runs during class creation, before SQLModel's
    metaclass builds the mapped table, so the resolved ``UniqueConstraint``
    instances are in place when the mapper reads ``__table_args__``. The
    ``__tablename__`` guard keeps abstract bases (no tablename) non-mapped.
    """

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        raw = getattr(cls, "__table_args__", ())
        tablename = cls.__dict__.get("__tablename__")
        if not raw or tablename is None:
            return
        cls.__table_args__ = tuple(
            UniqueConstraint(*entry.columns, name=f"uq_{tablename}_{entry.suffix}")
            if isinstance(entry, TabledUq)
            else entry
            for entry in raw
        )
