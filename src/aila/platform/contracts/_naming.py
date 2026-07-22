"""Table-derived constraint + foreign-key naming for platform record bases (RFC-01).

Postgres constraint names live in one namespace per schema, not per table, so
two modules that copy the same base and name a constraint identically collide
at ``CREATE TABLE`` time (RFC-00 Common Mistake #21). Deriving names and
foreign-key targets from the concrete ``__tablename__`` (and sibling-table
class vars) removes that class of collision structurally.

A base declares deferred markers in ``__table_args__``:

    __table_args__ = (
        TabledUq("team_id", "slug", suffix="team_slug"),
        TabledFk("investigation_id", target_attr="__investigation_tablename__"),
        TabledFk("parent_branch_id"),  # self-referential -> subclass __tablename__
    )

``TableDerivedConstraintsMixin`` materializes them into real
``UniqueConstraint`` / ``ForeignKeyConstraint`` instances against the concrete
subclass at class-creation time. The ``@declared_attr`` approach the record
bases would otherwise use is rejected by SQLModel's Pydantic metaclass (a
non-annotated ``declared_attr`` attribute raises ``PydanticUserError``), so the
FK column is a plain field on the base and only the constraint is derived here.
"""
from __future__ import annotations

from sqlalchemy import ForeignKeyConstraint, UniqueConstraint

__all__ = ["TableDerivedConstraintsMixin", "TabledFk", "TabledUq"]


class TabledUq:
    """Deferred UniqueConstraint whose name resolves against __tablename__.

    A subclass with ``__tablename__ = "vr_workspaces"`` materializes
    ``UniqueConstraint(..., name="uq_vr_workspaces_team_slug")``.
    """

    __slots__ = ("columns", "suffix")

    def __init__(self, *columns: str, suffix: str) -> None:
        self.columns = columns
        self.suffix = suffix


class TabledFk:
    """Deferred ForeignKeyConstraint on local ``columns``.

    ``target_attr`` names a class variable on the concrete subclass holding
    the parent table name; when it is None the foreign key is self-referential
    (targets the subclass's own ``__tablename__``). ``refcolumns`` are the
    referenced columns on the parent (the primary key ``id`` by default).
    ``ondelete`` maps to the SQL ``ON DELETE`` action (e.g. ``"CASCADE"``) so a
    base preserves a concrete's cascade behavior; None means no ON DELETE
    clause.
    """

    __slots__ = ("columns", "target_attr", "refcolumns", "ondelete")

    def __init__(
        self,
        *columns: str,
        target_attr: str | None = None,
        refcolumns: tuple[str, ...] = ("id",),
        ondelete: str | None = None,
    ) -> None:
        self.columns = columns
        self.target_attr = target_attr
        self.refcolumns = refcolumns
        self.ondelete = ondelete


class TableDerivedConstraintsMixin:
    """Materialize TabledUq / TabledFk entries in __table_args__.

    ``__init_subclass__`` runs during class creation, before SQLModel's
    metaclass builds the mapped table, so the resolved constraint instances
    are in place when the mapper reads ``__table_args__``. The ``__tablename__``
    guard keeps abstract bases (no tablename) non-mapped.
    """

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        raw = getattr(cls, "__table_args__", ())
        tablename = cls.__dict__.get("__tablename__")
        if not raw or tablename is None:
            return
        resolved: list[object] = []
        for entry in raw:
            if isinstance(entry, TabledUq):
                resolved.append(
                    UniqueConstraint(*entry.columns, name=f"uq_{tablename}_{entry.suffix}"),
                )
            elif isinstance(entry, TabledFk):
                target = tablename if entry.target_attr is None else getattr(cls, entry.target_attr)
                resolved.append(
                    ForeignKeyConstraint(
                        list(entry.columns),
                        [f"{target}.{ref}" for ref in entry.refcolumns],
                        ondelete=entry.ondelete,
                    ),
                )
            else:
                resolved.append(entry)
        cls.__table_args__ = tuple(resolved)
