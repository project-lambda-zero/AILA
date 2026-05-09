"""Mixins for storage model cross-cutting concerns.

TeamScopedMixin provides the team_id column used by all team-scoped models
(D-01). The column is nullable at the database level because:
  1. Admin-owned records have team_id=NULL (TEAM-06).
  2. The three-step migration (D-05) adds the column nullable first.

Models that require non-null team_id enforce this at the application layer
via StorageService.save() auto-stamping (D-07).
"""
from __future__ import annotations

from sqlmodel import Field


class TeamScopedMixin:
    """Mixin that adds an indexed team_id column to team-scoped models.

    Inherit from this mixin alongside SQLModel for any table that stores
    team-owned data. The do_orm_execute listener (team_scope.py) uses the
    presence of this column to decide whether to inject WHERE team_id = ?.

    Uses sa_column_kwargs for index=True so each subclass gets its own
    Column instance (sa_column= would share a single Column object).

    __allow_unmapped__ permits SQLAlchemy 2.0 to accept non-Mapped[]
    annotations on mixin classes used with SQLModel.

    Usage:
        class MyRecord(TeamScopedMixin, SQLModel, table=True):
            ...
    """

    __allow_unmapped__ = True

    team_id: str | None = Field(
        default=None,
        sa_column_kwargs={"nullable": True, "index": True},
    )
