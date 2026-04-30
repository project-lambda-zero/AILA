"""Team-scoped query auto-filtering via SQLAlchemy do_orm_execute event (D-03).

The listener inspects every SELECT query. If TeamContext is set on the
session (via session.info["team_context"]) and the user is not admin,
it injects WHERE team_id = :team_id for any model that has a team_id column.

This is the PRIMARY enforcement mechanism for team data isolation.
PostgreSQL RLS (Plan 04) is defense-in-depth only.

Registration: call register_team_scope_listener() once during app startup,
after the async engine is created.
"""
from __future__ import annotations

import logging

from sqlalchemy import event
from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

_LISTENER_REGISTERED = False


def _inject_team_filter(orm_execute_state) -> None:
    """do_orm_execute listener that injects team_id WHERE clause.

    Only filters SELECT statements on models that have a team_id column.
    Admin sessions (is_admin=True or no TeamContext) bypass filtering entirely.
    """
    ctx = orm_execute_state.session.info.get("team_context")
    if ctx is None or ctx.is_admin:
        return  # admin or no context -- no filtering (TEAM-06)

    if not orm_execute_state.is_select:
        return  # only filter reads, not writes

    # Extract the mapped entity from the query
    # Handle both SQLModel select() and raw sa.select() patterns
    mapper = orm_execute_state.bind_arguments.get("mapper")
    if mapper is None:
        # Try to get mapper from the statement column_descriptions
        try:
            stmt = orm_execute_state.statement
            for col_desc in stmt.column_descriptions:
                entity = col_desc.get("entity")
                if entity is not None and hasattr(entity, "team_id"):
                    stmt = stmt.where(entity.team_id == ctx.team_id)
                    orm_execute_state.statement = stmt
                    return
        except (AttributeError, TypeError):
            return
        return

    entity = mapper.entity
    if not hasattr(entity, "team_id"):
        return  # global model -- no filtering

    stmt = orm_execute_state.statement
    stmt = stmt.where(entity.team_id == ctx.team_id)
    orm_execute_state.statement = stmt


def register_team_scope_listener() -> None:
    """Register the do_orm_execute listener globally on Session class.

    Safe to call multiple times -- the listener is only registered once.
    Call this during application startup (e.g., in database.py init_db or app lifespan).
    """
    global _LISTENER_REGISTERED
    if _LISTENER_REGISTERED:
        return
    event.listen(Session, "do_orm_execute", _inject_team_filter)
    _LISTENER_REGISTERED = True
    logger.info("Team scope do_orm_execute listener registered")
