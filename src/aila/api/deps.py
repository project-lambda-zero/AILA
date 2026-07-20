"""FastAPI dependency functions for AILA.

Provides get_platform(), get_config_registry(), get_tool_registry(), and
get_task_queue() for injection into route handlers. Do NOT use session_scope
as a FastAPI dependency directly -- see RESEARCH Pitfall 3 (deadlock under load).
"""
from __future__ import annotations

from collections.abc import AsyncGenerator
from typing import TYPE_CHECKING, TypeVar

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import SQLModel, select

from aila.api.auth import AuthContext, TeamContext, require_user_or_api_key
from aila.platform.contracts.platform import AsyncTaskQueue
from aila.platform.runtime import AILAPlatform
from aila.platform.uow import UnitOfWork
from aila.storage.database import async_session_scope

T = TypeVar("T", bound=SQLModel)

if TYPE_CHECKING:
    from aila.platform.modules.protocol import ModuleProtocol
    from aila.platform.runtime.tools import ToolRegistry
    from aila.storage.registry import ConfigRegistry


def get_registered_module(request: Request, module_id: str) -> ModuleProtocol:
    """Return a registered module through the platform registry.

    API routes use this helper instead of importing module internals directly.
    """
    from fastapi import HTTPException, status

    platform: AILAPlatform | None = request.app.state.platform
    if platform is None or not hasattr(platform, "runtime") or platform.runtime is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Platform not initialized -- module registry unavailable; check server logs and restart the API server",
        )
    try:
        return platform.runtime.module_registry.require(module_id)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Module '{module_id}' is not registered.",
        ) from exc

__all__ = [
    "get_config_registry",
    "get_platform",
    "get_registered_module",
    "get_task_queue",
    "get_team_context_or_admin",
    "get_tool_registry",
    "owned_or_404",
    "require_team_context",
    "team_scoped_session",
    "team_scoped_uow",
]


def require_team_context(
    auth: AuthContext = Depends(require_user_or_api_key),
) -> TeamContext:
    """Return the caller's TeamContext, refusing a non-admin token with no team_id.

    A non-admin principal whose ``team_id`` is None is a broken token; reject
    403 rather than silently promoting it to the admin (unfiltered) view.
    """
    if auth.team_id is None and auth.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authenticated principal has no team_id",
        )
    return TeamContext.from_auth(auth)


def get_team_context_or_admin(
    auth: AuthContext = Depends(require_user_or_api_key),
) -> TeamContext:
    """Return the caller's TeamContext; admin (team_id=None) bypasses filtering."""
    return TeamContext.from_auth(auth)


async def team_scoped_session(
    ctx: TeamContext = Depends(require_team_context),
) -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency: yield a session whose info carries TeamContext.

    The C1 do_orm_execute listener then filters every SELECT on a team-scoped
    model for that session automatically.
    """
    async with async_session_scope(team_context=ctx) as session:
        yield session


async def team_scoped_uow(
    ctx: TeamContext = Depends(require_team_context),
) -> AsyncGenerator[UnitOfWork, None]:
    """FastAPI dependency: yield an entered UnitOfWork with TeamContext bound."""
    async with UnitOfWork(team_context=ctx) as uow:
        yield uow


async def owned_or_404(
    session: AsyncSession,
    model: type[T],
    pk: object,
    *,
    detail: str | None = None,
) -> T:
    """Load one row by PK through the team-scope listener and enforce ownership.

    Uses ``session.exec(select(...))`` rather than ``session.get()``: the
    identity-map fast path of ``session.get`` bypasses the do_orm_execute team
    filter, which is the #57 IDOR class. Returns 404 -- never 403 -- when the
    row is missing or owned by another team, so no cross-tenant existence
    oracle leaks. Admin sessions (no team_context) see any row.
    """
    pk_attr = model.__mapper__.primary_key[0].name  # type: ignore[attr-defined]
    stmt = select(model).where(getattr(model, pk_attr) == pk)
    record = (await session.exec(stmt)).first()  # type: ignore[call-overload]
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=detail or f"{model.__name__} '{pk}' not found",
        )
    return record


def get_platform(request: Request) -> AILAPlatform:
    """Return the AILAPlatform singleton stored in app.state by the lifespan context."""
    return request.app.state.platform  # type: ignore[no-any-return]


def get_config_registry(request: Request) -> ConfigRegistry:
    """FastAPI dependency that validates platform initialization before exposing the registry."""
    from fastapi import HTTPException, status

    platform: AILAPlatform | None = request.app.state.platform
    if platform is None or not hasattr(platform, "runtime") or platform.runtime is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Platform not initialized -- config registry unavailable; check server logs and restart the API server",
        )
    registry = platform.runtime.config_registry
    if registry is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Config registry is None despite platform being initialized -- check server logs for startup errors",
        )
    return registry


def get_tool_registry(request: Request) -> ToolRegistry:
    """FastAPI dependency that validates platform initialization before exposing tools."""
    from fastapi import HTTPException, status

    platform: AILAPlatform | None = request.app.state.platform
    if platform is None or not hasattr(platform, "runtime") or platform.runtime is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Platform not initialized -- tool registry unavailable; check server logs and restart the API server",
        )
    return platform.runtime.tool_registry


def get_task_queue(module_id: str, request: Request) -> AsyncTaskQueue:
    """Return the platform-backed AsyncTaskQueue for the given module.

    Modules call this from route handlers and receive an AsyncTaskQueue Protocol
    instance -- not the concrete TaskQueue class. The queue is constructed from
    the initialized platform runtime so config and module boundary enforcement
    come from one place.

    Args:
        module_id: The calling module's ID (e.g. "vulnerability").
        request: FastAPI Request providing access to app.state.platform.

    Returns:
        An AsyncTaskQueue Protocol instance backed by the platform TaskQueue.

    Raises:
        HTTPException(503): If the platform runtime or config registry is unavailable.
    """
    from fastapi import HTTPException, status

    from aila.platform.tasks.queue import TaskQueue

    platform: AILAPlatform | None = request.app.state.platform
    if platform is None or not hasattr(platform, "runtime") or platform.runtime is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Platform not initialized -- task queue unavailable; check server logs and restart the API server",
        )
    registry = platform.runtime.config_registry
    if registry is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Config registry is None despite platform being initialized -- task queue unavailable",
        )

    return TaskQueue(
        config_registry=registry,
        module_id=module_id,
    )
