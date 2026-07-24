"""RFC-11 step 1 -- admin CRUD for the MCP server instance catalog.

Operator surface for the ``mcp_server_instances`` table. This router is
the *catalog* administration path; the live dispatch path
(:class:`aila.platform.mcp.registry.McpRegistryServiceBase` and every
bridge under :mod:`aila.platform.mcp.bridges`) reads catalog rows via
:class:`~aila.platform.mcp.instance_catalog.McpInstanceCatalog` and is
never called from this router. The bridge / tool_executor call graph
stays byte-identical -- this surface only writes rows the resolver may
consult on the next request.

All endpoints require god-tier admin (``team_id=None``): MCP instance
targeting is platform-wide, not team-scoped, matching the audit rules
in :mod:`aila.api.routers.admin_prompts`. Every request is
rate-limited. Responses use :class:`DataEnvelope` per D-27.

Endpoints:
    GET    /platform/mcp/instances           list rows, optional module_scope filter
    POST   /platform/mcp/instances           create a new instance
    PATCH  /platform/mcp/instances/{id}      update endpoint / enabled / tags
    DELETE /platform/mcp/instances/{id}      remove an instance
"""
from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.exc import IntegrityError

from aila.api.auth import AuthContext, require_user_or_api_key
from aila.api.constants import ROLE_ADMIN
from aila.api.limiter import limiter
from aila.api.schemas.envelope import DataEnvelope
from aila.platform.mcp.instance_catalog import (
    TRANSPORT_HTTP,
    TRANSPORT_STDIO,
    McpInstanceCatalog,
)

__all__ = ["router"]

_log = logging.getLogger(__name__)

_CATALOG = McpInstanceCatalog()

_ALLOWED_TRANSPORTS: frozenset[str] = frozenset({TRANSPORT_HTTP, TRANSPORT_STDIO})


async def _require_admin(
    ctx: AuthContext = Depends(require_user_or_api_key),
) -> AuthContext:
    """Restrict every endpoint to god-tier admins (``team_id=None``).

    MCP instance targeting decides which workstation every module
    dispatches to, so a team-scoped admin is refused. Matches the same
    guard applied by RFC-09 and RFC-08 admin routers.
    """
    if ctx.role != ROLE_ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Requires '{ROLE_ADMIN}' role; current role: '{ctx.role}'",
        )
    if ctx.team_id is not None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="MCP instance catalog administration is restricted to god-tier administrators.",
        )
    return ctx


router = APIRouter(
    prefix="/platform/mcp/instances",
    tags=["platform-mcp"],
    dependencies=[Depends(_require_admin)],
)


class McpInstanceCreateRequest(BaseModel):
    """Request body for :func:`create_instance`."""

    model_config = ConfigDict(extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    transport: str = Field(default=TRANSPORT_HTTP, max_length=16)
    endpoint: str = Field(min_length=1, max_length=1024)
    capability_tags: list[str] = Field(default_factory=list)
    enabled: bool = Field(default=True)
    module_scope: str | None = Field(default=None, max_length=64)
    instance_id: str | None = Field(default=None, max_length=128)


class McpInstancePatchRequest(BaseModel):
    """Partial-update body for :func:`patch_instance`."""

    model_config = ConfigDict(extra="forbid")

    endpoint: str | None = Field(default=None, min_length=1, max_length=1024)
    enabled: bool | None = Field(default=None)
    capability_tags: list[str] | None = Field(default=None)


class McpInstanceResponse(BaseModel):
    """Projection returned by every endpoint on success."""

    model_config = ConfigDict(extra="forbid")

    id: str
    name: str
    transport: str
    endpoint: str
    capability_tags: list[str]
    enabled: bool
    module_scope: str | None
    created_at: str | None
    updated_at: str | None


def _project(row: Any) -> McpInstanceResponse:
    payload = _CATALOG.instance_to_dict(row)
    return McpInstanceResponse(**payload)


@router.get("")
@limiter.limit("60/minute")
async def list_instances(
    request: Request,
    module_scope: str | None = Query(default=None, max_length=64),
    include_disabled: bool = Query(default=True),
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[list[McpInstanceResponse]]:
    """List catalog rows.

    ``module_scope`` filters to a single namespace. ``include_disabled``
    defaults true so the operator sees temporarily-disabled rows.
    """
    del request, ctx
    rows = await _CATALOG.list_instances(
        module_scope=module_scope, include_disabled=include_disabled,
    )
    return DataEnvelope(data=[_project(r) for r in rows])


@router.post("", status_code=status.HTTP_201_CREATED)
@limiter.limit("30/minute")
async def create_instance(
    request: Request,
    body: McpInstanceCreateRequest,
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[McpInstanceResponse]:
    """Insert a new catalog row.

    A 400 fires when ``transport`` is not ``http`` or ``stdio``. A 409
    fires when the ``(module_scope, name)`` uniqueness constraint is
    violated (Postgres raises ``IntegrityError``).
    """
    del request, ctx
    if body.transport not in _ALLOWED_TRANSPORTS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"unknown transport {body.transport!r}; "
                f"expected one of {sorted(_ALLOWED_TRANSPORTS)}"
            ),
        )
    try:
        row = await _CATALOG.add_instance(
            name=body.name,
            transport=body.transport,
            endpoint=body.endpoint,
            capability_tags=body.capability_tags,
            enabled=body.enabled,
            module_scope=body.module_scope,
            instance_id=body.instance_id,
        )
    except IntegrityError as exc:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"instance already exists for (module_scope, name): {exc.orig}",
        ) from exc
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc),
        ) from exc
    return DataEnvelope(data=_project(row))


@router.patch("/{instance_id}")
@limiter.limit("60/minute")
async def patch_instance(
    request: Request,
    instance_id: str,
    body: McpInstancePatchRequest,
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[McpInstanceResponse]:
    """Update one or more mutable fields on a catalog row.

    Fields absent from the body are left unchanged. Every update stamps
    ``updated_at`` even when the value is identical, so the audit trail
    always records the intent. A 404 fires when the id is unknown.
    """
    del request, ctx
    if body.endpoint is None and body.enabled is None and body.capability_tags is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="At least one of 'endpoint', 'enabled', 'capability_tags' is required.",
        )
    row = None
    if body.endpoint is not None:
        row = await _CATALOG.update_endpoint(instance_id, body.endpoint)
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"MCP instance '{instance_id}' not found",
            )
    if body.enabled is not None:
        row = await _CATALOG.set_enabled(instance_id, body.enabled)
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"MCP instance '{instance_id}' not found",
            )
    if body.capability_tags is not None:
        row = await _CATALOG.update_capability_tags(
            instance_id, body.capability_tags,
        )
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"MCP instance '{instance_id}' not found",
            )
    if row is None:
        # Defensive branch -- earlier guard on all-None body already 400s,
        # so this path is only reachable if a field is set but the update
        # helper returned None without raising (shouldn't happen).
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"MCP instance '{instance_id}' not found",
        )
    return DataEnvelope(data=_project(row))


@router.delete("/{instance_id}", status_code=status.HTTP_204_NO_CONTENT)
@limiter.limit("30/minute")
async def delete_instance(
    request: Request,
    instance_id: str,
    ctx: AuthContext = Depends(_require_admin),
) -> None:
    """Remove a catalog row by id. A 404 fires when the id is unknown."""
    del request, ctx
    removed = await _CATALOG.remove_instance(instance_id)
    if not removed:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"MCP instance '{instance_id}' not found",
        )
