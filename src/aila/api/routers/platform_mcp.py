"""Platform-owned MCP operator surface: server health + call-log audit trail.

Consolidates the pre-req-10/40 per-module operator MCP routes into one
platform surface. Health probing composes over the module-
declared descriptors published to
:class:`aila.platform.mcp.capability_registry.McpCapabilityRegistry`; the
call-log read pulls rows from the consolidated
:class:`aila.platform.mcp.call_log_record.McpCallLogRecord` table (migration
136).

Endpoints:
    GET   /platform/mcp/servers       list every declared server with a live probe
    PATCH /platform/mcp/servers/{id}  retarget one server's ``base_url``
                                       (id = ``"<module_scope>:<server_id>"``)
    GET   /platform/mcp/calls         paged read of the platform call-log

Auth:
    ``GET`` endpoints: reader auth (``require_user_or_api_key``) so any
    authenticated operator sees the surface.
    ``PATCH`` endpoint: god-tier admin only, mirroring the trust posture on
    :mod:`aila.api.routers.mcp_instances` (server targeting is platform-wide).
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, ClassVar

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func as sa_func
from sqlmodel import select

from aila.api.auth import AuthContext, require_user_or_api_key
from aila.api.limiter import limiter
from aila.api.routers.mcp_instances import _require_admin
from aila.api.schemas.envelope import DataEnvelope, PaginatedMeta
from aila.platform.mcp.call_log_record import McpCallLogRecord
from aila.platform.mcp.capability_registry import (
    ModuleDescriptorDeclaration,
    default_capability_registry,
)
from aila.platform.mcp.registry import McpRegistryServiceBase
from aila.platform.uow import UnitOfWork

__all__ = ["router"]


router = APIRouter(prefix="/platform/mcp", tags=["platform-mcp"])


def _flatten(values: list[str] | None) -> list[str] | None:
    """Collapse repeated + comma-OR query params into one filter list.

    Mirrors the shape in :mod:`aila.api.routers.audit` /
    :mod:`aila.api.routers.llm_log`: repeated ``?key=v`` params AND a
    single ``?key=a,b`` value flatten identically to a stripped,
    de-duplicated, order-preserving list. Empty input returns ``None``
    so the caller can skip filter application entirely.
    """
    if not values:
        return None
    out: list[str] = []
    for raw in values:
        for part in raw.split(","):
            token = part.strip()
            if token and token not in out:
                out.append(token)
    return out or None


def _spec_from_descriptor(decl: ModuleDescriptorDeclaration) -> dict[str, str]:
    """Adapt a :class:`ModuleDescriptorDeclaration` to a probe-spec dict.

    The platform :class:`McpRegistryServiceBase` reads a ``_servers`` tuple
    of dicts keyed on ``id`` / ``name`` / ``description`` / ``env_var`` /
    ``config_key`` / ``default_url``; this function transcribes one
    descriptor into that shape so we can reuse the probe logic without
    subclassing per module.
    """
    d = decl.descriptor
    return {
        "id": d.name,
        "name": d.name,
        "description": d.description or "",
        "env_var": d.env_var,
        "config_key": d.config_key,
        "default_url": d.default_url,
    }


def _svc_for(module_scope: str, spec: dict[str, str]) -> McpRegistryServiceBase:
    """Construct an ad-hoc :class:`McpRegistryServiceBase` for one server.

    The registry base is module-agnostic but reads its scope + server catalog
    from ClassVars; instantiating a per-server, per-scope anonymous subclass
    keeps the probe + update paths byte-identical to the module-owned
    subclasses without importing them (RFC-05 direction: platform never
    names a module).
    """

    class _AdHocService(McpRegistryServiceBase):
        _module_id: ClassVar[str] = module_scope
        _servers: ClassVar[tuple[dict[str, str], ...]] = (spec,)

    return _AdHocService()


def _decorate_row(
    row: dict[str, Any], *, module_scope: str,
) -> dict[str, Any]:
    """Wrap the base probe projection with the composite id + module scope.

    The row is otherwise byte-identical to what
    :meth:`McpRegistryServiceBase._probe` produced pre-consolidation; the
    console reads ``id`` / ``module_scope`` / ``server_id`` off the
    envelope directly.
    """
    server_id = str(row.get("id") or "")
    row["module_scope"] = module_scope
    row["server_id"] = server_id
    row["id"] = f"{module_scope}:{server_id}"
    return row


def _split_composite(instance_id: str) -> tuple[str, str] | None:
    """Split ``"<module_scope>:<server_id>"`` at the FIRST colon.

    Server ids never contain a colon by convention (see the RFC-11
    descriptor validation), so the first colon is unambiguous. Returns
    ``None`` for a malformed id (no colon, or empty scope / server_id)
    so the router can 404 uniformly.
    """
    if ":" not in instance_id:
        return None
    scope, sep, name = instance_id.partition(":")
    if not sep or not scope.strip() or not name.strip():
        return None
    return scope.strip(), name.strip()


def _find_declaration(
    module_scope: str, server_id: str,
) -> ModuleDescriptorDeclaration | None:
    """Look up one declared descriptor by ``(module_scope, name)``."""
    for decl in default_capability_registry().declarations(
        module_scope=module_scope,
    ):
        if decl.descriptor.name == server_id:
            return decl
    return None


class McpServerBaseUrlPatch(BaseModel):
    """Body for :func:`patch_mcp_server` -- retarget one server's endpoint."""

    model_config = ConfigDict(extra="forbid")

    base_url: str = Field(min_length=1, max_length=1024)


@router.get("/servers")
@limiter.limit("60/minute")
async def list_mcp_servers(
    request: Request,
    module_scope: str | None = Query(default=None, max_length=512),
    ctx: AuthContext = Depends(require_user_or_api_key),
) -> DataEnvelope[list[dict[str, Any]]]:
    """List every declared MCP server with a live probe projection.

    Composes over :func:`default_capability_registry` so the surface is
    strictly module-declared: whatever modules published descriptors at
    startup determines the row set. The optional ``module_scope`` query
    accepts a comma-OR list (``?module_scope=vr,malware``).
    """
    del request, ctx
    wanted = _flatten([module_scope] if module_scope else None)
    rows: list[dict[str, Any]] = []
    for decl in default_capability_registry().declarations():
        if wanted is not None and decl.module_scope not in wanted:
            continue
        spec = _spec_from_descriptor(decl)
        svc = _svc_for(decl.module_scope, spec)
        probed = await svc._probe(spec)
        rows.append(_decorate_row(probed, module_scope=decl.module_scope))
    return DataEnvelope(data=rows)


@router.patch(
    "/servers/{instance_id}",
    dependencies=[Depends(_require_admin)],
)
@limiter.limit("30/minute")
async def patch_mcp_server(
    request: Request,
    instance_id: str,
    body: McpServerBaseUrlPatch,
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[dict[str, Any]]:
    """Retarget one declared server's ``base_url`` via ConfigRegistry.

    The composite id is ``"<module_scope>:<server_id>"``. Persistence goes
    through the module's ConfigRegistry namespace so the operator override
    survives restart and layers over the code-embedded default. The
    response is a fresh probe of the same server.
    """
    del request, ctx
    parts = _split_composite(instance_id)
    if parts is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"MCP server {instance_id!r} not declared.",
        )
    module_scope, server_id = parts
    decl = _find_declaration(module_scope, server_id)
    if decl is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"MCP server {instance_id!r} not declared.",
        )
    spec = _spec_from_descriptor(decl)
    svc = _svc_for(module_scope, spec)
    result = await svc.update_base_url(server_id, body.base_url.strip())
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"MCP server {instance_id!r} not declared.",
        )
    return DataEnvelope(data=_decorate_row(result, module_scope=module_scope))


@router.get("/calls")
@limiter.limit("60/minute")
async def list_mcp_calls(
    request: Request,
    module_scope: list[str] | None = Query(default=None),
    server_id: str | None = Query(default=None, max_length=64),
    status_filter: list[str] | None = Query(default=None, alias="status"),
    called_at_since: datetime | None = Query(default=None),
    called_at_until: datetime | None = Query(default=None),
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=100, ge=1, le=500),
    ctx: AuthContext = Depends(require_user_or_api_key),
) -> DataEnvelope[list[dict[str, Any]]]:
    """Paged read of the consolidated platform MCP call-log table."""
    del request
    scopes = _flatten(module_scope)
    statuses = _flatten(status_filter)
    async with UnitOfWork() as uow:
        base = select(McpCallLogRecord)
        if ctx.team_id is not None:
            base = base.where(McpCallLogRecord.team_id == ctx.team_id)
        if scopes is not None:
            base = base.where(McpCallLogRecord.module_scope.in_(scopes))  # type: ignore[union-attr]
        if server_id:
            base = base.where(McpCallLogRecord.server_id == server_id)
        if statuses is not None:
            base = base.where(McpCallLogRecord.status.in_(statuses))  # type: ignore[union-attr]
        if called_at_since is not None:
            base = base.where(McpCallLogRecord.called_at >= called_at_since)
        if called_at_until is not None:
            base = base.where(McpCallLogRecord.called_at <= called_at_until)
        count_stmt = select(sa_func.count()).select_from(base.subquery())
        total = int((await uow.session.exec(count_stmt)).one() or 0)
        stmt = (
            base.order_by(McpCallLogRecord.called_at.desc())  # type: ignore[union-attr]
            .offset(offset)
            .limit(limit)
        )
        rows = (await uow.session.exec(stmt)).all()
    items = [
        {
            "id": r.id,
            "module_scope": r.module_scope,
            "server_id": r.server_id,
            "base_url": r.base_url,
            "action": r.action,
            "status": r.status,
            "http_status": r.http_status,
            "latency_ms": r.latency_ms,
            "error_excerpt": r.error_excerpt,
            "target_id": r.target_id,
            "team_id": r.team_id,
            "instance_id": r.instance_id,
            "investigation_id": r.investigation_id,
            "branch_id": r.branch_id,
            "turn_number": r.turn_number,
            "called_at": r.called_at.isoformat() if r.called_at else None,
        }
        for r in rows
    ]
    return DataEnvelope(
        data=items,
        meta=PaginatedMeta(total=total, offset=offset, limit=limit).model_dump(),
    )
