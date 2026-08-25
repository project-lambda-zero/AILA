"""RFC-11 -- admin CRUD + zero-trust gate for the MCP server instance catalog.

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
    GET    /platform/mcp/instances               list rows, optional module_scope filter
    POST   /platform/mcp/instances               create a new (pending) instance
    PATCH  /platform/mcp/instances/{id}          update endpoint / enabled / tags / team_id
    DELETE /platform/mcp/instances/{id}          remove an instance
    POST   /platform/mcp/instances/{id}/approve  pin the current tool schema hash (trust)
    POST   /platform/mcp/instances/{id}/revoke   flip to revoked with an operator reason
    GET    /platform/mcp/instances/{id}/tools    fetch live schema + drift comparison
"""
from __future__ import annotations

import hashlib
import json
import logging
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func as sa_func
from sqlalchemy import or_
from sqlalchemy.exc import IntegrityError
from sqlmodel import select

from aila.api.auth import AuthContext, require_user_or_api_key
from aila.api.constants import ROLE_ADMIN
from aila.api.limiter import limiter
from aila.api.schemas.envelope import DataEnvelope, PaginatedMeta
from aila.platform.mcp.factory import make_bridge
from aila.platform.mcp.instance_catalog import (
    TRANSPORT_HTTP,
    TRANSPORT_STDIO,
    McpInstanceCatalog,
    McpServerInstance,
)
from aila.storage.database import async_session_scope

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
    team_id: str | None = Field(default=None, max_length=128)
    instance_id: str | None = Field(default=None, max_length=128)


class McpInstancePatchRequest(BaseModel):
    """Partial-update body for :func:`patch_instance`."""

    model_config = ConfigDict(extra="forbid")

    endpoint: str | None = Field(default=None, min_length=1, max_length=1024)
    enabled: bool | None = Field(default=None)
    capability_tags: list[str] | None = Field(default=None)
    team_id: str | None = Field(default=None, max_length=128)


class McpInstanceRevokeRequest(BaseModel):
    """Body for :func:`revoke_instance` -- operator explanation is required."""

    model_config = ConfigDict(extra="forbid")

    reason: str = Field(min_length=1, max_length=2048)


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
    team_id: str | None
    approval_state: str
    approved_hash: str | None
    schema_hash: str | None
    has_server_card: bool
    created_at: str | None
    updated_at: str | None


class McpInstanceToolsResponse(BaseModel):
    """Body of :func:`list_instance_tools` -- live tool schema + drift check."""

    model_config = ConfigDict(extra="forbid")

    tools: list[dict[str, Any]]
    schema_hash: str
    approved_hash: str | None
    drift: bool


def _project(row: Any) -> McpInstanceResponse:
    payload = _CATALOG.instance_to_dict(row)
    return McpInstanceResponse(**payload)


def _flatten(values: list[str] | None) -> list[str] | None:
    """Collapse repeated + comma-OR query params into one filter list.

    Mirrors the helper in :mod:`aila.api.routers.audit`: repeated
    ``?key=v`` params AND a single ``?key=a,b`` value flatten identically
    to a stripped, de-duplicated, order-preserving list.
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


@router.get("")
@limiter.limit("60/minute")
async def list_instances(
    request: Request,
    module_scope: list[str] | None = Query(default=None),
    transport: list[str] | None = Query(default=None),
    approval_state: list[str] | None = Query(default=None),
    enabled: bool | None = Query(default=None),
    search: str | None = Query(default=None, max_length=256),
    limit: int = Query(default=50, ge=1, le=250),
    offset: int = Query(default=0, ge=0),
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[list[McpInstanceResponse]]:
    """List catalog rows with comma-OR filters + offset pagination.

    Every multi-value filter (``module_scope`` / ``transport`` /
    ``approval_state``) accepts repeated params AND a comma-joined value
    (see :func:`_flatten`). ``search`` is a case-insensitive substring
    match on both ``name`` and ``endpoint``. ``enabled`` narrows to a
    single boolean when supplied; omitted returns rows regardless of
    enable state. Response ``meta`` carries the pre-page ``total`` so
    the console can paginate.
    """
    del request, ctx
    scopes = _flatten(module_scope)
    transports = _flatten(transport)
    approvals = _flatten(approval_state)
    search_term = search.strip() if search and search.strip() else None
    async with async_session_scope() as session:
        base = select(McpServerInstance)
        if scopes is not None:
            base = base.where(McpServerInstance.module_scope.in_(scopes))  # type: ignore[union-attr]
        if transports is not None:
            base = base.where(McpServerInstance.transport.in_(transports))  # type: ignore[union-attr]
        if approvals is not None:
            base = base.where(McpServerInstance.approval_state.in_(approvals))  # type: ignore[union-attr]
        if enabled is not None:
            base = base.where(McpServerInstance.enabled.is_(enabled))
        if search_term:
            pattern = f"%{search_term}%"
            base = base.where(
                or_(
                    McpServerInstance.name.ilike(pattern),  # type: ignore[union-attr]
                    McpServerInstance.endpoint.ilike(pattern),  # type: ignore[union-attr]
                ),
            )
        count_stmt = select(sa_func.count()).select_from(base.subquery())
        total = int((await session.exec(count_stmt)).one() or 0)
        stmt = (
            base.order_by(McpServerInstance.module_scope, McpServerInstance.name)
            .offset(offset)
            .limit(limit)
        )
        rows = (await session.exec(stmt)).all()
    return DataEnvelope(
        data=[_project(r) for r in rows],
        meta=PaginatedMeta(total=total, offset=offset, limit=limit).model_dump(),
    )


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
            team_id=body.team_id,
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
    if (
        body.endpoint is None
        and body.enabled is None
        and body.capability_tags is None
        and body.team_id is None
    ):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "At least one of 'endpoint', 'enabled', "
                "'capability_tags', 'team_id' is required."
            ),
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
    if body.team_id is not None:
        row = await _CATALOG.update_team_id(instance_id, body.team_id)
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


def _canonical_schema_hash(specs: list[dict[str, Any]]) -> str:
    """Compute the sha256 pin for an MCP server's tool catalogue.

    The projection is deliberately narrow: only the tool ``name`` and
    the parameter shape (name, type, required, default) enter the hash.
    Free-text descriptions do NOT, so a server rewording a description
    without changing the callable surface does not force a re-approval
    (drift signals real schema change, not doc drift).
    """
    payload: list[dict[str, Any]] = []
    for entry in sorted(specs, key=lambda item: str(item.get("name") or "")):
        name = str(entry.get("name") or "")
        params_in = entry.get("params") or []
        params_out: list[dict[str, Any]] = []
        for p in sorted(params_in, key=lambda item: str(item.get("name") or "")):
            entry_out: dict[str, Any] = {
                "name": str(p.get("name") or ""),
                "type": str(p.get("type") or "any"),
                "required": bool(p.get("required")),
            }
            if "default" in p:
                entry_out["default"] = p["default"]
            params_out.append(entry_out)
        payload.append({"name": name, "params": params_out})
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


async def _fetch_live_specs(row: Any) -> list[dict[str, Any]]:
    """Return the ``compact_tool_spec`` list for ``row``'s server.

    Constructs a bridge through :func:`make_bridge` so both dispatch
    and the trust-gate handlers agree on the projection. A missing
    ``module_scope`` falls back to ``"platform"`` -- the same string
    the admin surface uses in its logs.
    """
    module_id = row.module_scope or "platform"
    bridge = make_bridge(row.name, module_id=module_id)
    try:
        return await bridge.list_tool_specs()
    finally:
        await bridge.aclose()


async def _fetch_server_card(row: Any) -> str | None:
    """Best-effort GET of the ``.well-known/mcp.json`` MCP Server Card.

    Returns the raw JSON body as a string, or ``None`` when the fetch
    fails for any reason (missing endpoint, network error, non-200
    response, malformed JSON). The approve handler treats a missing
    card as informational -- the operator still gets to pin the schema
    hash even when the server exposes no card.
    """
    module_id = row.module_scope or "platform"
    bridge = make_bridge(row.name, module_id=module_id)
    try:
        base_url = await bridge.base_url()
    except (RuntimeError, OSError, ValueError) as exc:
        _log.info(
            "mcp approve: base_url resolve failed for %s (%s: %s); "
            "skipping server card",
            row.id, type(exc).__name__, exc,
        )
        await bridge.aclose()
        return None
    url = f"{base_url.rstrip('/')}/.well-known/mcp.json"
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(url)
        if resp.status_code != 200:
            _log.info(
                "mcp approve: server card fetch for %s returned %d",
                row.id, resp.status_code,
            )
            return None
        # Validate JSON, but store the raw body so operators see the
        # exact bytes the server served at approval time.
        json.loads(resp.text)
        return resp.text
    except (httpx.HTTPError, json.JSONDecodeError, ValueError) as exc:
        _log.info(
            "mcp approve: server card fetch/parse for %s failed (%s: %s)",
            row.id, type(exc).__name__, exc,
        )
        return None
    finally:
        await bridge.aclose()


@router.post("/{instance_id}/approve")
@limiter.limit("10/minute")
async def approve_instance(
    request: Request,
    instance_id: str,
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[McpInstanceResponse]:
    """Pin the row's current tool-schema hash and flip trust to ``approved``.

    Fetches the live tool catalogue for the row's server via
    :func:`make_bridge` and computes the canonical sha256 pin. A
    best-effort ``GET /.well-known/mcp.json`` captures the MCP Server
    Card at the same moment; card-fetch failure is swallowed so the
    operator can still approve an instance that exposes no card.
    A 502 fires when the schema fetch itself fails (the operator must
    reach a live server before approving).
    """
    del request
    row = await _CATALOG.get_instance(instance_id)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"MCP instance '{instance_id}' not found",
        )
    try:
        specs = await _fetch_live_specs(row)
    except (httpx.HTTPError, RuntimeError, OSError, ValueError) as exc:
        _log.warning(
            "mcp approve: schema fetch failed for %s (%s: %s)",
            instance_id, type(exc).__name__, exc,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=(
                f"failed to fetch tool schema for '{instance_id}': "
                f"{type(exc).__name__}: {exc}"
            ),
        ) from exc
    schema_hash = _canonical_schema_hash(specs)
    server_card_json = await _fetch_server_card(row)
    approved = await _CATALOG.approve_instance(
        instance_id,
        schema_hash=schema_hash,
        approver=ctx.user_id,
        server_card_json=server_card_json,
    )
    if approved is None:
        # Row disappeared between the get_instance above and the
        # approve call -- surface as 404 rather than 500.
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"MCP instance '{instance_id}' not found",
        )
    return DataEnvelope(data=_project(approved))


@router.post("/{instance_id}/revoke")
@limiter.limit("30/minute")
async def revoke_instance(
    request: Request,
    instance_id: str,
    body: McpInstanceRevokeRequest,
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[McpInstanceResponse]:
    """Flip the row to ``revoked`` and record the operator explanation.

    A revoked row is invisible to the resolve path (which passes
    ``approved_only=True``) so live dispatch immediately stops targeting
    it. ``approved_hash`` is preserved so a later re-approval can
    compare against the prior pin. A 404 fires when the id is unknown.
    """
    del request
    row = await _CATALOG.revoke_instance(
        instance_id, approver=ctx.user_id, reason=body.reason,
    )
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"MCP instance '{instance_id}' not found",
        )
    return DataEnvelope(data=_project(row))


@router.get("/{instance_id}/tools")
@limiter.limit("30/minute")
async def list_instance_tools(
    request: Request,
    instance_id: str,
    ctx: AuthContext = Depends(_require_admin),
) -> DataEnvelope[McpInstanceToolsResponse]:
    """Return the live tool schema + drift flag against the pinned hash.

    The observed ``schema_hash`` is persisted onto the row so the
    operator UI can render historical drift without re-fetching every
    render. A 502 fires when the live schema fetch itself fails.
    """
    del request, ctx
    row = await _CATALOG.get_instance(instance_id)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"MCP instance '{instance_id}' not found",
        )
    try:
        specs = await _fetch_live_specs(row)
    except (httpx.HTTPError, RuntimeError, OSError, ValueError) as exc:
        _log.warning(
            "mcp tools: schema fetch failed for %s (%s: %s)",
            instance_id, type(exc).__name__, exc,
        )
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=(
                f"failed to fetch tool schema for '{instance_id}': "
                f"{type(exc).__name__}: {exc}"
            ),
        ) from exc
    schema_hash = _canonical_schema_hash(specs)
    await _CATALOG.record_schema_hash(instance_id, schema_hash)
    approved_hash = row.approved_hash
    return DataEnvelope(
        data=McpInstanceToolsResponse(
            tools=specs,
            schema_hash=schema_hash,
            approved_hash=approved_hash,
            drift=approved_hash is not None and approved_hash != schema_hash,
        ),
    )
