"""Tools router for AILA REST API.

Provides read access to registered tool metadata and direct invocation.
POST /tools/{tool_key} requires operator+ role (D-20).
"""
from __future__ import annotations

import asyncio
import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status

from aila.api.auth import AuthContext, require_role, require_user_or_api_key
from aila.api.constants import (
    AUDIT_ACTION_TOOL_INVOKE,
    AUDIT_STAGE_TOOL,
    AUDIT_STATUS_COMPLETED,
    ROLE_OPERATOR,
    TRACK_PLATFORM,
)
from aila.api.deps import get_tool_registry
from aila.api.limiter import limiter
from aila.api.schemas.tools import (
    ToolDetailResponse,
    ToolInvokeRequest,
    ToolInvokeResponse,
    ToolSummaryResponse,
)
from aila.platform.runtime.tools import ToolRegistry
from aila.platform.services.audit import record_audit_event
from aila.storage.database import async_session_scope

__all__ = ["router"]

_log = logging.getLogger(__name__)

router = APIRouter(
    prefix="/tools",
    tags=["tools"],
    dependencies=[Depends(require_user_or_api_key)],
)


def _module_id_from_key(tool_key: str) -> str:
    """Derive module_id from tool key prefix (e.g. 'vuln.query_cves' -> 'vuln')."""
    return tool_key.split(".", maxsplit=1)[0] if "." in tool_key else TRACK_PLATFORM


@router.get("", response_model=list[ToolSummaryResponse], summary="List registered tools")
async def list_tools(
    request: Request,
) -> list[ToolSummaryResponse]:
    """Return summary info for all registered tools."""
    registry: ToolRegistry = get_tool_registry(request)  # type: ignore[assignment]

    def _collect() -> list[ToolSummaryResponse]:
        results: list[ToolSummaryResponse] = []
        try:
            keys = list(registry.keys)
        except (AttributeError, TypeError, RuntimeError):
            _log.warning("Tool registry keys lookup failed; returning empty tool list", exc_info=True)
            return results
        for key in keys:
            try:
                tool = registry.require(key)
                results.append(
                    ToolSummaryResponse(
                        tool_key=key,
                        name=getattr(tool, "name", key) or key,
                        description=getattr(tool, "description", "") or "",
                        module_id=_module_id_from_key(key),
                    )
                )
            except (AttributeError, KeyError, TypeError, RuntimeError):
                _log.warning("Skipping tool %r in list_tools due to error", key, exc_info=True)
                continue
        return results

    return await asyncio.to_thread(_collect)


@router.get("/{tool_key:path}", response_model=ToolDetailResponse, summary="Get tool schema")
async def get_tool(
    tool_key: str,
    request: Request,
) -> ToolDetailResponse:
    """Return full detail for a tool including input JSON schema and output type."""
    registry: ToolRegistry = get_tool_registry(request)  # type: ignore[assignment]

    def _get() -> ToolDetailResponse | None:
        try:
            tool = registry.require(tool_key)
        except KeyError:
            return None
        inputs: dict[str, object] = {}
        if hasattr(tool, "inputs"):
            raw_inputs = tool.inputs
            if isinstance(raw_inputs, dict):
                inputs = raw_inputs
        output_type = "string"
        if hasattr(tool, "output_type"):
            output_type = str(tool.output_type)
        return ToolDetailResponse(
            tool_key=tool_key,
            name=tool.name,
            description=tool.description,
            module_id=_module_id_from_key(tool_key),
            inputs=inputs,
            output_type=output_type,
        )

    result = await asyncio.to_thread(_get)
    if result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tool '{tool_key}' not registered -- list available tools via GET /tools",
        )
    return result


@limiter.limit("60/minute")
@router.post("/{tool_key:path}", response_model=ToolInvokeResponse, summary="Invoke a tool directly")
async def invoke_tool(
    tool_key: str,
    body: ToolInvokeRequest,
    request: Request,
    operator: AuthContext = Depends(require_role(ROLE_OPERATOR)),
) -> ToolInvokeResponse:
    """Invoke a registered tool directly with the provided kwargs.

    Requires operator role or higher. Tool errors are returned in the
    error field rather than raised as HTTP errors.
    """
    registry: ToolRegistry = get_tool_registry(request)  # type: ignore[assignment]

    def _invoke() -> tuple[object, str | None] | None:
        try:
            tool = registry.require(tool_key)
        except KeyError:
            return None
        try:
            result = tool.forward(**body.kwargs)
            return result, None
        except Exception as exc:
            _log.warning("Tool %s invocation failed: %s", tool_key, exc, exc_info=True)
            return None, str(exc)

    invoke_result = await asyncio.to_thread(_invoke)
    if invoke_result is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Tool '{tool_key}' not registered -- list available tools via GET /tools",
        )
    result, error = invoke_result

    async def _audit_invoke() -> None:
        async with async_session_scope() as session:
            record_audit_event(
                session,
                run_id=tool_key,
                stage=AUDIT_STAGE_TOOL,
                action=AUDIT_ACTION_TOOL_INVOKE,
                status=AUDIT_STATUS_COMPLETED,
                target=tool_key,
                user_id=operator.user_id,
                details={"error": error} if error else {},
            )
            await session.commit()

    await _audit_invoke()

    return ToolInvokeResponse(tool_key=tool_key, result=result, error=error)
