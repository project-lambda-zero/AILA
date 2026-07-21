"""Config router for AILA REST API.

Provides read/write access to module configuration via ConfigRegistry.
PUT /config/{namespace}/{key} requires admin role (D-11).

Note: ConfigRegistry does not expose a list() method; we query ConfigEntryRecord
directly via session_scope for list endpoints, and use registry.set() only for
the write path to ensure type validation through the registry.
"""
from __future__ import annotations

import math

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlmodel import select

from aila.api.auth import AuthContext, require_role, require_user_or_api_key
from aila.api.constants import (
    AUDIT_ACTION_CONFIG_UPDATE,
    AUDIT_STAGE_CONFIG,
    AUDIT_STATUS_COMPLETED,
    ROLE_ADMIN,
)
from aila.api.deps import get_config_registry
from aila.api.limiter import limiter
from aila.api.schemas.config import ConfigEntryResponse, ConfigListResponse, ConfigUpdateRequest
from aila.platform.services.audit import record_audit_event
from aila.storage.database import async_session_scope
from aila.storage.db_models import ConfigEntryRecord
from aila.storage.registry import is_secret_config_key

__all__ = ["router"]

router = APIRouter(
    prefix="/config",
    tags=["config"],
    dependencies=[Depends(require_user_or_api_key)],
)


_REDACTED_CONFIG_VALUE = "[REDACTED]"


def _entry_to_response(record: ConfigEntryRecord, *, redact: bool = False) -> ConfigEntryResponse:
    value = record.value
    if redact and is_secret_config_key(record.key):
        value = _REDACTED_CONFIG_VALUE
    return ConfigEntryResponse(
        namespace=record.namespace,
        key=record.key,
        value=value,
        value_type=record.value_type,
        updated_at=record.updated_at,
    )


@router.get("", response_model=ConfigListResponse, summary="List all config entries")
async def list_all_config(
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=250),
    auth: AuthContext = Depends(require_user_or_api_key),
) -> ConfigListResponse:
    """List all configuration entries across all namespaces."""
    redact = auth.role != "admin"

    async def _query() -> list[ConfigEntryRecord]:
        async with async_session_scope() as session:
            stmt = select(ConfigEntryRecord).order_by(
                ConfigEntryRecord.namespace, ConfigEntryRecord.key
            )
            return list((await session.exec(stmt)).all())

    rows = await _query()
    total = len(rows)
    offset = (page - 1) * page_size
    page_rows = rows[offset : offset + page_size]
    return ConfigListResponse(
        total=total,
        page=page,
        page_size=page_size,
        pages=math.ceil(total / page_size) if total > 0 else 0,
        items=[_entry_to_response(r, redact=redact) for r in page_rows],
    )


@router.get("/{namespace}", response_model=ConfigListResponse, summary="List config entries for a namespace")
async def list_namespace_config(
    namespace: str,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=250),
    auth: AuthContext = Depends(require_user_or_api_key),
) -> ConfigListResponse:
    """List all configuration entries for a module namespace."""
    redact = auth.role != "admin"

    async def _query() -> list[ConfigEntryRecord]:
        async with async_session_scope() as session:
            stmt = (
                select(ConfigEntryRecord)
                .where(ConfigEntryRecord.namespace == namespace)
                .order_by(ConfigEntryRecord.key)
            )
            return list((await session.exec(stmt)).all())

    rows = await _query()
    total = len(rows)
    offset = (page - 1) * page_size
    page_rows = rows[offset : offset + page_size]
    return ConfigListResponse(
        total=total,
        page=page,
        page_size=page_size,
        pages=math.ceil(total / page_size) if total > 0 else 0,
        items=[_entry_to_response(r, redact=redact) for r in page_rows],
    )


@router.get("/{namespace}/{key}", response_model=ConfigEntryResponse, summary="Get one config value")
async def get_config_value(
    namespace: str,
    key: str,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> ConfigEntryResponse:
    """Get a single configuration value by namespace and key."""
    redact = auth.role != "admin"

    async def _query() -> ConfigEntryRecord | None:
        async with async_session_scope() as session:
            stmt = select(ConfigEntryRecord).where(
                ConfigEntryRecord.namespace == namespace,
                ConfigEntryRecord.key == key,
            )
            result: ConfigEntryRecord | None = (await session.exec(stmt)).first()
            return result

    record = await _query()
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Config key '{namespace}/{key}' not found -- list available keys via GET /config/{namespace}",
        )
    return _entry_to_response(record, redact=redact)


@limiter.limit("60/minute")
@router.put(
    "/{namespace}/{key}",
    response_model=ConfigEntryResponse,
    summary="Update a config value (admin only)",
)
async def update_config_value(
    namespace: str,
    key: str,
    body: ConfigUpdateRequest,
    request: Request,
    admin: AuthContext = Depends(require_role(ROLE_ADMIN)),
) -> ConfigEntryResponse:
    """Write through ConfigRegistry to ensure type validation on the new value."""
    registry = get_config_registry(request)

    async def _update() -> ConfigEntryRecord | None:
        await registry.set(namespace, key, body.value)
        async with async_session_scope() as session:
            stmt = select(ConfigEntryRecord).where(
                ConfigEntryRecord.namespace == namespace,
                ConfigEntryRecord.key == key,
            )
            result: ConfigEntryRecord | None = (await session.exec(stmt)).first()
            if result is not None:
                secret = is_secret_config_key(key)
                audit_value = _REDACTED_CONFIG_VALUE if secret else body.value
                record_audit_event(
                    session,
                    run_id=f"{namespace}/{key}",
                    stage=AUDIT_STAGE_CONFIG,
                    action=AUDIT_ACTION_CONFIG_UPDATE,
                    status=AUDIT_STATUS_COMPLETED,
                    target=f"{namespace}/{key}",
                    user_id=admin.user_id,
                    team_id=admin.team_id,
                    details={
                        "namespace": namespace,
                        "key": key,
                        "value": audit_value,
                        "was_secret": secret,
                    },
                )
                await session.commit()
                await session.refresh(result)
            return result

    try:
        record = await _update()
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        )
    if record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Config key '{namespace}/{key}' not found after update -- the registry set() call may have failed silently",
        )
    return _entry_to_response(record)
