"""Auth request and response schemas for the AILA REST API."""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from aila.api.constants import ROLE_READER, TOKEN_TYPE_BEARER

from .common import APIModel

__all__ = [
    "ApiKeyCreateRequest",
    "ApiKeyCreateResponse",
    "ApiKeyListItem",
    "ApiKeyListResponse",
    "ApiKeyRevokeResponse",
    "RefreshRequest",
    "RefreshResponse",
    "TokenRequest",
    "TokenResponse",
]


class ApiKeyCreateRequest(APIModel):
    """Request body for POST /auth/keys."""

    role: Literal["admin", "operator", "reader"] = ROLE_READER
    label: str = ""


class ApiKeyCreateResponse(APIModel):
    """Response from POST /auth/keys. raw_key is shown once and never stored."""

    key_id: str
    raw_key: str
    key_prefix: str
    role: str
    label: str
    created_at: datetime


class ApiKeyListItem(APIModel):
    """One entry in GET /auth/keys response. Raw key is never returned."""

    key_id: str
    key_prefix: str
    role: str
    label: str
    created_by: str
    created_at: datetime
    revoked_at: datetime | None = None


class ApiKeyListResponse(APIModel):
    """Response from GET /auth/keys."""

    keys: list[ApiKeyListItem]


class TokenRequest(APIModel):
    """Request body for POST /auth/token."""

    api_key: str


class TokenResponse(APIModel):
    """Response from POST /auth/token."""

    access_token: str
    refresh_token: str
    token_type: str = TOKEN_TYPE_BEARER
    expires_in: int


class RefreshRequest(APIModel):
    """Request body for POST /auth/refresh."""

    refresh_token: str


class RefreshResponse(APIModel):
    """Response from POST /auth/refresh."""

    access_token: str
    token_type: str = TOKEN_TYPE_BEARER
    expires_in: int


class ApiKeyRevokeResponse(APIModel):
    """Response from DELETE /auth/keys/{key_id}."""

    key_id: str
    revoked: bool = True
