"""User account schemas for the AILA REST API.

Per D-13/D-17/D-18/D-19/D-20: user accounts with argon2id hashing,
admin-invite only, RBAC roles, NIST 800-63B password policy, soft-delete.

DataEnvelope wrapper is applied at the router level.
"""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

__all__ = [
    "LoginRequest",
    "LogoutRequest",
    "LogoutResponse",
    "RefreshTokenRequest",
    "RevokeSessionResponse",
    "TokenResponse",
    "UserCreateRequest",
    "UserSessionResponse",
    "UserUpdateRequest",
    "UserResponse",
]


class LoginRequest(BaseModel):
    """Request body for POST /auth/login."""

    username: str
    password: str


class RefreshTokenRequest(BaseModel):
    """Request body for POST /auth/refresh/user.

    #36: the refresh token was previously accepted as a URL query
    parameter, which leaked the long-lived credential into web-server
    access logs, browser history, and any intermediary that captures
    the request URI. Moving it to the JSON body keeps the token in the
    request stream that TLS protects and that access loggers redact by
    default.
    """

    refresh_token: str = Field(min_length=1)


class LogoutRequest(BaseModel):
    """Request body for POST /auth/logout.

    #36: the refresh token was previously accepted as a URL query
    parameter (same log/history leak as :class:`RefreshTokenRequest`);
    accepted in the JSON body now.
    """

    refresh_token: str = Field(min_length=1)


class TokenResponse(BaseModel):
    """Response body for POST /auth/login and POST /auth/refresh."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class UserCreateRequest(BaseModel):
    """Request body for POST /users (admin only).

    Per D-19: minimum 8-character password. No complexity rules (NIST 800-63B).
    Per D-17: admin-invite only -- admin calls this endpoint to create accounts.
    Per D-08: team_id is data isolation; group_id is access control.
    """

    username: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=8)
    email: str | None = None
    role: str = "operator"
    group_id: str | None = None
    team_id: str | None = None  # TEAM-02: data isolation boundary (D-08)


class UserUpdateRequest(BaseModel):
    """Request body for PATCH /users/{user_id} (admin only).

    Per D-20: is_active=False implements soft-delete.
    Per D-18: only admins can change roles; role must be in VALID_ROLES.
    Per D-08: team_id reassignment by admin.
    """

    email: str | None = None
    role: str | None = None
    group_id: str | None = None
    team_id: str | None = None  # TEAM-02: admin can reassign team
    is_active: bool | None = None


class UserResponse(BaseModel):
    """Response shape for a single user. Never includes hashed_password (T-138-04)."""

    id: str
    username: str
    email: str | None
    role: str
    group_id: str | None
    team_id: str | None = None  # TEAM-02: data isolation boundary
    is_active: bool
    created_at: datetime
    last_login_at: datetime | None


class LogoutResponse(BaseModel):
    """Response for POST /auth/logout confirming token revocation."""

    revoked: bool


class UserSessionResponse(BaseModel):
    """Active session metadata for GET /auth/sessions.

    Per T-140-18: token_hash is never returned -- only metadata.
    """

    id: str
    ip_address: str | None = None
    user_agent: str | None = None
    created_at: str | None = None
    expires_at: str | None = None


class RevokeSessionResponse(BaseModel):
    """Response for DELETE /auth/sessions/{session_id} confirming revocation."""

    revoked: str = Field(description="Session ID that was revoked")
