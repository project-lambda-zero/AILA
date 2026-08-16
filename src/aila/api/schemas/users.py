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

    #119: the refresh token is now issued as an ``HttpOnly`` cookie
    (``aila_refresh``) so JS -- and therefore XSS -- cannot read it.
    The endpoint reads the cookie directly; ``refresh_token`` here is
    an optional legacy hook for callers that still POST a body. New
    callers should send an empty body and let the browser attach the
    cookie automatically.

    #36 (retained): body-only was the previous shape. Query-parameter
    passing remains rejected with 422 because ``refresh_token`` is not
    exposed as a query field on the endpoint.
    """

    refresh_token: str | None = Field(default=None, min_length=1)


class LogoutRequest(BaseModel):
    """Request body for POST /auth/logout.

    #119: identical rationale to :class:`RefreshTokenRequest` -- the
    server now revokes the refresh token identified by the
    ``aila_refresh`` cookie and clears the auth cookies on the
    response. The body field remains optional for compatibility.
    """

    refresh_token: str | None = Field(default=None, min_length=1)


class TokenResponse(BaseModel):
    """Response body for POST /auth/login and POST /auth/refresh.

    #119: ``refresh_token`` is no longer returned by the user-password
    endpoints -- the value ships as an ``HttpOnly`` cookie so no
    script (including XSS) can read it. The field is kept optional on
    the wire so the API-key ``POST /auth/token`` path (Bearer flow,
    schemas.auth.TokenResponse) can still populate it if needed by
    non-browser clients; user-facing endpoints leave it ``None``.
    """

    access_token: str
    refresh_token: str | None = None
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
