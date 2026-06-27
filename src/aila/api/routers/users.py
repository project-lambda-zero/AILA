"""Users router for AILA REST API.

Provides user account management and username/password authentication.

Endpoints:
  POST /auth/login          -- Authenticate with username/password, get JWT tokens (PUBLIC)
  POST /auth/refresh/user   -- Exchange user refresh token for new access token (PUBLIC)
  POST /auth/logout         -- Revoke a user refresh token (PUBLIC with valid token)
  GET  /users               -- List users, paginated (ADMIN only)
  POST /users               -- Create user account (ADMIN only)
  GET  /users/{user_id}     -- Get a single user (ADMIN only)
  PATCH /users/{user_id}    -- Update user fields, including soft-delete (ADMIN only)

Per D-13: argon2id password hashing.
Per D-17: admin-invite only registration.
Per D-18: RBAC admin/operator/reader.
Per D-19: NIST 800-63B password policy with HaveIBeenPwned breach check.
Per D-20: soft-delete via is_active=False.
Per D-26: offset/limit pagination with total count.
Per D-27: DataEnvelope response wrapper.
Per D-46: all auth events dual-written to structlog AND AuditEventRecord.
Per T-138-04: hashed_password never returned in any response.
Per T-138-05: login endpoint protected by rate limiting (via slowapi if available).
Per T-138-10: login failure returns generic "Invalid credentials".
"""
from __future__ import annotations

import hashlib
import logging
from datetime import UTC, datetime
from uuid import uuid4

import httpx
import structlog
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlmodel import func, select

from aila.api.auth import (
    ROLE_LEVELS,
    AuthContext,
    hash_user_password,
    issue_user_jwt,
    issue_user_refresh_token,
    require_user_or_api_key,
    verify_user_password,
)
from aila.api.constants import (
    AUDIT_STAGE_AUTH,
    AUDIT_STATUS_COMPLETED,
    JWT_TYP_USER_REFRESH,
    ROLE_ADMIN,
    VALID_ROLES,
)
from aila.api.limiter import limiter
from aila.api.metrics import SILENT_FAILURE_TOTAL
from aila.api.schemas.envelope import DataEnvelope
from aila.api.schemas.users import (
    LoginRequest,
    LogoutResponse,
    RevokeSessionResponse,
    TokenResponse,
    UserCreateRequest,
    UserResponse,
    UserSessionResponse,
    UserUpdateRequest,
)
from aila.config import get_settings
from aila.platform.contracts._common import utc_now
from aila.platform.services.audit import record_audit_event
from aila.storage.database import async_session_scope
from aila.storage.db_models import RefreshTokenRecord, UserRecord

__all__ = ["router"]

_log = logging.getLogger(__name__)
_slog = structlog.get_logger(__name__)

router = APIRouter(tags=["users"])


async def _require_admin(ctx: AuthContext = Depends(require_user_or_api_key)) -> AuthContext:
    """Dependency: require admin role from either user JWT or API key JWT."""
    required_level = ROLE_LEVELS.get(ROLE_ADMIN, 2)
    caller_level = ROLE_LEVELS.get(ctx.role, -1)
    if caller_level < required_level:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"This endpoint requires 'admin' role or higher; current role: '{ctx.role}'",
        )
    return ctx


# Admin-only sub-router for user management
_admin_router = APIRouter(
    prefix="/users",
    tags=["users"],
    dependencies=[Depends(_require_admin)],
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _user_to_response(user: UserRecord) -> UserResponse:
    """Convert a UserRecord to UserResponse, never exposing hashed_password."""
    return UserResponse(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role,
        group_id=user.group_id,
        team_id=getattr(user, "team_id", None),  # TEAM-02
        is_active=user.is_active,
        created_at=user.created_at,
        last_login_at=user.last_login_at,
    )


async def _check_hibp(password: str) -> bool:
    """Check password against HaveIBeenPwned k-anonymity API (T-138-09 / D-19).

    Uses the k-anonymity model: hashes password with SHA1, sends only the first
    5 chars to the HIBP API, checks if the full SHA1 suffix appears in the response.

    Returns True if the password is breached, False if clean or if the API
    is unreachable (fail-open per NIST 800-63B -- never block on HIBP failure).
    """
    sha1 = hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()
    prefix, suffix = sha1[:5], sha1[5:]
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            resp = await client.get(f"https://api.pwnedpasswords.com/range/{prefix}")
        if resp.status_code != 200:
            return False  # fail open
        for line in resp.text.splitlines():
            if ":" in line:
                line_suffix, _ = line.split(":", 1)
                if line_suffix.upper() == suffix:
                    return True
        return False
    except Exception:
        SILENT_FAILURE_TOTAL.labels(component="hibp").inc()
        return False  # fail open -- HIBP unreachable


# ---------------------------------------------------------------------------
# Auth endpoints (public -- no auth required)
# ---------------------------------------------------------------------------


@router.post("/auth/login", response_model=DataEnvelope[TokenResponse], summary="Login with username/password")
@limiter.limit("10/minute")
async def login(request: Request, body: LoginRequest) -> DataEnvelope[TokenResponse]:
    """Authenticate with username and password, return JWT access + refresh tokens.

    Per T-138-10: always returns "Invalid credentials" on failure -- never reveals
    whether the username or password was wrong.
    Per D-46: login events (success and failure) dual-written to structlog AND AuditEventRecord.
    """
    # Generic failure response to prevent username enumeration (T-138-10)
    _invalid = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid credentials",
    )

    async with async_session_scope() as session:
        stmt = select(UserRecord).where(UserRecord.username == body.username)
        result = await session.exec(stmt)
        user: UserRecord | None = result.first()

        if user is None or not user.is_active:
            _slog.info("login_failed", username=body.username, reason="user_not_found_or_inactive")
            record_audit_event(
                session,
                run_id=uuid4().hex,
                stage=AUDIT_STAGE_AUTH,
                action="login_failed",
                status="failed",
                target=body.username,
                user_id="anonymous",
                details={"reason": "user_not_found_or_inactive"},
            )
            await session.commit()
            raise _invalid

        if user.hashed_password is None:
            # OIDC-only account -- cannot login with password
            _slog.info("login_failed", username=body.username, reason="no_password_set")
            record_audit_event(
                session,
                run_id=uuid4().hex,
                stage=AUDIT_STAGE_AUTH,
                action="login_failed",
                status="failed",
                target=body.username,
                user_id=user.id,
                details={"reason": "oidc_only_account"},
            )
            await session.commit()
            raise _invalid

        if not verify_user_password(body.password, user.hashed_password):
            _slog.info("login_failed", username=body.username, reason="wrong_password")
            record_audit_event(
                session,
                run_id=uuid4().hex,
                stage=AUDIT_STAGE_AUTH,
                action="login_failed",
                status="failed",
                target=body.username,
                user_id=user.id,
                details={"reason": "wrong_password"},
            )
            await session.commit()
            raise _invalid

        # Update last_login_at
        user.last_login_at = datetime.now(UTC)
        session.add(user)

        record_audit_event(
            session,
            run_id=uuid4().hex,
            stage=AUDIT_STAGE_AUTH,
            action="login_success",
            status=AUDIT_STATUS_COMPLETED,
            target=body.username,
            user_id=user.id,
            details={"role": user.role},
        )
        await session.commit()

        user_id = user.id
        role = user.role
        team_id = getattr(user, "team_id", None)  # TEAM-02: from UserRecord

    access_token, expires_in = issue_user_jwt(user_id, role, team_id=team_id)
    refresh_token = await issue_user_refresh_token(
        user_id,
        role,
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent"),
        team_id=team_id,
    )

    _slog.info("login_success", user_id=user_id, role=role)

    return DataEnvelope(
        data=TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=expires_in,
        )
    )


@limiter.limit("5/minute")
@router.post("/auth/refresh/user", response_model=DataEnvelope[TokenResponse], summary="Refresh user access token")
async def refresh_user_token(request: Request, refresh_token: str = Query(..., description="Refresh token JWT")) -> DataEnvelope[TokenResponse]:
    """Exchange a valid user refresh token for a new access token.

    Validates the token signature, checks it is not revoked in RefreshTokenRecord,
    then issues a new access token. The refresh token is NOT rotated on each use
    (stateful revocation via revoked_at handles security).
    """
    settings = get_settings()
    import jwt as _jwt

    from aila.api.constants import JWT_ALGORITHM

    _invalid_refresh = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or expired refresh token",
    )

    try:
        payload = _jwt.decode(refresh_token, settings.jwt_secret_key, algorithms=[JWT_ALGORITHM])
    except _jwt.ExpiredSignatureError:
        raise _invalid_refresh
    except _jwt.InvalidTokenError:
        raise _invalid_refresh

    if payload.get("typ") != JWT_TYP_USER_REFRESH:
        raise _invalid_refresh

    user_id = payload.get("user_id")
    if not user_id:
        raise _invalid_refresh

    # Check token hash is in DB and not revoked
    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    async with async_session_scope() as session:
        stmt = select(RefreshTokenRecord).where(RefreshTokenRecord.token_hash == token_hash)
        result = await session.exec(stmt)
        record: RefreshTokenRecord | None = result.first()

        if record is None or record.revoked_at is not None:
            raise _invalid_refresh

        # Validate user still active
        user: UserRecord | None = await session.get(UserRecord, user_id)
        if user is None or not user.is_active:
            raise _invalid_refresh

        role = user.role
        team_id = getattr(user, "team_id", None)  # TEAM-02: from UserRecord

    access_token, expires_in = issue_user_jwt(user_id, role, team_id=team_id)
    return DataEnvelope(
        data=TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,  # Return same refresh token
            token_type="bearer",
            expires_in=expires_in,
        )
    )


@limiter.limit("10/minute")
@router.post("/auth/logout", response_model=DataEnvelope[LogoutResponse], summary="Logout -- revoke refresh token")
async def logout(request: Request, refresh_token: str = Query(..., description="Refresh token to revoke")) -> DataEnvelope[LogoutResponse]:
    """Revoke a user refresh token, invalidating further refresh attempts."""
    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    async with async_session_scope() as session:
        stmt = select(RefreshTokenRecord).where(RefreshTokenRecord.token_hash == token_hash)
        result = await session.exec(stmt)
        record: RefreshTokenRecord | None = result.first()
        if record and record.revoked_at is None:
            record.revoked_at = datetime.now(UTC)
            session.add(record)
            await session.commit()
    return DataEnvelope(data=LogoutResponse(revoked=True))


@router.get("/auth/sessions", response_model=DataEnvelope[list[UserSessionResponse]], summary="List active sessions for current user")
async def list_user_sessions(
    auth: AuthContext = Depends(require_user_or_api_key),
) -> DataEnvelope[list[UserSessionResponse]]:
    """Return all active (non-revoked, non-expired) refresh token sessions for the authenticated user.

    Per T-140-17: endpoint requires authentication; only returns sessions for auth.user_id.
    Per T-140-18: token_hash is never returned -- only metadata (IP, user-agent, timestamps).
    """
    async with async_session_scope() as session:
        stmt = (
            select(RefreshTokenRecord)
            .where(
                RefreshTokenRecord.user_id == auth.user_id,
                RefreshTokenRecord.revoked_at.is_(None),
                RefreshTokenRecord.expires_at > datetime.now(UTC),
            )
            .order_by(RefreshTokenRecord.created_at.desc())
        )
        result = await session.exec(stmt)
        records = result.all()

    sessions_data = [
        UserSessionResponse(
            id=str(record.id),
            ip_address=record.ip_address,
            user_agent=record.user_agent,
            created_at=record.created_at.isoformat() if record.created_at else None,
            expires_at=record.expires_at.isoformat() if record.expires_at else None,
        )
        for record in records
    ]
    return DataEnvelope(data=sessions_data)


@limiter.limit("10/minute")
@router.delete("/auth/sessions/{session_id}", response_model=DataEnvelope[RevokeSessionResponse], summary="Revoke a specific session")
async def revoke_session(
    request: Request,
    session_id: str,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> DataEnvelope[RevokeSessionResponse]:
    """Revoke a specific refresh token session by ID.

    Per T-140-16: only the owning user can revoke their own sessions.
    """
    async with async_session_scope() as db_session:
        record: RefreshTokenRecord | None = await db_session.get(RefreshTokenRecord, session_id)
        if record is None or record.user_id != auth.user_id:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
        if record.revoked_at is not None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Session already revoked")
        record.revoked_at = datetime.now(UTC)
        db_session.add(record)
        await db_session.commit()
    return DataEnvelope(data=RevokeSessionResponse(revoked=session_id))


# ---------------------------------------------------------------------------
# User management endpoints (admin only)
# ---------------------------------------------------------------------------


@_admin_router.get("", response_model=DataEnvelope[list[UserResponse]], summary="List users")
async def list_users(
    offset: int = Query(default=0, ge=0),
    limit: int = Query(default=50, ge=1, le=250),
) -> DataEnvelope[list[UserResponse]]:
    """Return a paginated list of all user accounts. Admin only.

    Per D-26: offset/limit pagination with total count in DataEnvelope.meta.
    Per T-138-04: hashed_password is never included in responses.
    """
    async with async_session_scope() as session:
        count_stmt = select(func.count()).select_from(UserRecord)
        total_result = await session.exec(count_stmt)
        total = total_result.one()

        stmt = select(UserRecord).order_by(UserRecord.created_at).offset(offset).limit(limit)
        result = await session.exec(stmt)
        users = list(result.all())

    return DataEnvelope(
        data=[_user_to_response(u) for u in users],
        meta={"total": total, "offset": offset, "limit": limit},
    )


@limiter.limit("60/minute")
@_admin_router.post("", response_model=DataEnvelope[UserResponse], status_code=status.HTTP_201_CREATED, summary="Create user")
async def create_user(
    request: Request,
    body: UserCreateRequest,
    caller: AuthContext = Depends(_require_admin),
) -> DataEnvelope[UserResponse]:
    """Create a new user account. Admin only.

    Per D-17: admin-invite only registration.
    Per D-19: NIST 800-63B -- min 8 chars, HaveIBeenPwned breach check.
    Per D-18: role must be in VALID_ROLES.
    Per D-46: user creation event dual-written to structlog AND AuditEventRecord.
    """
    # Validate role
    if body.role not in VALID_ROLES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid role '{body.role}'. Must be one of: {sorted(VALID_ROLES)}",
        )

    # HIBP breach check (T-138-09 / D-19)
    if await _check_hibp(body.password):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Password has been found in a data breach. Choose a different password.",
        )

    hashed_pw = hash_user_password(body.password)
    now = utc_now()
    async with async_session_scope() as session:
        # Check username uniqueness
        existing_stmt = select(UserRecord).where(UserRecord.username == body.username)
        existing = (await session.exec(existing_stmt)).first()
        if existing is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Username '{body.username}' is already taken",
            )

        user = UserRecord(
            username=body.username,
            email=body.email,
            hashed_password=hashed_pw,
            role=body.role,
            group_id=body.group_id,
            team_id=body.team_id,  # TEAM-02: data isolation boundary (D-08)
            is_active=True,
            created_at=now,
            updated_at=now,
        )
        session.add(user)

        record_audit_event(
            session,
            run_id=uuid4().hex,
            stage=AUDIT_STAGE_AUTH,
            action="user_created",
            status=AUDIT_STATUS_COMPLETED,
            target=body.username,
            user_id=caller.user_id,
            details={"role": body.role, "group_id": body.group_id, "team_id": body.team_id},
        )
        await session.commit()
        await session.refresh(user)

    _slog.info("user_created", username=body.username, role=body.role)
    return DataEnvelope(data=_user_to_response(user))


@_admin_router.get("/{user_id}", response_model=DataEnvelope[UserResponse], summary="Get user")
async def get_user(user_id: str) -> DataEnvelope[UserResponse]:
    """Return a single user by ID. Admin only."""
    async with async_session_scope() as session:
        user: UserRecord | None = await session.get(UserRecord, user_id)
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User '{user_id}' not found")
    return DataEnvelope(data=_user_to_response(user))


@limiter.limit("60/minute")
@_admin_router.patch("/{user_id}", response_model=DataEnvelope[UserResponse], summary="Update user")
async def update_user(
    request: Request,
    user_id: str,
    body: UserUpdateRequest,
    caller: AuthContext = Depends(_require_admin),
) -> DataEnvelope[UserResponse]:
    """Update user fields. Supports soft-delete via is_active=False (D-20).

    Per T-138-06: only admin can change roles; role validated against VALID_ROLES.
    Per D-46: role changes dual-written to structlog AND AuditEventRecord.
    """
    if body.role is not None and body.role not in VALID_ROLES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid role '{body.role}'. Must be one of: {sorted(VALID_ROLES)}",
        )

    async with async_session_scope() as session:
        user: UserRecord | None = await session.get(UserRecord, user_id)
        if user is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User '{user_id}' not found")

        changes: dict = {}
        if body.email is not None:
            changes["email"] = body.email
            user.email = body.email
        if body.role is not None and body.role != user.role:
            changes["role_from"] = user.role
            changes["role_to"] = body.role
            user.role = body.role
        if body.group_id is not None:
            changes["group_id"] = body.group_id
            user.group_id = body.group_id
        if body.team_id is not None:
            changes["team_id"] = body.team_id
            user.team_id = body.team_id  # type: ignore[assignment]  # TEAM-02
        if body.is_active is not None:
            changes["is_active"] = body.is_active
            user.is_active = body.is_active

        user.updated_at = utc_now()
        session.add(user)

        if changes:
            record_audit_event(
                session,
                run_id=uuid4().hex,
                stage=AUDIT_STAGE_AUTH,
                action="user_updated",
                status=AUDIT_STATUS_COMPLETED,
                target=user_id,
                user_id=caller.user_id,
                details=changes,
            )
        await session.commit()
        await session.refresh(user)

    # Invalidate auth revocation cache when user is deactivated (TEAM-09)
    if body.is_active is not None and not body.is_active:
        from aila.api.auth_cache import get_auth_cache

        await get_auth_cache().invalidate(f"user:{user_id}")

    _slog.info("user_updated", user_id=user_id, changes=changes)
    return DataEnvelope(data=_user_to_response(user))


# Include admin router into main router
router.include_router(_admin_router)
