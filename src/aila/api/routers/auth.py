"""Authentication router: API key management and JWT token issuance.

Endpoints:
  POST /auth/token      -- Exchange raw API key for JWT (PUBLIC: no Bearer required)
  POST /auth/refresh    -- Exchange refresh token for new access token (PUBLIC)
  POST /auth/keys       -- Create new API key (ADMIN only)
  GET  /auth/keys       -- List all API keys (ADMIN only)
  DELETE /auth/keys/{key_id} -- Revoke an API key (ADMIN only)

All endpoints except POST /auth/token and POST /auth/refresh require a valid
Bearer JWT. The protected sub-router uses APIRouter(dependencies=[Depends(require_api_key)])
to ensure auth is applied at router level -- no per-route drift (RESEARCH Pitfall 5).
"""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import update as sa_update
from sqlmodel import select
from starlette.requests import Request

from aila.api.auth import (
    AuthContext,
    decode_and_blacklist_check,
    generate_api_key,
    hash_api_key,
    issue_jwt_token,
    issue_refresh_token,
    require_role,
    require_user_or_api_key,
    verify_api_key,
)
from aila.api.constants import (
    AUDIT_ACTION_CREATE_API_KEY,
    AUDIT_ACTION_REVOKE_API_KEY,
    AUDIT_ACTION_TOKEN_ISSUE,
    AUDIT_ACTION_TOKEN_REFRESH,
    AUDIT_STAGE_AUTH,
    AUDIT_STATUS_COMPLETED,
    JWT_TYP_REFRESH,
    ROLE_ADMIN,
    TOKEN_TYPE_BEARER,
    VALID_ROLES,
)
from aila.api.limiter import limiter
from aila.api.schemas.auth import (
    ApiKeyCreateRequest,
    ApiKeyCreateResponse,
    ApiKeyListItem,
    ApiKeyListResponse,
    ApiKeyRevokeResponse,
    RefreshRequest,
    RefreshResponse,
    TokenRequest,
    TokenResponse,
)
from aila.platform.contracts._common import utc_now
from aila.platform.services.audit import record_audit_event
from aila.storage.database import async_session_scope
from aila.storage.db_models import ApiKeyRecord

__all__ = ["router"]

# Public router: no auth required (token issuance endpoints)
public_router = APIRouter(prefix="/auth", tags=["auth"])

# Protected router: all routes require a valid Bearer JWT (AUTH-06)
protected_router = APIRouter(
    prefix="/auth",
    tags=["auth"],
    dependencies=[Depends(require_user_or_api_key)],
)


@limiter.limit("5/minute")
@public_router.post("/token", response_model=TokenResponse)
async def login(request: Request, body: TokenRequest) -> TokenResponse:
    """Exchange a raw API key for JWT access and refresh tokens.

    D-04: Client sends API key once; receives JWT for subsequent requests.
    D-05: Access token expiry configurable via AILA_JWT_EXPIRY_SECONDS.
    D-06: Refresh token also issued; use POST /auth/refresh to renew.

    The session is closed before verify_api_key() is called. This is
    intentional: bcrypt verification is CPU-bound and should not hold
    an open DB session.

    Args:
        request: Contains the raw API key string.

    Returns:
        Access token, refresh token, token type, and expiry seconds.

    Raises:
        HTTPException(401): If the API key is not found or does not match hash.
    """
    raw_key = body.api_key
    prefix = raw_key[:12] if len(raw_key) >= 12 else raw_key

    async def _lookup() -> list[ApiKeyRecord]:
        async with async_session_scope() as session:
            stmt = select(ApiKeyRecord).where(
                ApiKeyRecord.key_prefix == prefix,
                ApiKeyRecord.revoked_at.is_(None),  # type: ignore[union-attr]
            )
            return list((await session.exec(stmt)).all())

    candidates = await _lookup()

    matched: ApiKeyRecord | None = None
    for candidate in candidates:
        if verify_api_key(raw_key, candidate.hashed_key):
            matched = candidate
            break

    if matched is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid API key -- verify the key is correct and not revoked, then retry POST /auth/token",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token, expires_in = issue_jwt_token(matched)
    refresh_token = issue_refresh_token(matched)

    async def _audit_login() -> None:
        async with async_session_scope() as session:
            record_audit_event(
                session,
                run_id=matched.id,
                stage=AUDIT_STAGE_AUTH,
                action=AUDIT_ACTION_TOKEN_ISSUE,
                status=AUDIT_STATUS_COMPLETED,
                target=matched.key_prefix,
                user_id=matched.id,
                team_id=matched.team_id,
                details={"role": matched.role},
            )
            await session.commit()

    await _audit_login()

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        token_type=TOKEN_TYPE_BEARER,
        expires_in=expires_in,
    )


@limiter.limit("5/minute")
@public_router.post("/refresh", response_model=RefreshResponse)
async def refresh_token(request: Request, body: RefreshRequest) -> RefreshResponse:
    """Exchange a refresh token for a new access token.

    D-06: No re-sending of the raw API key needed. Refresh token carries
    key_id for blacklist check -- revoked keys invalidate refresh tokens too.

    Args:
        request: Contains the refresh token JWT string.

    Returns:
        New access token and expiry seconds.

    Raises:
        HTTPException(401): If refresh token is invalid, expired, or key revoked.
    """
    key_record = await decode_and_blacklist_check(body.refresh_token, JWT_TYP_REFRESH)
    access_token, expires_in = issue_jwt_token(key_record)

    async def _audit_refresh() -> None:
        async with async_session_scope() as session:
            record_audit_event(
                session,
                run_id=key_record.id,
                stage=AUDIT_STAGE_AUTH,
                action=AUDIT_ACTION_TOKEN_REFRESH,
                status=AUDIT_STATUS_COMPLETED,
                target=key_record.key_prefix,
                user_id=key_record.id,
                team_id=key_record.team_id,
                details={"role": key_record.role},
            )
            await session.commit()

    await _audit_refresh()

    return RefreshResponse(
        access_token=access_token,
        token_type=TOKEN_TYPE_BEARER,
        expires_in=expires_in,
    )


@limiter.limit("60/minute")
@protected_router.post("/keys", response_model=ApiKeyCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_api_key(
    request: Request,
    body: ApiKeyCreateRequest,
    admin: AuthContext = Depends(require_role(ROLE_ADMIN)),
) -> ApiKeyCreateResponse:
    """Generate bcrypt-hashed credential with role assignment; raw secret shown only in this response."""
    if body.role not in VALID_ROLES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid role '{body.role}'. Must be one of: {sorted(VALID_ROLES)}",
        )

    raw_key = generate_api_key()
    hashed = hash_api_key(raw_key)
    key_prefix = raw_key[:12]
    now = utc_now()

    record = ApiKeyRecord(
        hashed_key=hashed,
        key_prefix=key_prefix,
        role=body.role,
        label=body.label,
        created_by=admin.user_id,
        # #36: a team-scoped admin's key belongs to that team; a god-tier
        # admin (team_id=None) mints a team-less (god-tier) key.
        team_id=admin.team_id,
        created_at=now,
    )

    async def _persist() -> tuple[str, str, str, datetime]:
        async with async_session_scope() as session:
            session.add(record)
            # #52-3.2: stage the audit row inside the SAME transaction as
            # the record insert. The previous flow (`commit(); audit;
            # commit()`) opened a crash window where the key was already
            # persisted but the audit trail row was lost. ApiKeyRecord.id
            # and .created_at are populated by default_factory at object
            # construction, so both the audit payload and the return
            # snapshot are safe to read before commit -- no refresh
            # needed. record_audit_event only stages an INSERT on the
            # session; the single commit below persists both writes or
            # neither.
            rec_id: str = record.id
            rec_role: str = record.role
            rec_label: str = record.label
            rec_created_at: datetime = record.created_at
            record_audit_event(
                session,
                run_id=rec_id,
                stage=AUDIT_STAGE_AUTH,
                action=AUDIT_ACTION_CREATE_API_KEY,
                status=AUDIT_STATUS_COMPLETED,
                target=key_prefix,
                user_id=admin.user_id,
                team_id=admin.team_id,
                details={"role": rec_role, "label": rec_label},
            )
            await session.commit()
            return rec_id, rec_role, rec_label, rec_created_at

    record_id, record_role, record_label, record_created_at = await _persist()

    return ApiKeyCreateResponse(
        key_id=record_id,
        raw_key=raw_key,
        key_prefix=key_prefix,
        role=record_role,
        label=record_label,
        created_at=record_created_at,
    )


@protected_router.get("/keys", response_model=ApiKeyListResponse)
async def list_api_keys(
    active_only: bool = Query(False),
    admin: AuthContext = Depends(require_role(ROLE_ADMIN)),
) -> ApiKeyListResponse:
    """List API keys. Pass active_only=true to exclude revoked keys.

    D-09: Admin only. Raw keys are never returned -- only prefix, id, role.

    Args:
        active_only: When True, exclude keys with revoked_at set.
        admin: Injected by require_role("admin").

    Returns:
        List of ApiKeyListItem records.
    """
    async def _query() -> list[ApiKeyRecord]:
        async with async_session_scope() as session:
            stmt = select(ApiKeyRecord)
            if active_only:
                stmt = stmt.where(ApiKeyRecord.revoked_at.is_(None))  # type: ignore[union-attr]
            # #36: a team-scoped admin sees only its own team's keys; a
            # god-tier admin (team_id=None) sees every team's keys.
            if admin.team_id is not None:
                stmt = stmt.where(ApiKeyRecord.team_id == admin.team_id)
            return list((await session.exec(stmt)).all())

    records = await _query()

    return ApiKeyListResponse(
        keys=[
            ApiKeyListItem(
                key_id=r.id,
                key_prefix=r.key_prefix,
                role=r.role,
                label=r.label,
                created_by=r.created_by,
                created_at=r.created_at,
                revoked_at=r.revoked_at,
            )
            for r in records
        ]
    )


@limiter.limit("60/minute")
@protected_router.delete("/keys/{key_id}", response_model=ApiKeyRevokeResponse)
async def revoke_api_key(
    request: Request,
    key_id: str,
    admin: AuthContext = Depends(require_role(ROLE_ADMIN)),
) -> ApiKeyRevokeResponse:
    """Revoke an API key by setting its revoked_at timestamp.

    D-07: Revocation makes all outstanding JWTs for that key_id immediately
    invalid via the D-11 blacklist check. D-10: No role patching -- revoke
    and re-create is the intended workflow.
    D-12: Revocation event logged to AuditEventRecord.

    Args:
        key_id: UUID of the key to revoke.
        admin: Injected by require_role("admin").

    Returns:
        key_id and revoked=True on success.

    Raises:
        HTTPException(404): If key_id not found.
        HTTPException(409): If key is already revoked.
    """
    async def _revoke() -> str | None:
        async with async_session_scope() as session:
            record = await session.get(ApiKeyRecord, key_id)
            if record is None:
                return "not_found"
            # #36: a team-scoped admin may only revoke its own team's key;
            # god-tier (team_id=None) may revoke any. Returning "not_found"
            # (404, not 403) avoids a cross-team existence oracle.
            if admin.team_id is not None and getattr(record, "team_id", None) != admin.team_id:
                return "not_found"
            # Atomic conditional update: flip revoked_at only while it is still
            # NULL and check the affected row count. Two concurrent revocations
            # serialize on the row lock, so exactly one sees rowcount 1 (200) and
            # the loser sees rowcount 0 (409). A read-then-check-then-write here
            # was a TOCTOU race that let both duplicates commit 200.
            result = await session.execute(
                sa_update(ApiKeyRecord)
                .where(ApiKeyRecord.id == key_id)
                .where(ApiKeyRecord.revoked_at.is_(None))
                .values(revoked_at=utc_now())
            )
            if result.rowcount == 0:
                return "already_revoked"
            # #52-3.2: write the audit row in the SAME transaction as the
            # conditional UPDATE. The previous flow (`commit(); audit;
            # commit()`) opened a crash window where the key was already
            # revoked but the audit trail row was lost. record_audit_event
            # only stages an INSERT on the session; both writes commit
            # atomically below. The atomic conditional-UPDATE contract
            # above is preserved -- rowcount==0 still short-circuits
            # before any audit row is staged.
            record_audit_event(
                session,
                run_id=key_id,
                stage=AUDIT_STAGE_AUTH,
                action=AUDIT_ACTION_REVOKE_API_KEY,
                status=AUDIT_STATUS_COMPLETED,
                target=record.key_prefix,
                user_id=admin.user_id,
                team_id=admin.team_id,
                details={"role": record.role},
            )
            await session.commit()
        return None

    result = await _revoke()
    if result == "not_found":
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"API key '{key_id}' not found -- verify the key_id via GET /auth/keys",
        )
    if result == "already_revoked":
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"API key '{key_id}' is already revoked -- no action needed",
        )

    # Invalidate auth revocation cache entry for this key (TEAM-09)
    from aila.api.auth_cache import get_auth_cache

    await get_auth_cache().invalidate(f"api_key:{key_id}")

    return ApiKeyRevokeResponse(key_id=key_id, revoked=True)


# Combined router that the app mounts: public routes first, then protected
router = APIRouter()
router.include_router(public_router)
router.include_router(protected_router)
