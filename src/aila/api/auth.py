"""Authentication core for the AILA REST API.

Provides:
- API key generation and bcrypt hashing (pwdlib[bcrypt]).
- JWT issuance (access tokens) and refresh token issuance (PyJWT HS256).
- require_api_key FastAPI dependency: decodes JWT, validates non-revocation (D-11).
- require_role dependency factory: enforces role hierarchy from JWT.

Token blacklist (D-11): every authenticated request queries ApiKeyRecord by
key_id. If revoked_at is set, the JWT is rejected immediately regardless of
its expiry timestamp. This provides instant revocation with zero cache window.

Signing algorithm: HS256 (symmetric HMAC-SHA256). RS256 is deferred to
multi-worker / external-verifier scenarios.

Refresh tokens: signed JWTs with typ: refresh claim and longer expiry.
API-key refresh tokens are stateless (validated via key_id blacklist).
User refresh tokens are persisted in RefreshTokenRecord for server-side
revocation.

Role hierarchy: admin (2) > operator (1) > reader (0). A token with role
'operator' satisfies require_role('reader') because 1 >= 0. This allows
operators to call all reader-accessible endpoints without requiring separate
reader credentials.
"""
from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import jwt
from argon2 import PasswordHasher as _ArgonPH
from argon2.exceptions import VerifyMismatchError as _ArgonMismatch
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pwdlib import PasswordHash
from pwdlib.hashers.bcrypt import BcryptHasher

from aila.api.constants import (
    JWT_ALGORITHM,
    JWT_TYP_ACCESS,
    JWT_TYP_REFRESH,
    JWT_TYP_USER_ACCESS,
    JWT_TYP_USER_REFRESH,
    ROLE_ADMIN,
    ROLE_OPERATOR,
    ROLE_READER,
)
from aila.config import get_settings
from aila.storage.database import async_session_scope
from aila.storage.db_models import ApiKeyRecord

__all__ = [
    "AuthContext",
    "ROLE_LEVELS",
    "TeamContext",
    "decode_and_blacklist_check",
    "generate_api_key",
    "get_team_context",
    "hash_api_key",
    "hash_user_password",
    "issue_jwt_token",
    "issue_refresh_token",
    "issue_user_jwt",
    "issue_user_refresh_token",
    "require_api_key",
    "require_role",
    "require_user_or_api_key",
    "verify_api_key",
    "verify_user_password",
]

# Explicitly use bcrypt — do not rely on PasswordHash autodetection which
# varies depending on installed extras. BcryptHasher guarantees bcrypt.
_HASHER: PasswordHash = PasswordHash((BcryptHasher(),))
_BEARER_SCHEME: HTTPBearer = HTTPBearer(auto_error=False)

# argon2id hasher for user passwords (D-13). Separate from _HASHER (bcrypt for API keys).
_USER_PH: _ArgonPH = _ArgonPH()


@dataclass(frozen=True, slots=True)
class AuthContext:
    """Unified auth context returned by require_user_or_api_key.

    auth_type is "user" for user JWT tokens, "api_key" for API key JWTs.
    user_id is the UserRecord.id for user auth, or ApiKeyRecord.id for API key auth.
    team_id is None for admin tokens (TEAM-06: god tier — sees all teams' data).
    """

    user_id: str
    role: str
    auth_type: str  # "user" | "api_key"
    team_id: str | None = None  # None = admin (TEAM-06)


@dataclass(frozen=True, slots=True)
class TeamContext:
    """Team isolation context extracted from JWT claims (D-02).

    team_id is None for admin tokens (TEAM-06: god tier).
    is_admin is derived from team_id being None.
    """

    team_id: str | None
    is_admin: bool

    @classmethod
    def from_auth(cls, auth: AuthContext) -> TeamContext:
        """Construct TeamContext from AuthContext."""
        return cls(team_id=auth.team_id, is_admin=auth.team_id is None)

_ACCESS_EXPIRY_DEFAULT: int = 2_592_000   # 30 days in seconds
_REFRESH_EXPIRY_DEFAULT: int = 7_776_000  # 90 days in seconds

# Role hierarchy levels. Higher value = broader access.
# admin (2) >= operator (1) >= reader (0).
# require_role checks ROLE_LEVELS[key.role] >= ROLE_LEVELS[required_role].
ROLE_LEVELS: dict[str, int] = {
    ROLE_READER: 0,
    ROLE_OPERATOR: 1,
    ROLE_ADMIN: 2,
}


def generate_api_key() -> str:
    """Generate a new raw API key with the 'aila_sk_' prefix.

    Returns:
        A 40-character string starting with 'aila_sk_' followed by 32 hex chars.
        Example: 'aila_sk_a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6'
    """
    return f"aila_sk_{uuid4().hex}"


def hash_api_key(raw_key: str) -> str:
    """Hash a raw API key using bcrypt via pwdlib.

    Args:
        raw_key: The full raw key string to hash.

    Returns:
        bcrypt hash string suitable for storage in ApiKeyRecord.hashed_key.
    """
    return _HASHER.hash(raw_key)


def verify_api_key(raw_key: str, hashed_key: str) -> bool:
    """Verify a raw API key against its stored bcrypt hash.

    Args:
        raw_key: The raw key provided by the client.
        hashed_key: The bcrypt hash from ApiKeyRecord.hashed_key.

    Returns:
        True if the key matches, False otherwise.
    """
    return _HASHER.verify(raw_key, hashed_key)


def _access_expiry_seconds() -> int:
    from aila.platform.tasks import get_task_tuning

    return get_task_tuning("jwt_access_expiry_s", _ACCESS_EXPIRY_DEFAULT)


def _refresh_expiry_seconds() -> int:
    from aila.platform.tasks import get_task_tuning

    return get_task_tuning("jwt_refresh_expiry_s", _REFRESH_EXPIRY_DEFAULT)


def issue_jwt_token(key_record: ApiKeyRecord) -> tuple[str, int]:
    """Issue a signed JWT access token from an ApiKeyRecord.

    Encodes role and key_id claims (D-07). Uses HS256 with the jwt_secret_key
    from Settings. The expiry is configurable via AILA_JWT_EXPIRY_SECONDS (D-05).

    Args:
        key_record: The ApiKeyRecord for the authenticated key.

    Returns:
        Tuple of (encoded_token_string, expiry_seconds).
    """
    settings = get_settings()
    expiry = _access_expiry_seconds()
    payload = {
        "jti": uuid4().hex,
        "key_id": key_record.id,
        "role": key_record.role,
        "team_id": getattr(key_record, "team_id", None),  # TEAM-01: None for admin keys
        "typ": JWT_TYP_ACCESS,
        "exp": datetime.now(UTC) + timedelta(seconds=expiry),
        "iat": datetime.now(UTC),
    }
    token = jwt.encode(payload, settings.jwt_secret_key, algorithm=JWT_ALGORITHM)
    return token, expiry


def issue_refresh_token(key_record: ApiKeyRecord) -> str:
    """Issue a signed JWT refresh token from an ApiKeyRecord.

    Refresh tokens carry 'typ': 'refresh' to distinguish them from access
    tokens. They are longer-lived (D-06: default 90 days). The key_id claim
    enables blacklist checking if the key is revoked before the refresh
    token expires.

    Args:
        key_record: The ApiKeyRecord for the authenticated key.

    Returns:
        Encoded refresh token string.
    """
    settings = get_settings()
    expiry = _refresh_expiry_seconds()
    payload = {
        "jti": uuid4().hex,
        "key_id": key_record.id,
        "role": key_record.role,
        "team_id": getattr(key_record, "team_id", None),  # TEAM-01: None for admin keys
        "typ": JWT_TYP_REFRESH,
        "exp": datetime.now(UTC) + timedelta(seconds=expiry),
        "iat": datetime.now(UTC),
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=JWT_ALGORITHM)


async def decode_and_blacklist_check(token: str, expected_typ: str = JWT_TYP_ACCESS) -> ApiKeyRecord:
    """Decode a JWT and verify the key_id is not revoked (D-11 blacklist check).

    This is an async function using async_session_scope for the DB blacklist
    check. Called from require_api_key (async dependency) and from the refresh
    endpoint.

    Args:
        token: Raw JWT string from the Authorization header.
        expected_typ: 'access' for normal auth, 'refresh' for refresh endpoint.

    Returns:
        The active ApiKeyRecord for the validated key_id.

    Raises:
        HTTPException(401): If token is invalid, expired, wrong type, or key revoked.
    """
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="JWT access token has expired -- obtain a new token via POST /auth/token or POST /auth/refresh",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="JWT token is malformed or has an invalid signature -- send a valid Bearer token from POST /auth/token",
        )

    actual_typ = payload.get("typ")
    # Accept user_access tokens wherever access tokens are expected (unified auth)
    _ACCESS_TYPES = {JWT_TYP_ACCESS, JWT_TYP_USER_ACCESS}
    if expected_typ in _ACCESS_TYPES:
        if actual_typ not in _ACCESS_TYPES:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Expected access token but received '{actual_typ}'",
            )
    elif actual_typ != expected_typ:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Expected '{expected_typ}' token but received '{actual_typ}'",
        )

    # Auth revocation cache integration (TEAM-09 / D-06)
    from aila.api.auth_cache import get_auth_cache

    cache = get_auth_cache()

    # Handle both token types: API key JWT has key_id, user JWT has user_id
    if actual_typ == JWT_TYP_USER_ACCESS:
        # User JWT — look up user, return a synthetic ApiKeyRecord-compatible object
        from aila.storage.db_models import UserRecord

        user_id = payload.get("user_id")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="JWT payload is missing the 'user_id' claim",
            )

        # Check cache before DB query
        user_cache_key = f"user:{user_id}"
        cached = await cache.check(user_cache_key)
        if cached is False:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account not found or deactivated",
            )

        async with async_session_scope() as session:
            user: UserRecord | None = await session.get(UserRecord, user_id)
        is_valid = user is not None and user.is_active
        if cached is None:
            # Cache miss -- store the result
            await cache.store(user_cache_key, is_valid)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account not found or deactivated",
            )
        # Return a synthetic ApiKeyRecord so callers that expect .id/.role still work
        synthetic = ApiKeyRecord(
            id=user.id,
            hashed_key="",
            key_prefix="user",
            role=user.role,
            label=user.username,
            created_by="user_jwt",
        )
        # Carry team_id from JWT payload onto synthetic record (TEAM-02)
        _jwt_team_id = payload.get("team_id")
        if hasattr(synthetic, "team_id"):
            synthetic.team_id = _jwt_team_id  # type: ignore[assignment]
        return synthetic

    key_id = payload.get("key_id")
    if not key_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="JWT payload is missing the 'key_id' claim -- re-issue the token via POST /auth/token",
        )

    # Check cache before DB query for API key
    api_cache_key = f"api_key:{key_id}"
    cached = await cache.check(api_cache_key)
    if cached is False:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"API key '{key_id}' has been revoked or does not exist -- create a new key via POST /auth/keys",
        )

    async with async_session_scope() as session:
        key_record: ApiKeyRecord | None = await session.get(ApiKeyRecord, key_id)

    is_valid = key_record is not None and key_record.revoked_at is None
    if cached is None:
        # Cache miss -- store the result
        await cache.store(api_cache_key, is_valid)

    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"API key '{key_id}' has been revoked or does not exist -- create a new key via POST /auth/keys",
        )

    return key_record


async def require_api_key(
    credentials: HTTPAuthorizationCredentials | None = Depends(_BEARER_SCHEME),
) -> ApiKeyRecord:
    """FastAPI dependency: verify Bearer JWT and return the active ApiKeyRecord.

    This is an async dependency using async_session_scope for the DB blacklist
    check, avoiding event loop blocking.

    Applied at router level via APIRouter(dependencies=[Depends(require_api_key)]).
    This guarantees every route under a protected router checks auth — no per-route
    drift (RESEARCH Pitfall 5: auth missing from internal routes).

    Args:
        credentials: Injected from HTTPBearer scheme; None if no Authorization header.

    Returns:
        The active ApiKeyRecord for the authenticated request.

    Raises:
        HTTPException(401): If credentials are missing, invalid, expired, or key revoked.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization: Bearer <token> header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return await decode_and_blacklist_check(credentials.credentials, expected_typ=JWT_TYP_ACCESS)


def require_role(required_role: str) -> Callable[..., AuthContext]:
    """Dependency factory: enforce a minimum role level on a route.

    Uses ROLE_LEVELS hierarchy: admin (2) >= operator (1) >= reader (0).
    A token with role 'operator' satisfies require_role('reader') because
    its level (1) >= reader's level (0). A token with role 'reader' does NOT
    satisfy require_role('operator') because 0 < 1.

    Args:
        required_role: Minimum role string ('admin', 'operator', or 'reader').

    Returns:
        An async FastAPI dependency function that raises 403 if the
        caller's role level is below the required level.

    Example:
        @router.post("/keys")
        async def create_key(admin: AuthContext = Depends(require_role("admin"))): ...
    """
    required_level = ROLE_LEVELS.get(required_role, 0)

    async def check_role(auth: AuthContext = Depends(require_user_or_api_key)) -> AuthContext:
        caller_level = ROLE_LEVELS.get(auth.role, -1)
        if caller_level < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=(
                    f"This endpoint requires '{required_role}' role or higher; "
                    f"current role: '{auth.role}'"
                ),
            )
        return auth

    return check_role


# ---------------------------------------------------------------------------
# User password hashing (argon2id) — separate from API key bcrypt hashing
# ---------------------------------------------------------------------------


def hash_user_password(plain_password: str) -> str:
    """Hash a plain-text user password using argon2id via argon2-cffi.

    Per D-13: argon2id, NOT bcrypt. The _USER_PH instance uses argon2-cffi
    defaults which are OWASP-recommended: time_cost=3, memory_cost=65536,
    parallelism=4, hash_len=32.

    Args:
        plain_password: The plain-text password to hash.

    Returns:
        argon2id hash string suitable for storage in UserRecord.hashed_password.
    """
    if not plain_password:
        raise ValueError("Password must not be empty")
    return _USER_PH.hash(plain_password)


def verify_user_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain-text password against its stored argon2id hash.

    Args:
        plain_password: The plain-text password from the login request.
        hashed_password: The argon2id hash from UserRecord.hashed_password.

    Returns:
        True if the password matches, False otherwise.
    """
    try:
        return _USER_PH.verify(hashed_password, plain_password)
    except _ArgonMismatch:
        return False


# ---------------------------------------------------------------------------
# User JWT issuance (user_access + user_refresh tokens)
# ---------------------------------------------------------------------------

_USER_ACCESS_EXPIRY: int = 31_536_000   # 1 year
_USER_REFRESH_EXPIRY: int = 31_536_000  # 1 year


def issue_user_jwt(user_id: str, role: str, *, team_id: str | None = None) -> tuple[str, int]:
    """Issue a signed JWT access token for a user account.

    60-minute access token lifetime. Uses typ='user_access' to
    distinguish from API key JWTs (typ='access').

    Args:
        user_id: The UserRecord.id for the authenticated user.
        role: The user's role string ('admin', 'operator', 'reader').
        team_id: Team isolation ID (TEAM-02). None for admin users (TEAM-06).

    Returns:
        Tuple of (encoded_token_string, expiry_seconds).
    """
    settings = get_settings()
    payload = {
        "jti": uuid4().hex,
        "user_id": user_id,
        "role": role,
        "team_id": team_id,  # TEAM-02: None for admin users
        "typ": JWT_TYP_USER_ACCESS,
        "exp": datetime.now(UTC) + timedelta(seconds=_USER_ACCESS_EXPIRY),
        "iat": datetime.now(UTC),
    }
    token = jwt.encode(payload, settings.jwt_secret_key, algorithm=JWT_ALGORITHM)
    return token, _USER_ACCESS_EXPIRY


async def issue_user_refresh_token(
    user_id: str,
    role: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
    *,
    team_id: str | None = None,
) -> str:
    """Issue a signed JWT refresh token for a user account and store its hash in DB.

    Per D-14: 7-day refresh token lifetime. Stores SHA-256 hash in RefreshTokenRecord
    for server-side revocation. The token itself is returned to the client once.

    Args:
        user_id: The UserRecord.id for the authenticated user.
        role: The user's role string.
        ip_address: Optional client IP at login time (stored for session management UI).
        user_agent: Optional User-Agent header at login time (stored for session management UI).
        team_id: Team isolation ID (TEAM-02). None for admin users (TEAM-06).

    Returns:
        Encoded refresh token string (JWT).
    """
    from aila.platform.contracts._common import utc_now
    from aila.storage.db_models import RefreshTokenRecord

    settings = get_settings()
    payload = {
        "jti": uuid4().hex,
        "user_id": user_id,
        "role": role,
        "team_id": team_id,  # TEAM-02: None for admin users
        "typ": JWT_TYP_USER_REFRESH,
        "exp": datetime.now(UTC) + timedelta(seconds=_USER_REFRESH_EXPIRY),
        "iat": datetime.now(UTC),
    }
    token = jwt.encode(payload, settings.jwt_secret_key, algorithm=JWT_ALGORITHM)

    # Store SHA-256 hash of the token for server-side revocation (T-138-02)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires_at = datetime.now(UTC) + timedelta(seconds=_USER_REFRESH_EXPIRY)

    async with async_session_scope() as session:
        record = RefreshTokenRecord(
            user_id=user_id,
            token_hash=token_hash,
            expires_at=expires_at,
            created_at=utc_now(),
            ip_address=ip_address,
            user_agent=user_agent,
        )
        session.add(record)
        await session.commit()

    return token


# ---------------------------------------------------------------------------
# Unified auth dependency: accepts both user JWTs and API key JWTs
# ---------------------------------------------------------------------------


async def require_user_or_api_key(
    credentials: HTTPAuthorizationCredentials | None = Depends(_BEARER_SCHEME),
) -> AuthContext:
    """FastAPI dependency: accept both user JWTs (user_access) and API key JWTs (access).

    Allows endpoints to be called by either authenticated users or existing API keys,
    enabling a seamless transition period (D-16: backward compatibility).

    Returns an AuthContext with user_id, role, and auth_type so handlers can
    distinguish between user-based and API-key-based callers.

    Args:
        credentials: Injected from HTTPBearer; None if no Authorization header.

    Returns:
        AuthContext with user_id, role, auth_type.

    Raises:
        HTTPException(401): If credentials are missing or invalid.
    """
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization: Bearer <token> header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = credentials.credentials
    settings = get_settings()

    try:
        payload = jwt.decode(token, settings.jwt_secret_key, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        )

    typ = payload.get("typ")

    if typ == JWT_TYP_USER_ACCESS:
        # User JWT — validate against UserRecord with cache (TEAM-09)
        from aila.api.auth_cache import get_auth_cache
        from aila.storage.db_models import UserRecord

        user_id = payload.get("user_id")
        if not user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

        cache = get_auth_cache()
        user_cache_key = f"user:{user_id}"
        cached = await cache.check(user_cache_key)
        if cached is False:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account not found or deactivated",
            )

        async with async_session_scope() as session:
            user: UserRecord | None = await session.get(UserRecord, user_id)
        is_valid = user is not None and user.is_active
        if cached is None:
            await cache.store(user_cache_key, is_valid)
        if not is_valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User account not found or deactivated",
            )
        team_id = payload.get("team_id")  # TEAM-02: may be None for admin users
        return AuthContext(user_id=user.id, role=user.role, auth_type="user", team_id=team_id)

    elif typ == JWT_TYP_ACCESS:
        # API key JWT — delegate to existing blacklist check
        key_record = await decode_and_blacklist_check(token, expected_typ=JWT_TYP_ACCESS)
        return AuthContext(
            user_id=key_record.id,
            role=key_record.role,
            auth_type="api_key",
            team_id=getattr(key_record, "team_id", None),  # TEAM-01: from ApiKeyRecord
        )

    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Unexpected token type '{typ}'",
        )


async def get_team_context(
    auth: AuthContext = Depends(require_user_or_api_key),
) -> TeamContext:
    """FastAPI dependency: extract TeamContext from authenticated request (D-02).

    Returns TeamContext with team_id from JWT and is_admin derived from team_id=None.
    """
    return TeamContext.from_auth(auth)
