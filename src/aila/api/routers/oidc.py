"""OIDC router for AILA REST API -- multi-provider authentication (Phase 177).

Supports three provider_type values:

    microsoft  -- Azure AD via msal + tenant_id (backward compatible, D-15)
    google     -- https://accounts.google.com/.well-known/openid-configuration
    generic    -- operator-supplied issuer_url (any OIDC-compliant IdP)

For Google and generic providers, the callback handler:
  1. Fetches {issuer}/.well-known/openid-configuration to resolve endpoints.
  2. Exchanges the authorization code via the token endpoint.
  3. Verifies the id_token signature against the issuer's JWKS.
  4. Extracts the standard ``sub`` / ``email`` / ``name`` claims.

Per T-138-07: state parameter validation via signed JWT cookie prevents CSRF.
Per T-138-08: client_secret stored encrypted via SecretStore; never returned
from any endpoint response.

Endpoints (all envelope-wrapped):
  GET     /auth/oidc/authorize              -- Redirect URL (PUBLIC)
  GET     /auth/oidc/callback               -- Code exchange (PUBLIC)
  GET     /auth/oidc/providers              -- List providers (ADMIN)
  POST    /auth/oidc/providers              -- Create/upsert (ADMIN)
  PUT     /auth/oidc/providers/{id}         -- Update (ADMIN)
  DELETE  /auth/oidc/providers/{id}         -- Delete (ADMIN)
"""
from __future__ import annotations

import hmac
import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import httpx
import jwt
from fastapi import APIRouter, Cookie, Depends, HTTPException, Query, Request, Response, status
from pydantic import BaseModel, Field
from sqlmodel import select

from aila.api.auth import (
    issue_user_jwt,
    issue_user_refresh_token,
    require_role,
)
from aila.api.constants import JWT_ALGORITHM, ROLE_ADMIN
from aila.api.limiter import limiter
from aila.api.schemas.endpoints import OIDCAuthorizeResponse
from aila.api.schemas.envelope import DataEnvelope
from aila.api.schemas.users import TokenResponse
from aila.config import get_settings
from aila.platform.contracts._common import utc_now
from aila.storage.database import async_session_scope
from aila.storage.db_models import OIDCProviderRecord, SecretRecord, UserRecord
from aila.storage.secrets import SecretStore

__all__ = ["router"]

_log = logging.getLogger(__name__)

router = APIRouter(prefix="/auth/oidc", tags=["oidc"])

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_STATE_JWT_EXPIRY: int = 600  # 10 minutes
_OIDC_SECRET_SCOPE = "oidc"

_PROVIDER_TYPES = ("microsoft", "google", "generic")
_GOOGLE_ISSUER = "https://accounts.google.com"
_DEFAULT_SCOPES = ["openid", "email", "profile"]

# Bounded HTTP timeouts for well-known + token exchange + JWKS fetches.
_HTTP_TIMEOUT_SECONDS = 5.0

# Simple in-process cache for well-known and JWKS documents. Keyed by
# issuer/jwks_uri. Cleared on provider update so stale keys don't linger.
_METADATA_CACHE: dict[str, tuple[datetime, dict]] = {}
_METADATA_TTL_SECONDS = 3600  # 1 hour


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------


class OIDCProviderCreateRequest(BaseModel):
    """Request body for POST /auth/oidc/providers.

    ``provider_type`` selects the flow. Required fields depend on the type:

        microsoft: tenant_id, client_id, client_secret
        google:    client_id, client_secret  (issuer hardcoded)
        generic:   issuer_url, client_id, client_secret
    """

    provider_name: str = Field(..., min_length=1, max_length=64)
    provider_type: str = Field(..., pattern=r"^(microsoft|google|generic)$")
    display_name: str | None = Field(default=None, max_length=128)
    tenant_id: str | None = Field(default=None, max_length=256)
    issuer_url: str | None = Field(default=None, max_length=512)
    client_id: str = Field(..., min_length=1, max_length=512)
    client_secret: str = Field(..., min_length=1)
    scopes: list[str] | None = Field(default=None)
    is_enabled: bool = True


class OIDCProviderUpdateRequest(BaseModel):
    """Partial update. Only non-None fields are applied."""

    provider_name: str | None = Field(default=None, min_length=1, max_length=64)
    provider_type: str | None = Field(default=None, pattern=r"^(microsoft|google|generic)$")
    display_name: str | None = Field(default=None, max_length=128)
    tenant_id: str | None = Field(default=None, max_length=256)
    issuer_url: str | None = Field(default=None, max_length=512)
    client_id: str | None = Field(default=None, min_length=1, max_length=512)
    client_secret: str | None = None
    scopes: list[str] | None = None
    is_enabled: bool | None = None


class OIDCProviderResponse(BaseModel):
    """Response shape for a configured OIDC provider.

    Per T-138-08: ``client_secret`` is never returned.
    """

    id: str
    provider_name: str
    provider_type: str
    display_name: str | None
    tenant_id: str | None
    issuer_url: str | None
    client_id: str
    scopes: list[str]
    is_enabled: bool
    created_at: datetime


class OIDCProviderPublicResponse(BaseModel):
    """Minimal public representation (used by the login page).

    Exposes only fields needed to render a provider chooser. Never includes
    client_id, client_secret, tenant_id, or issuer_url -- those are admin-only.
    """

    id: str
    name: str
    provider_type: str


# ---------------------------------------------------------------------------
# Secret helpers
# ---------------------------------------------------------------------------


def _secret_key_for_provider(provider_id: str) -> str:
    """SecretStore key used for a given provider id."""
    return f"client_secret_{provider_id}"


async def _encrypt_client_secret(provider_id: str, plaintext: str) -> str:
    """Encrypt and persist a provider's client_secret.

    Returns the SecretRecord id stored on ``OIDCProviderRecord.client_secret_encrypted``.
    Uses SecretStore.upsert_secret which handles encryption and record lifecycle.
    """
    store = SecretStore()
    secret_key = _secret_key_for_provider(provider_id)
    async with async_session_scope() as session:
        record = await store.upsert_secret(
            session,
            scope=_OIDC_SECRET_SCOPE,
            secret_key=secret_key,
            plaintext=plaintext,
        )
        return record.id


async def _decrypt_client_secret(provider: OIDCProviderRecord) -> str:
    """Retrieve and decrypt the client_secret for a provider.

    Falls back to the legacy ``client_secret_microsoft`` key for rows created
    before Phase 177 migrated to per-provider secret keys.
    """
    settings = get_settings()
    store = SecretStore(settings)
    async with async_session_scope() as session:
        # Try new per-provider key first
        secret = await store.get_secret_by_key(
            session,
            scope=_OIDC_SECRET_SCOPE,
            secret_key=_secret_key_for_provider(provider.id),
        )
        if secret:
            return secret
        # Legacy fallback (pre-Phase-177 Microsoft-only deployment)
        legacy = await store.get_secret_by_key(
            session, scope=_OIDC_SECRET_SCOPE, secret_key="client_secret_microsoft"
        )
        return legacy or ""  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Well-known + JWKS fetchers
# ---------------------------------------------------------------------------


def _resolve_issuer(provider: OIDCProviderRecord) -> str:
    """Map a provider record to its canonical issuer URL."""
    if provider.provider_type == "google":
        return _GOOGLE_ISSUER
    if provider.provider_type == "microsoft":
        tenant = provider.tenant_id or "common"
        return f"https://login.microsoftonline.com/{tenant}/v2.0"
    if provider.provider_type == "generic":
        if not provider.issuer_url:
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="Generic OIDC provider missing issuer_url",
            )
        return provider.issuer_url.rstrip("/")
    raise HTTPException(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        detail=f"Unknown provider_type: {provider.provider_type!r}",
    )


async def _fetch_well_known(issuer: str) -> dict:
    """Fetch and cache the OIDC well-known metadata for an issuer."""
    cached = _METADATA_CACHE.get(issuer)
    now = datetime.now(UTC)
    if cached and (now - cached[0]).total_seconds() < _METADATA_TTL_SECONDS:
        return cached[1]

    url = f"{issuer}/.well-known/openid-configuration"
    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_SECONDS) as client:
            resp = await client.get(url)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to fetch OIDC metadata from {url}: {exc}",
        ) from exc

    data = resp.json()
    _METADATA_CACHE[issuer] = (now, data)
    return data


async def _fetch_jwks(jwks_uri: str) -> dict:
    """Fetch and cache a JWKS document."""
    cached = _METADATA_CACHE.get(jwks_uri)
    now = datetime.now(UTC)
    if cached and (now - cached[0]).total_seconds() < _METADATA_TTL_SECONDS:
        return cached[1]

    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_SECONDS) as client:
            resp = await client.get(jwks_uri)
        resp.raise_for_status()
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to fetch JWKS from {jwks_uri}: {exc}",
        ) from exc

    data = resp.json()
    _METADATA_CACHE[jwks_uri] = (now, data)
    return data


def _invalidate_metadata_cache() -> None:
    """Drop all cached well-known + JWKS docs (called on provider upsert/delete)."""
    _METADATA_CACHE.clear()


def _parse_scopes(scopes_json: str | None) -> list[str]:
    """Parse the scopes_json column, falling back to openid+email+profile."""
    if not scopes_json:
        return list(_DEFAULT_SCOPES)
    try:
        parsed = json.loads(scopes_json)
    except json.JSONDecodeError:
        return list(_DEFAULT_SCOPES)
    if not isinstance(parsed, list):
        return list(_DEFAULT_SCOPES)
    # Only keep short string scopes to avoid unbounded payloads in auth URL.
    return [str(s)[:64] for s in parsed if isinstance(s, str)][:16]


def _provider_to_response(p: OIDCProviderRecord) -> OIDCProviderResponse:
    return OIDCProviderResponse(
        id=p.id,
        provider_name=p.provider_name,
        provider_type=getattr(p, "provider_type", "microsoft"),
        display_name=getattr(p, "display_name", None),
        tenant_id=p.tenant_id,
        issuer_url=getattr(p, "issuer_url", None),
        client_id=p.client_id,
        scopes=_parse_scopes(getattr(p, "scopes_json", None)),
        is_enabled=p.is_enabled,
        created_at=p.created_at,
    )


# ---------------------------------------------------------------------------
# State JWT helpers (T-138-07)
# ---------------------------------------------------------------------------


def _make_state_jwt(redirect_uri: str, provider_id: str | None = None) -> str:
    """Create a short-lived signed JWT for OIDC state validation."""
    settings = get_settings()
    payload = {
        "jti": uuid4().hex,
        "typ": "oidc_state",
        "redirect_uri": redirect_uri,
        "provider_id": provider_id,
        "exp": datetime.now(UTC) + timedelta(seconds=_STATE_JWT_EXPIRY),
        "iat": datetime.now(UTC),
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=JWT_ALGORITHM)


def _validate_state_jwt(state_token: str) -> dict:
    """Validate the OIDC state JWT from the cookie (CSRF protection)."""
    settings = get_settings()
    try:
        payload = jwt.decode(state_token, settings.jwt_secret_key, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OIDC state token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OIDC state token")
    if payload.get("typ") != "oidc_state":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid OIDC state token type")
    return payload


# ---------------------------------------------------------------------------
# Provider lookup
# ---------------------------------------------------------------------------


async def _load_enabled_provider(provider_id: str | None = None) -> OIDCProviderRecord:
    """Load a specific provider by id, or fall back to the first enabled one."""
    async with async_session_scope() as session:
        if provider_id:
            provider = await session.get(OIDCProviderRecord, provider_id)
            if provider is None or not provider.is_enabled:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail=f"OIDC provider '{provider_id}' not found or disabled",
                )
            return provider
        stmt = select(OIDCProviderRecord).where(
            OIDCProviderRecord.is_enabled == True,
        )
        result = await session.exec(stmt)
        provider = result.first()
    if provider is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No OIDC provider configured. Configure one via POST /auth/oidc/providers.",
        )
    return provider


# ---------------------------------------------------------------------------
# Public provider listing (login page)
# ---------------------------------------------------------------------------


@router.get(
    "/providers/public",
    response_model=DataEnvelope[list[OIDCProviderPublicResponse]],
    summary="List enabled OIDC providers (PUBLIC)",
)
async def list_public_providers() -> DataEnvelope[list[OIDCProviderPublicResponse]]:
    """Return enabled providers for the login page selector.

    Publicly accessible -- only exposes provider id, display name, and type.
    No secrets, no issuer URLs, no client ids.
    """
    async with async_session_scope() as session:
        stmt = select(OIDCProviderRecord).where(
            OIDCProviderRecord.is_enabled == True,
        )
        result = await session.exec(stmt)
        providers = list(result.all())

    return DataEnvelope(
        data=[
            OIDCProviderPublicResponse(
                id=p.id,
                name=(getattr(p, "display_name", None) or p.provider_name),
                provider_type=getattr(p, "provider_type", "microsoft"),
            )
            for p in providers
        ]
    )


# ---------------------------------------------------------------------------
# Authorize endpoint
# ---------------------------------------------------------------------------


@router.get(
    "/authorize",
    response_model=DataEnvelope[OIDCAuthorizeResponse],
    summary="Get OIDC authorization URL",
)
async def oidc_authorize(
    response: Response,
    redirect_uri: str = Query(default="http://localhost:3000/auth/callback"),
    provider_id: str | None = Query(default=None, description="Specific provider id (optional)"),
) -> DataEnvelope[OIDCAuthorizeResponse]:
    """Return the OIDC authorization URL for the selected provider.

    Microsoft providers continue to use msal for backward compatibility.
    Google and generic providers build the auth URL from the well-known
    document.
    """
    provider = await _load_enabled_provider(provider_id)
    client_secret = await _decrypt_client_secret(provider)
    if not client_secret:
        raise HTTPException(status_code=500, detail="OIDC client_secret could not be decrypted")

    state_token = _make_state_jwt(redirect_uri, provider.id)
    scopes = _parse_scopes(getattr(provider, "scopes_json", None))

    provider_type = getattr(provider, "provider_type", "microsoft")

    if provider_type == "microsoft":
        import msal

        authority = f"https://login.microsoftonline.com/{provider.tenant_id or 'common'}"
        app = msal.ConfidentialClientApplication(
            client_id=provider.client_id,
            client_credential=client_secret,
            authority=authority,
        )
        auth_url = app.get_authorization_request_url(
            scopes=scopes,
            redirect_uri=redirect_uri,
            state=state_token,
        )
    else:
        # Google / generic: build URL from well-known
        issuer = _resolve_issuer(provider)
        meta = await _fetch_well_known(issuer)
        auth_endpoint = meta.get("authorization_endpoint")
        if not auth_endpoint:
            raise HTTPException(
                status_code=status.HTTP_502_BAD_GATEWAY,
                detail=f"OIDC issuer {issuer} missing authorization_endpoint",
            )
        from urllib.parse import urlencode

        params = {
            "client_id": provider.client_id,
            "response_type": "code",
            "scope": " ".join(scopes),
            "redirect_uri": redirect_uri,
            "state": state_token,
        }
        auth_url = f"{auth_endpoint}?{urlencode(params)}"

    response.set_cookie(
        key="oidc_state",
        value=state_token,
        httponly=True,
        secure=False,  # Flip to True behind HTTPS in production
        samesite="lax",
        max_age=_STATE_JWT_EXPIRY,
    )

    return DataEnvelope(data=OIDCAuthorizeResponse(authorization_url=auth_url))


# ---------------------------------------------------------------------------
# Callback endpoint
# ---------------------------------------------------------------------------


async def _exchange_code_standard(
    provider: OIDCProviderRecord,
    client_secret: str,
    code: str,
    redirect_uri: str,
) -> dict[str, Any]:
    """Exchange authorization code for tokens via the OIDC token endpoint.

    Used for Google + generic providers. Returns the parsed token response
    (``id_token``, ``access_token``, etc.).
    """
    issuer = _resolve_issuer(provider)
    meta = await _fetch_well_known(issuer)
    token_endpoint = meta.get("token_endpoint")
    if not token_endpoint:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"OIDC issuer {issuer} missing token_endpoint",
        )

    try:
        async with httpx.AsyncClient(timeout=_HTTP_TIMEOUT_SECONDS) as client:
            resp = await client.post(
                token_endpoint,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "client_id": provider.client_id,
                    "client_secret": client_secret,
                },
                headers={"Accept": "application/json"},
            )
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"OIDC token exchange request failed: {exc}",
        ) from exc

    if resp.status_code != 200:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"OIDC token exchange failed ({resp.status_code}): {resp.text[:200]}",
        )

    return resp.json()


async def _verify_id_token(
    provider: OIDCProviderRecord,
    id_token: str,
) -> dict[str, Any]:
    """Verify an id_token signature via the issuer's JWKS and return claims."""
    issuer = _resolve_issuer(provider)
    meta = await _fetch_well_known(issuer)
    jwks_uri = meta.get("jwks_uri")
    if not jwks_uri:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"OIDC issuer {issuer} missing jwks_uri",
        )

    jwks = await _fetch_jwks(jwks_uri)

    # Get the signing key from JWKS using the kid in the token header
    try:
        unverified_header = jwt.get_unverified_header(id_token)
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid id_token header: {exc}",
        ) from exc

    kid = unverified_header.get("kid")
    alg = unverified_header.get("alg", "RS256")

    matching_key = None
    for key in jwks.get("keys", []):
        if key.get("kid") == kid:
            matching_key = key
            break
    if matching_key is None and jwks.get("keys"):
        # Some IdPs publish single-key JWKS without a kid -- accept it.
        matching_key = jwks["keys"][0]
    if matching_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No matching JWKS key for id_token kid",
        )

    try:
        signing_key = jwt.PyJWK(matching_key).key  # type: ignore[arg-type]
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Failed to parse JWKS key: {exc}",
        ) from exc

    try:
        claims = jwt.decode(
            id_token,
            signing_key,
            algorithms=[alg],
            audience=provider.client_id,
            # Skip issuer check for microsoft (v2.0 vs tenant-specific issuer mismatches).
            options={"verify_iss": False},
        )
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"id_token verification failed: {exc}",
        ) from exc

    return claims


@router.get(
    "/callback",
    response_model=DataEnvelope[TokenResponse],
    summary="OIDC authorization callback",
)
async def oidc_callback(
    code: str = Query(..., description="Authorization code from OIDC provider"),
    state: str = Query(..., description="State token for CSRF validation"),
    redirect_uri: str = Query(default="http://localhost:3000/auth/callback"),
    oidc_state: str | None = Cookie(default=None),
) -> DataEnvelope[TokenResponse]:
    """Exchange OIDC authorization code for user session tokens.

    Validates state cookie (T-138-07). For Microsoft, uses msal. For
    Google/generic, exchanges code via the issuer's token_endpoint and
    verifies the id_token via JWKS.
    """
    if oidc_state is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Missing OIDC state cookie")
    state_payload = _validate_state_jwt(oidc_state)
    # Double-submit CSRF: the state echoed back by the IdP in the query string
    # must be byte-identical to the signed JWT stored in the httponly cookie.
    # (_make_state_jwt puts the same token in both the auth URL and the cookie.)
    if not hmac.compare_digest(oidc_state, state):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OIDC state mismatch")

    provider_id = state_payload.get("provider_id")
    provider = await _load_enabled_provider(provider_id)
    client_secret = await _decrypt_client_secret(provider)
    if not client_secret:
        raise HTTPException(status_code=500, detail="OIDC client_secret could not be decrypted")

    provider_type = getattr(provider, "provider_type", "microsoft")
    scopes = _parse_scopes(getattr(provider, "scopes_json", None))

    if provider_type == "microsoft":
        import msal

        authority = f"https://login.microsoftonline.com/{provider.tenant_id or 'common'}"
        app = msal.ConfidentialClientApplication(
            client_id=provider.client_id,
            client_credential=client_secret,
            authority=authority,
        )
        result_data = app.acquire_token_by_authorization_code(
            code=code,
            scopes=scopes,
            redirect_uri=redirect_uri,
        )
        if "error" in result_data:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"OIDC token exchange failed: {result_data.get('error_description', result_data['error'])}",
            )
        claims = result_data.get("id_token_claims", {})
    else:
        # Google / generic: token exchange + JWKS-verified id_token
        tokens = await _exchange_code_standard(provider, client_secret, code, redirect_uri)
        id_token = tokens.get("id_token")
        if not id_token:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="OIDC token response missing id_token",
            )
        claims = await _verify_id_token(provider, id_token)

    oidc_sub = claims.get("sub") or claims.get("oid")
    email = claims.get("email") or claims.get("preferred_username")
    name = claims.get("name", "")

    if not oidc_sub:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="OIDC response missing subject claim")

    # Look up or auto-provision user (D-15)
    async with async_session_scope() as session:
        stmt = select(UserRecord).where(UserRecord.oidc_sub == oidc_sub)
        result = await session.exec(stmt)
        user: UserRecord | None = result.first()

        if user is None:
            username = (name or email or oidc_sub).replace(" ", "_").lower()[:64]
            now = utc_now()
            user = UserRecord(
                username=username,
                email=email,
                oidc_sub=oidc_sub,
                role="operator",
                is_active=True,
                created_at=now,
                updated_at=now,
            )
            session.add(user)
            await session.commit()
            await session.refresh(user)
            _log.info(
                "OIDC user auto-provisioned: %s (provider=%s)", username, provider.provider_name
            )
        elif not user.is_active:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User account is deactivated")

        user_id = user.id
        role = user.role

    access_token, expires_in = issue_user_jwt(user_id, role)
    refresh_token = await issue_user_refresh_token(user_id, role)

    return DataEnvelope(
        data=TokenResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=expires_in,
        )
    )


# ---------------------------------------------------------------------------
# Admin-only provider management
# ---------------------------------------------------------------------------


_admin_router = APIRouter(
    prefix="",
    tags=["oidc"],
    dependencies=[Depends(require_role(ROLE_ADMIN))],
)


def _validate_create_payload(body: OIDCProviderCreateRequest) -> None:
    """Reject payloads with fields missing for the declared provider_type."""
    if body.provider_type == "microsoft" and not body.tenant_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Microsoft OIDC provider requires tenant_id",
        )
    if body.provider_type == "generic" and not body.issuer_url:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Generic OIDC provider requires issuer_url",
        )


@_admin_router.get(
    "/providers",
    response_model=DataEnvelope[list[OIDCProviderResponse]],
    summary="List OIDC providers",
)
async def list_providers() -> DataEnvelope[list[OIDCProviderResponse]]:
    """List all configured OIDC providers. Never returns client_secret."""
    async with async_session_scope() as session:
        result = await session.exec(select(OIDCProviderRecord))
        providers = list(result.all())
    return DataEnvelope(data=[_provider_to_response(p) for p in providers])


@limiter.limit("60/minute")
@_admin_router.post(
    "/providers",
    response_model=DataEnvelope[OIDCProviderResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Create an OIDC provider",
)
async def create_provider(
    request: Request, body: OIDCProviderCreateRequest
) -> DataEnvelope[OIDCProviderResponse]:
    """Create a new OIDC provider of any supported type."""
    _validate_create_payload(body)

    scopes_json = json.dumps(body.scopes) if body.scopes else '["openid","email","profile"]'

    # Create the record first so we have a stable id for the secret key.
    provider = OIDCProviderRecord(
        provider_name=body.provider_name,
        provider_type=body.provider_type,
        display_name=body.display_name,
        tenant_id=body.tenant_id,
        issuer_url=body.issuer_url,
        client_id=body.client_id,
        client_secret_encrypted="",  # Filled after secret persisted
        scopes_json=scopes_json,
        is_enabled=body.is_enabled,
        created_at=utc_now(),
    )

    async with async_session_scope() as session:
        session.add(provider)
        await session.commit()
        await session.refresh(provider)

    secret_ref = await _encrypt_client_secret(provider.id, body.client_secret)

    async with async_session_scope() as session:
        fresh = await session.get(OIDCProviderRecord, provider.id)
        if fresh is None:
            raise HTTPException(status_code=500, detail="Provider vanished after create")
        fresh.client_secret_encrypted = secret_ref
        session.add(fresh)
        await session.commit()
        await session.refresh(fresh)
        provider = fresh

    _invalidate_metadata_cache()
    return DataEnvelope(data=_provider_to_response(provider))


@limiter.limit("60/minute")
@_admin_router.put(
    "/providers/{provider_id}",
    response_model=DataEnvelope[OIDCProviderResponse],
    summary="Update an OIDC provider",
)
async def update_provider(
    request: Request,
    provider_id: str,
    body: OIDCProviderUpdateRequest,
) -> DataEnvelope[OIDCProviderResponse]:
    """Partial update. Only non-None fields are applied."""
    async with async_session_scope() as session:
        provider = await session.get(OIDCProviderRecord, provider_id)
        if provider is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Provider not found")

        if body.provider_name is not None:
            provider.provider_name = body.provider_name
        if body.provider_type is not None:
            provider.provider_type = body.provider_type
        if body.display_name is not None:
            provider.display_name = body.display_name
        if body.tenant_id is not None:
            provider.tenant_id = body.tenant_id
        if body.issuer_url is not None:
            provider.issuer_url = body.issuer_url
        if body.client_id is not None:
            provider.client_id = body.client_id
        if body.scopes is not None:
            provider.scopes_json = json.dumps(body.scopes)
        if body.is_enabled is not None:
            provider.is_enabled = body.is_enabled

        session.add(provider)
        await session.commit()
        await session.refresh(provider)

    if body.client_secret is not None:
        secret_ref = await _encrypt_client_secret(provider_id, body.client_secret)
        async with async_session_scope() as session:
            fresh = await session.get(OIDCProviderRecord, provider_id)
            if fresh is not None:
                fresh.client_secret_encrypted = secret_ref
                session.add(fresh)
                await session.commit()
                await session.refresh(fresh)
                provider = fresh

    _invalidate_metadata_cache()
    return DataEnvelope(data=_provider_to_response(provider))


@limiter.limit("60/minute")
@_admin_router.delete(
    "/providers/{provider_id}",
    response_model=DataEnvelope[dict],
    summary="Delete an OIDC provider",
)
async def delete_provider(
    request: Request, provider_id: str
) -> DataEnvelope[dict]:
    """Delete a provider. Associated SecretRecord is also removed."""
    async with async_session_scope() as session:
        provider = await session.get(OIDCProviderRecord, provider_id)
        if provider is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Provider not found")
        await session.delete(provider)
        # Drop the associated secret too
        stmt = select(SecretRecord).where(
            SecretRecord.scope == _OIDC_SECRET_SCOPE,
            SecretRecord.secret_key == _secret_key_for_provider(provider_id),
        )
        sec = (await session.exec(stmt)).first()
        if sec is not None:
            await session.delete(sec)
        await session.commit()

    _invalidate_metadata_cache()
    return DataEnvelope(data={"deleted": provider_id})


router.include_router(_admin_router)
