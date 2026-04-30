"""Dual-auth dependency for SbD NFR session endpoints.

Design references: D-23a, D-23b, D-23c, D-25, D-28, D-52, D-53, D-54, Pitfall 3.

Two access paths:

  JWT path:
    Standard Bearer token validated via decode_and_verify_token().
    Caller's role (owner / assigned architect / admin) determines permission level.

  Share-token path:
    No JWT. Caller provides ?share_token=<uuid> in the query string.
    contributor_name and contributor_email are also required (D-25) for audit
    traceability.  Share-token contributors can edit answers but cannot
    complete, delete, or trigger resolution (D-23c, T-134-09).

Pitfall 3 (from RESEARCH): using HTTPBearer(auto_error=True) would reject share-
token requests with 401 before our code can inspect the share_token param.
Use HTTPBearer(auto_error=False) and handle the no-JWT case ourselves.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from fastapi import Depends, HTTPException, Query, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from aila.platform.contracts.auth import AuthContext, decode_and_verify_token, require_auth

_log = logging.getLogger(__name__)

# auto_error=False so share-token requests are not rejected before we see them.
_OPTIONAL_BEARER: HTTPBearer = HTTPBearer(auto_error=False)

__all__ = [
    "SessionAccessContext",
    "require_session_access",
    "require_jwt_session_owner",
]


@dataclass(frozen=True, slots=True)
class SessionAccessContext:
    """Who is accessing a session: JWT owner, architect, admin, or share-token contributor.

    Properties encode the permission model per D-23a, D-23b, D-23c:
      - owner: full access including complete / delete / trigger resolution
      - architect: can complete / trigger resolution; cannot delete
      - admin: can complete + hard-delete; cannot edit answers via contributor path
      - share_token_contributor: can edit answers only
    """

    session_id: str
    is_owner: bool = False
    is_architect: bool = False        # assigned architect for THIS session
    is_admin: bool = False
    is_share_token_contributor: bool = False
    contributor_name: str = ""
    contributor_email: str = ""
    user_id: str | None = None        # ApiKeyRecord.id when JWT auth
    user_role: str = "contributor"    # "admin" | "operator" | "reader" | "contributor"

    @property
    def can_complete(self) -> bool:
        """Per D-23c: only owner, assigned architect, and admin can complete / delete / trigger resolution."""
        return self.is_owner or self.is_architect or self.is_admin

    @property
    def can_edit_answers(self) -> bool:
        """Owner, assigned architect, and share-token contributor can save answers."""
        return self.is_owner or self.is_architect or self.is_share_token_contributor

    @property
    def can_delete(self) -> bool:
        """Per D-35a: owner soft-delete; admin hard-delete."""
        return self.is_owner or self.is_admin


async def require_session_access(
    session_id: str,
    share_token: str | None = Query(default=None),
    contributor_name: str | None = Query(default=None),
    contributor_email: str | None = Query(default=None),
    credentials: HTTPAuthorizationCredentials | None = Depends(_OPTIONAL_BEARER),
    db: object | None = None,
) -> SessionAccessContext:
    """Dual-auth FastAPI dependency.

    Accepts either:
      - A Bearer JWT token (owner / architect / admin path), OR
      - ?share_token=<uuid> query param with contributor_name and contributor_email.

    Raises:
        HTTPException(401): No auth provided.
        HTTPException(400): Share-token path missing name or email (D-25).
        HTTPException(403): Auth provided but no matching access for this session.
        HTTPException(404): Session not found or soft-deleted.

    Note: The db parameter is expected to be provided at the call site via
    Depends(get_async_session) in the router layer.  This function signature
    accepts it as an optional param so it can be used as a Depends without
    breaking unit tests that call it directly.
    """
    # Lazy import to avoid circular dependency — db_models pulls in SQLModel.
    from sqlmodel import select
    from aila.modules.sbd_nfr.db_models import SbdNfrSessionRecord

    # --- Load session ---
    # db may be None when this function is called in tests without a real DB.
    # In production, db is always provided by the router's Depends chain.
    session_record: SbdNfrSessionRecord | None = None
    if db is not None:
        session_record = (await db.exec(
            select(SbdNfrSessionRecord).where(SbdNfrSessionRecord.id == session_id)
        )).first()
        if session_record is None or session_record.is_deleted:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Session '{session_id}' not found",
            )

    # --- JWT path ---
    if credentials is not None:
        try:
            key_record = await decode_and_verify_token(credentials.credentials)
        except HTTPException:
            raise

        is_admin = key_record.role == "admin"
        is_owner = session_record is not None and key_record.id == session_record.owner_id
        is_architect = (
            session_record is not None
            and session_record.assigned_architect_id is not None
            and key_record.id == session_record.assigned_architect_id
        )

        if not (is_owner or is_architect or is_admin):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have access to this session",
            )

        return SessionAccessContext(
            session_id=session_id,
            is_owner=is_owner,
            is_architect=is_architect,
            is_admin=is_admin,
            is_share_token_contributor=False,
            user_id=key_record.id,
            user_role=key_record.role,
        )

    # --- Share-token path ---
    if share_token is not None:
        if session_record is not None and share_token != session_record.share_token:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid share token for this session",
            )

        # D-25: name + email required for contributor audit traceability.
        if not contributor_name or not contributor_email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="contributor_name and contributor_email are required when accessing via share_token",
            )

        return SessionAccessContext(
            session_id=session_id,
            is_owner=False,
            is_architect=False,
            is_admin=False,
            is_share_token_contributor=True,
            contributor_name=contributor_name,
            contributor_email=contributor_email,
            user_id=None,
            user_role="contributor",
        )

    # --- No auth provided ---
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Provide a Bearer token or ?share_token= to access this session",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def require_jwt_session_owner(
    session_id: str,
    auth: AuthContext = Depends(require_auth),
    db: object | None = None,
) -> SessionAccessContext:
    """JWT-only dependency for owner/architect/admin operations.

    Used for complete, delete, trigger-resolution, and assign-architect
    endpoints where share-token contributors are explicitly prohibited (D-23c).

    Raises:
        HTTPException(403): JWT user lacks owner/architect/admin access.
        HTTPException(404): Session not found or soft-deleted.
    """
    from sqlmodel import select
    from aila.modules.sbd_nfr.db_models import SbdNfrSessionRecord

    session_record: SbdNfrSessionRecord | None = None
    if db is not None:
        session_record = (await db.exec(
            select(SbdNfrSessionRecord).where(SbdNfrSessionRecord.id == session_id)
        )).first()
        if session_record is None or session_record.is_deleted:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Session '{session_id}' not found",
            )

    is_admin = auth.role == "admin"
    is_owner = session_record is not None and auth.user_id == session_record.owner_id
    is_architect = (
        session_record is not None
        and session_record.assigned_architect_id is not None
        and auth.user_id == session_record.assigned_architect_id
    )

    if not (is_owner or is_architect or is_admin):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only the session owner, assigned architect, or admin may perform this action",
        )

    return SessionAccessContext(
        session_id=session_id,
        is_owner=is_owner,
        is_architect=is_architect,
        is_admin=is_admin,
        is_share_token_contributor=False,
        user_id=auth.user_id,
        user_role=auth.role,
    )
