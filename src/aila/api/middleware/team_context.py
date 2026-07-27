"""TeamContext ambient binding middleware for FastAPI (#53).

Every authenticated request carries a JWT that includes the caller's
``team_id`` (``None`` for admin/god-tier). To let bare ``UnitOfWork()`` and
``async_session_scope()`` sites inherit the tenant scope without threading
``team_context=`` through every call, this middleware decodes the bearer
token, extracts the ``team_id`` claim, and binds a
:class:`~aila.api.auth.TeamContext` onto the ambient ContextVar for the
duration of the request.

Decode failures are silent: this middleware is NOT the auth boundary --
:func:`aila.api.auth.require_user_or_api_key` still fully validates the
token and rejects a bad request with 401. When decode fails here we simply
leave the ambient unset, which yields the god-tier bypass (same behavior
as an unauthenticated public endpoint today).
"""
from __future__ import annotations

import logging

import jwt
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from aila.api.auth import TeamContext
from aila.api.constants import (
    JWT_ALGORITHM,
    JWT_TYP_ACCESS,
    JWT_TYP_USER_ACCESS,
)
from aila.config import get_settings
from aila.platform.services.team_scope import team_context_scope

__all__ = ["TeamContextMiddleware"]

_log = logging.getLogger(__name__)


def _extract_bearer_token(request: Request) -> str | None:
    """Return the bearer token when present, else ``None``.

    Only accepts the ``Authorization: Bearer <token>`` shape. Any other
    scheme, a missing header, or malformed contents returns ``None`` and
    the request falls through to the god-tier bypass.
    """
    header = request.headers.get("Authorization")
    if not header:
        return None
    parts = header.split(" ", 1)
    if len(parts) != 2:
        return None
    scheme, token = parts[0].strip().lower(), parts[1].strip()
    if scheme != "bearer" or not token:
        return None
    return token


def _team_context_from_token(token: str) -> TeamContext | None:
    """Decode ``token`` and return its :class:`TeamContext`, or ``None``.

    Decoding is best-effort -- this middleware runs before auth deps, so
    any failure means the real auth layer will reject the request with
    401 anyway. Only the ``team_id`` claim is consulted; role, blacklist,
    and typ validation are the auth dependency's job.
    """
    settings = get_settings()
    try:
        payload = jwt.decode(
            token, settings.jwt_secret_key, algorithms=[JWT_ALGORITHM],
        )
    except jwt.PyJWTError as exc:
        # Advisory decode -- the real auth boundary (require_user_or_api_key)
        # rejects invalid tokens for real. Log at debug so the audit trail
        # records the failure class without leaking token bytes, and no warn
        # spam fires on anonymous requests.
        _log.debug("team_context middleware: JWT decode failed (%s)", type(exc).__name__)
        return None
    typ = payload.get("typ")
    if typ not in (JWT_TYP_ACCESS, JWT_TYP_USER_ACCESS):
        return None
    team_id = payload.get("team_id")
    # Normalize an empty-string team_id to None (god-tier bypass).
    if isinstance(team_id, str) and not team_id.strip():
        team_id = None
    if team_id is not None and not isinstance(team_id, str):
        # Malformed claim -- fall through unscoped; the auth dep will 401.
        return None
    return TeamContext(team_id=team_id, is_admin=team_id is None)


class TeamContextMiddleware(BaseHTTPMiddleware):
    """Bind the caller's :class:`TeamContext` to the ambient ContextVar.

    Runs early enough that every downstream FastAPI dependency, endpoint,
    and short-lived session opened during the request inherits the tenant
    scope. On unauthenticated / public endpoints the ambient stays unset
    and behavior matches the pre-#53 admin/global default.
    """

    async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[override]
        token = _extract_bearer_token(request)
        ctx = _team_context_from_token(token) if token else None
        # team_context_scope handles the None case correctly: it explicitly
        # binds ``None`` for the duration of the scope, restoring whatever
        # was there before. This matters for tests that construct an
        # explicit outer scope and expect it not to be clobbered by an
        # unauthenticated call slipping through the middleware.
        with team_context_scope(ctx):
            return await call_next(request)
