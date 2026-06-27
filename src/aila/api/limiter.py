"""slowapi rate limiter singleton for AILA REST API.

Exported from this module (not from app.py) to avoid circular imports when
routers import the limiter at module load time.

Usage in routers:
    from aila.api.limiter import limiter

Usage in app.py:
    from aila.api.limiter import limiter
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
"""
from __future__ import annotations

import jwt
from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.requests import Request

__all__ = ["limiter"]


def _authenticated_user_key(request: Request) -> str:
    """Rate-limit bucket by authenticated user/key identity.

    Reads the Bearer token from the Authorization header and decodes the JWT
    payload WITHOUT signature verification -- we only need the identity claim
    for bucketing, not for security.  Falls back to remote IP for unauthenticated
    requests so the limiter still applies to the auth endpoints themselves.

    This prevents shared-egress / proxy collapse where all users behind a NAT
    share a single IP bucket (STRIDE T-04 finding from Phase 181 review).
    """
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        try:
            payload = jwt.decode(token, options={"verify_signature": False}, algorithms=["HS256"])
            uid: str | None = payload.get("user_id") or payload.get("key_id")
            if uid:
                return uid
        except jwt.PyJWTError:
            pass
    return get_remote_address(request)


# Per D-31 + STRIDE T-04: per-authenticated-user rate limiting.
# Falls back to remote IP for unauthenticated (login/refresh) endpoints.
limiter: Limiter = Limiter(key_func=_authenticated_user_key)
