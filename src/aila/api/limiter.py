"""slowapi rate limiter singleton for AILA REST API.

Exported from this module (not from app.py) to avoid circular imports when
routers import the limiter at module load time.

Usage in routers:
    from aila.api.limiter import limiter

Usage in app.py:
    from aila.api.limiter import limiter
    app.state.limiter = limiter
    app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

Pin justification (issue #56):
    ``slowapi==0.1.9`` is pinned in ``pyproject.toml``. Upstream is
    low-velocity but not abandoned in the security-critical sense: the
    surface actually exercised here is intentionally narrow -- ``Limiter``
    with a custom ``key_func`` plus the exception handler and per-route
    ``@limiter.limit(...)`` decorator. All rate-limit state lives in the
    in-process memory backend (no Redis storage, no signed-cookie window,
    no distributed synchronisation), so the historically CVE-prone slowapi
    features -- shared storage backends, IP spoofing via forwarded
    headers, custom cost keys -- are not in use. Bucketing is by
    authenticated identity (see ``_authenticated_user_key`` below), which
    supersedes the library-provided ``get_remote_address`` for anything
    behind a NAT / shared egress.

    Replacement surface is 35+ routers (every ``@limiter.limit`` site) and
    the shared ``request.app.state.limiter`` / ``RateLimitExceeded`` wiring
    in ``app.py``; that is not "small" in the ticket's sense, so we keep
    the pin and mitigate risk by (a) restricting slowapi to the in-process
    surface enumerated above and (b) auditing every version bump against
    the imports listed here (``Limiter``, ``get_remote_address``,
    ``_rate_limit_exceeded_handler``, ``RateLimitExceeded``). A move to a
    maintained alternative (e.g. ``fastapi-limiter`` + Redis, or a bespoke
    middleware) is a follow-up that should land in a dedicated PR so the
    per-route budget policy can be reviewed together.
"""
from __future__ import annotations

import jwt
from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.requests import Request

from aila.api.constants import JWT_ALGORITHM
from aila.config import get_settings

__all__ = ["limiter"]


def _authenticated_user_key(request: Request) -> str:
    """Rate-limit bucket by authenticated user/key identity.

    Reads the Bearer token from the Authorization header and decodes the JWT
    with full signature verification against the platform's HS256 secret.
    Only when the signature verifies do we bucket by the ``user_id`` / ``key_id``
    claim.  On ANY failure -- missing/malformed header, invalid signature,
    expired token, forged payload -- we fall back to ``get_remote_address``.

    Signature verification is load-bearing here (issue #172): with the previous
    ``verify_signature=False`` decode, anyone could send a forged JWT carrying
    a fabricated or rotating ``user_id`` to escape the per-IP brute-force limit
    on ``/auth/token`` (5/min) and ``/auth/login`` (10/min), or set a real
    admin ``key_id`` to exhaust that admin's quota.

    Bucketing by verified identity still preserves the legitimate NAT /
    shared-egress mitigation (D-31 / STRIDE T-04) for real logged-in users
    behind a shared IP.
    """
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        try:
            payload = jwt.decode(
                token,
                get_settings().jwt_secret_key,
                algorithms=[JWT_ALGORITHM],
            )
            uid: str | None = payload.get("user_id") or payload.get("key_id")
            if uid:
                return uid
        except jwt.PyJWTError:
            pass
    return get_remote_address(request)


# Per D-31 + STRIDE T-04: per-authenticated-user rate limiting.
# Falls back to remote IP for unauthenticated (login/refresh) endpoints.
limiter: Limiter = Limiter(key_func=_authenticated_user_key)
