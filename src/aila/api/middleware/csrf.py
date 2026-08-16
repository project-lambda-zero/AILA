"""CSRF double-submit enforcement middleware (#119).

The refresh token now travels as an ``HttpOnly`` cookie (``aila_refresh``) so
that XSS cannot exfiltrate it (see :mod:`aila.api.routers.users`). That
change turns every cookie-authenticated state-changing request into a live
CSRF surface: a hostile page can still trigger the browser into sending
those cookies alongside a POST to our origin.

This middleware closes that surface with the standard double-submit
pattern:

* The auth endpoints mint a random ``aila_csrf`` cookie (NOT ``HttpOnly``,
  so the SPA can read it).
* The SPA mirrors that value into the ``X-CSRF-Token`` header on every
  mutating request.
* This middleware rejects any mutating request whose header does not
  match the cookie with 403.

Exemptions:

* Read-only methods (``GET``, ``HEAD``, ``OPTIONS``) are unaffected.
* Requests carrying ``Authorization: Bearer …`` skip the check entirely.
  Bearer flows are not cookie-authenticated and therefore not
  CSRF-susceptible; the SPA's ``authorizedRequestJson`` sends the access
  token as a Bearer header, so this exemption covers the entire
  authenticated API surface.
* Requests that carry neither the refresh cookie nor a bearer token are
  unauthenticated (e.g. the initial ``POST /auth/login`` bootstrap
  before any cookie exists). They pass through here; the downstream
  handler decides whether to 401.
"""
from __future__ import annotations

import hmac
import logging

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

__all__ = [
    "AILA_CSRF_COOKIE",
    "AILA_REFRESH_COOKIE",
    "CSRF_HEADER_NAME",
    "CSRFMiddleware",
]

_log = logging.getLogger(__name__)

AILA_REFRESH_COOKIE: str = "aila_refresh"
AILA_CSRF_COOKIE: str = "aila_csrf"
CSRF_HEADER_NAME: str = "X-CSRF-Token"

_MUTATING_METHODS: frozenset[str] = frozenset({"POST", "PUT", "PATCH", "DELETE"})


class CSRFMiddleware(BaseHTTPMiddleware):
    """Reject cookie-authenticated mutating requests with a bad CSRF pair."""

    async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[override]
        if request.method.upper() not in _MUTATING_METHODS:
            return await call_next(request)

        # Bearer-authenticated requests are exempt -- the token is
        # unreachable from a cross-origin document, so there is no CSRF.
        auth_header = request.headers.get("authorization", "")
        if auth_header.lower().startswith("bearer "):
            return await call_next(request)

        # Unauthenticated request (no session cookie): let the downstream
        # handler run. Bootstrap flows like POST /auth/login have no
        # cookies to protect yet.
        refresh_cookie = request.cookies.get(AILA_REFRESH_COOKIE)
        if not refresh_cookie:
            return await call_next(request)

        csrf_cookie = request.cookies.get(AILA_CSRF_COOKIE, "")
        csrf_header = request.headers.get(CSRF_HEADER_NAME, "")
        if not csrf_cookie or not csrf_header or not hmac.compare_digest(csrf_cookie, csrf_header):
            _log.info(
                "csrf_reject path=%s method=%s cookie_present=%s header_present=%s",
                request.url.path,
                request.method,
                bool(csrf_cookie),
                bool(csrf_header),
            )
            return JSONResponse(
                status_code=403,
                content={
                    "detail": "CSRF token missing or mismatched",
                    "code": "csrf_invalid",
                    "errors": None,
                },
            )

        return await call_next(request)
