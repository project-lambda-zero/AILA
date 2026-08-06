"""Response security-headers middleware (#47).

Adds a defensive-baseline set of HTTP security headers to every response so
API consumers get browser-level protection layered on top of the auth and
CORS layers. The headers are chosen to be safe defaults for JSON APIs; the
SPA is served separately (Vite dev / reverse proxy in production) and
carries its own ``<meta http-equiv="Content-Security-Policy">``.

Header set applied on every response:

* ``Content-Security-Policy`` -- ``default-src 'none'; frame-ancestors 'none'``
  by default. API responses are JSON so nothing should be renderable; the
  policy is a defence-in-depth barrier against a client that tries to
  interpret a response body as HTML (e.g. via a mis-set ``<iframe>`` or
  content-type sniffing exploit).
* ``X-Content-Type-Options: nosniff`` -- disables browser MIME sniffing.
* ``X-Frame-Options: DENY`` -- refuses framing regardless of CSP support.
* ``Referrer-Policy: strict-origin-when-cross-origin`` -- preserves the
  same-origin path but strips it cross-origin.
* ``Cross-Origin-Opener-Policy: same-origin`` -- process-isolates windows
  opened from a response, hardening against side-channel leaks.
* ``Cross-Origin-Resource-Policy: same-site`` -- prevents cross-site
  resource inclusion.
* ``Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()``
  -- disable browser features the API surface never needs.

Existing headers on the response are respected -- the middleware never
overwrites a header that was already set (e.g. a router-owned CSP for a
future HTML endpoint).
"""
from __future__ import annotations

import os

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

__all__ = ["SecurityHeadersMiddleware", "default_security_headers"]


def default_security_headers() -> dict[str, str]:
    """Return the header set applied by :class:`SecurityHeadersMiddleware`.

    Read once from module import; the CSP directive can be overridden via
    ``AILA_API_CSP`` for environments that need a custom policy (e.g. a
    reverse proxy that terminates SSE with different origin rules).
    """
    csp = os.environ.get(
        "AILA_API_CSP",
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'",
    )
    return {
        "Content-Security-Policy": csp,
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "Referrer-Policy": "strict-origin-when-cross-origin",
        "Cross-Origin-Opener-Policy": "same-origin",
        "Cross-Origin-Resource-Policy": "same-site",
        "Permissions-Policy": (
            "camera=(), microphone=(), geolocation=(), payment=(), "
            "usb=(), interest-cohort=()"
        ),
    }


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attach a fixed security-header baseline to every response.

    The middleware never overwrites a header a downstream handler set
    explicitly -- callers that need to relax one directive (e.g. an
    embed-friendly documentation page) can do so at the response level
    without a middleware ordering rewrite.
    """

    def __init__(self, app) -> None:
        super().__init__(app)
        self._headers = default_security_headers()

    async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[override]
        response: Response = await call_next(request)
        for name, value in self._headers.items():
            if name not in response.headers:
                response.headers[name] = value
        return response
