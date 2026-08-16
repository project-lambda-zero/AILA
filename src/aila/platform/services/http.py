from __future__ import annotations

from typing import Protocol

import httpx

from .ssrf import SSRFValidatingAsyncTransport, SSRFValidatingTransport

__all__ = ["HTTPClientSettings", "build_async_http_client", "build_http_client"]


class HTTPClientSettings(Protocol):
    """Minimal settings interface required by build_http_client.

    Implemented by PlatformSettings and any settings class that needs to
    construct an httpx.Client with platform defaults.
    """

    request_timeout_seconds: float
    user_agent: str


def build_http_client(
    settings: HTTPClientSettings,
    *,
    verify: bool | str | None = None,
    proxies: str | None = None,
) -> httpx.Client:
    """Construct an httpx.Client configured with platform defaults.

    TLS verification is operator-controlled via the verify parameter -- True by
    default, overridable per provider via the <provider>_verify_tls config field.
    Proxy is resolved by the caller (registry-first, then env var fallback) and
    passed here as a single URL string. The platform User-Agent and timeout are
    always applied from settings.
    """
    inner_kwargs: dict[str, object] = {"verify": True if verify is None else verify}
    if proxies:
        inner_kwargs["proxy"] = proxies
    # Wrap the real transport so every request hop -- initial URL AND each
    # redirect target (follow_redirects stays on) -- is validated against the
    # SSRF egress policy before its socket opens (issue #42). A redirect into
    # a private/link-local address, a non-web scheme, or a disallowed port
    # raises SSRFBlockedError and aborts the chain.
    transport = SSRFValidatingTransport(httpx.HTTPTransport(**inner_kwargs))  # type: ignore[arg-type]
    return httpx.Client(
        transport=transport,
        timeout=settings.request_timeout_seconds,
        headers={"User-Agent": settings.user_agent},
        follow_redirects=True,
    )


def build_async_http_client(
    settings: HTTPClientSettings,
    *,
    verify: bool | str | None = None,
    proxies: str | None = None,
    timeout: float | None = None,
) -> httpx.AsyncClient:
    """Async counterpart of :func:`build_http_client`.

    Modules that dispatch outbound HTTP from async request handlers (e.g.
    MCP-bridge upload/refresh fetches whose ``base_url`` is operator-set
    via the mcp registry) call this instead of constructing
    ``httpx.AsyncClient`` directly, so every request hop -- initial URL AND
    each redirect target -- is validated against the SSRF egress policy
    before its socket opens. A blocked scheme/port/address raises
    :class:`aila.platform.services.ssrf.SSRFBlockedError` and aborts the
    chain.

    ``timeout`` overrides ``settings.request_timeout_seconds`` for
    long-running paths (large uploads, index rebuilds) that legitimately
    need longer than the default request budget.
    """
    inner_kwargs: dict[str, object] = {"verify": True if verify is None else verify}
    if proxies:
        inner_kwargs["proxy"] = proxies
    transport = SSRFValidatingAsyncTransport(
        httpx.AsyncHTTPTransport(**inner_kwargs),  # type: ignore[arg-type]
    )
    return httpx.AsyncClient(
        transport=transport,
        timeout=settings.request_timeout_seconds if timeout is None else timeout,
        headers={"User-Agent": settings.user_agent},
        follow_redirects=True,
    )
