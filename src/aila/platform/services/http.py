from __future__ import annotations

from typing import Protocol

import httpx

__all__ = ["HTTPClientSettings", "build_http_client"]


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
    kwargs: dict[str, object] = {
        "timeout": settings.request_timeout_seconds,
        "headers": {"User-Agent": settings.user_agent},
        "follow_redirects": True,
        "verify": True if verify is None else verify,
    }
    if proxies:
        kwargs["proxies"] = {"http://": proxies, "https://": proxies}
    return httpx.Client(**kwargs)  # type: ignore[arg-type]
