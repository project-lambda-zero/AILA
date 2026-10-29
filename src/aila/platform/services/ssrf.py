"""Shared SSRF egress policy: address blocklist, URL validation, and httpx
transports that re-validate every request hop.

Historically the SSRF apparatus lived in ``aila.platform.tools.http`` and only
``HTTPFetchTool`` (module-agent egress) enforced it, following redirects
manually so each hop was re-checked. The platform ``build_http_client``
(used by CVE/provider fetchers and health probes) set ``follow_redirects=True``
with NO per-hop validation, so an external endpoint could ``301`` the client
into cloud IMDS (169.254.169.254) or an internal service (issue #42).

The policy now lives here so BOTH layers share one blocklist. The transports
below validate the request URL before the socket opens; httpx calls a
transport once per redirect hop, so wrapping the real transport re-checks the
initial URL and every redirect target without relying on event-hook ordering.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

import httpx

__all__ = [
    "SSRFBlockedError",
    "SSRFValidatingAsyncTransport",
    "SSRFValidatingTransport",
    "check_url",
    "endpoint_of",
]

_BLOCKED_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),  # link-local + cloud IMDS
    ipaddress.ip_network("100.64.0.0/10"),   # CGNAT
    ipaddress.ip_network("0.0.0.0/8"),        # "this network"
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)

# Defense-in-depth allow-lists: a redirect to file://, gopher://, or an
# SSH/other-service port is refused before the socket is opened.
_ALLOWED_SCHEMES: frozenset[str] = frozenset({"http", "https"})
_ALLOWED_PORTS: frozenset[int] = frozenset({80, 443, 8080, 8443})
_REDIRECT_CODES: frozenset[int] = frozenset({301, 302, 303, 307, 308})
_MAX_REDIRECT_HOPS = 3


class SSRFBlockedError(ValueError):
    """Raised when a URL or redirect target violates egress policy."""


def _blocked_ip(
    addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """Return the blocked network an address falls in, unwrapping IPv4-mapped
    IPv6 so ``::ffff:127.0.0.1`` is checked as ``127.0.0.1``."""
    check = addr
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        check = addr.ipv4_mapped
    for net in _BLOCKED_NETWORKS:
        if check.version == net.version and check in net:
            return net
    return None


def endpoint_of(url: str) -> frozenset[tuple[str, int]]:
    """Return the ``{(host, port)}`` singleton for a trusted base URL.

    Internal-MCP call sites (the sample ``/upload`` and index ``/refresh``
    fetches whose ``base_url`` is the operator-configured loopback MCP)
    pass this to :func:`check_url` / the SSRF transports as
    ``allow_endpoints`` so the exact trusted endpoint is exempt from the
    port allow-list and IP block-list. Everything else, including redirect
    targets to any other host:port, is still refused. Returns an empty set
    when the URL has no hostname.
    """
    parsed = urlparse(url)
    host = parsed.hostname
    if host is None:
        return frozenset()
    scheme = (parsed.scheme or "").lower()
    port = parsed.port or (443 if scheme == "https" else 80)
    return frozenset({(host, port)})


def check_url(
    url: str,
    *,
    allow_endpoints: frozenset[tuple[str, int]] = frozenset(),
) -> None:
    """Reject a URL whose scheme, port, or resolved address violates policy.

    Enforced on the initial URL and re-enforced on every redirect hop so an
    external ``301 Location: http://169.254.169.254/...`` (cloud IMDS) or a
    redirect to a non-web scheme/port cannot smuggle the client into an
    internal target.

    ``allow_endpoints`` is a set of trusted ``(host, port)`` tuples -- the
    operator-configured internal MCP base URLs. A URL whose host:port is in
    that set bypasses the port allow-list and the IP block-list (a loopback
    MCP on 127.0.0.1:18821 is the normal deployment and would otherwise be
    refused by ``127.0.0.0/8``). The scheme check still applies, and because
    this runs on every redirect hop, a redirect to any OTHER host:port is
    still refused -- only the exact trusted endpoint passes.
    """
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise SSRFBlockedError(f"egress blocked: scheme '{scheme}' is not allowed")
    hostname = parsed.hostname
    if hostname is None:
        raise SSRFBlockedError("egress blocked: URL has no hostname")
    port = parsed.port or (443 if scheme == "https" else 80)
    if (hostname, port) in allow_endpoints:
        return
    if port not in _ALLOWED_PORTS:
        raise SSRFBlockedError(f"egress blocked: port {port} is not allowed")
    try:
        candidates = [ipaddress.ip_address(hostname)]
    except ValueError:
        try:
            resolved = socket.getaddrinfo(hostname, None)
        except socket.gaierror as exc:
            raise SSRFBlockedError(
                f"egress blocked: DNS lookup failed for {hostname}"
            ) from exc
        candidates = [ipaddress.ip_address(info[4][0]) for info in resolved]
        if not candidates:
            raise SSRFBlockedError(f"egress blocked: no addresses for {hostname}")
    # Refuse if ANY resolved answer is blocked -- defeats split-horizon DNS.
    for cand in candidates:
        net = _blocked_ip(cand)
        if net is not None:
            raise SSRFBlockedError(
                f"egress blocked: {hostname} resolves to {cand} in {net}"
            )


class SSRFValidatingTransport(httpx.BaseTransport):
    """Sync transport wrapper that runs :func:`check_url` before each hop.

    httpx invokes the transport once per request, including every redirect
    hop when ``follow_redirects=True``, so wrapping the real transport
    re-validates the initial URL and every redirect target before its socket
    is opened. A violation raises :class:`SSRFBlockedError` and aborts the
    chain.
    """

    def __init__(
        self,
        inner: httpx.BaseTransport,
        allow_endpoints: frozenset[tuple[str, int]] = frozenset(),
    ) -> None:
        self._inner = inner
        self._allow_endpoints = allow_endpoints

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        check_url(str(request.url), allow_endpoints=self._allow_endpoints)
        return self._inner.handle_request(request)

    def close(self) -> None:
        self._inner.close()


class SSRFValidatingAsyncTransport(httpx.AsyncBaseTransport):
    """Async counterpart of :class:`SSRFValidatingTransport`.

    ``check_url`` performs a blocking DNS lookup; that is acceptable for the
    low-frequency health-probe path that uses this transport. Wrap the real
    async transport so each hop is validated before its socket is opened.
    """

    def __init__(
        self,
        inner: httpx.AsyncBaseTransport,
        allow_endpoints: frozenset[tuple[str, int]] = frozenset(),
    ) -> None:
        self._inner = inner
        self._allow_endpoints = allow_endpoints

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        check_url(str(request.url), allow_endpoints=self._allow_endpoints)
        return await self._inner.handle_async_request(request)

    async def aclose(self) -> None:
        await self._inner.aclose()
