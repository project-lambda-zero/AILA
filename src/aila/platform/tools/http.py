from __future__ import annotations

import ipaddress
import json
import socket
from urllib.parse import urljoin, urlparse

import httpx

from ..config import PlatformSettings
from ..services.http import build_http_client
from ..services.log_redact import redact_secrets
from ._common import Tool, require_text

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


def _blocked_ip(addr: ipaddress.IPv4Address | ipaddress.IPv6Address) -> ipaddress.IPv4Network | ipaddress.IPv6Network | None:
    """Return the blocked network an address falls in, unwrapping IPv4-mapped
    IPv6 so ``::ffff:127.0.0.1`` is checked as ``127.0.0.1``."""
    check = addr
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        check = addr.ipv4_mapped
    for net in _BLOCKED_NETWORKS:
        if check.version == net.version and check in net:
            return net
    return None


def _check_url(url: str) -> None:
    """Reject a URL whose scheme, port, or resolved address violates policy.

    Enforced on the initial URL and re-enforced on every redirect hop so an
    external ``301 Location: http://169.254.169.254/...`` (cloud IMDS) or a
    redirect to a non-web scheme/port cannot smuggle the client into an
    internal target.
    """
    parsed = urlparse(url)
    scheme = (parsed.scheme or "").lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise SSRFBlockedError(f"http.fetch blocked: scheme '{scheme}' is not allowed")
    hostname = parsed.hostname
    if hostname is None:
        raise SSRFBlockedError("http.fetch blocked: URL has no hostname")
    port = parsed.port or (443 if scheme == "https" else 80)
    if port not in _ALLOWED_PORTS:
        raise SSRFBlockedError(f"http.fetch blocked: port {port} is not allowed")
    try:
        candidates = [ipaddress.ip_address(hostname)]
    except ValueError:
        try:
            resolved = socket.getaddrinfo(hostname, None)
        except socket.gaierror as exc:
            raise SSRFBlockedError(
                f"http.fetch blocked: DNS lookup failed for {hostname}"
            ) from exc
        candidates = [ipaddress.ip_address(info[4][0]) for info in resolved]
        if not candidates:
            raise SSRFBlockedError(f"http.fetch blocked: no addresses for {hostname}")
    # Refuse if ANY resolved answer is blocked -- defeats split-horizon DNS.
    for cand in candidates:
        net = _blocked_ip(cand)
        if net is not None:
            raise SSRFBlockedError(
                f"http.fetch blocked: {hostname} resolves to {cand} in {net}"
            )


class HTTPFetchTool(Tool):
    """Platform tool for making outbound HTTP requests from module agents.

    TLS verification is operator-controlled via platform settings (per-provider
    <provider>_verify_tls config field) -- not agent-controlled. This design was
    intentional (Phase 15): removing verify_tls from the tool's input schema
    prevents agents from bypassing TLS verification regardless of what the model
    requests. Proxy resolution is handled at the PlatformSettings level before
    the HTTP client is constructed.
    """

    name = "http_fetch"
    description = "Send an HTTP request with the platform user-agent and return the structured response."
    inputs = {
        "method": {"type": "string", "description": "HTTP method such as GET, POST, PUT, PATCH, DELETE, or HEAD."},
        "url": {"type": "string", "description": "Absolute URL to request."},
        "params": {
            "type": "object",
            "description": "Optional query parameters.",
            "nullable": True,
        },
        "headers": {
            "type": "object",
            "description": "Optional request headers.",
            "nullable": True,
        },
        "json_body": {
            "type": "object",
            "description": "Optional JSON request body.",
            "nullable": True,
        },
        "body": {
            "type": "string",
            "description": "Optional raw request body.",
            "nullable": True,
        },
        "timeout_seconds": {
            "type": "number",
            "description": "Optional per-request timeout override.",
            "nullable": True,
        },
        "raise_for_status": {
            "type": "boolean",
            "description": "Whether 4xx and 5xx responses should raise.",
            "nullable": True,
        },
        "max_text_chars": {
            "type": "integer",
            "description": "Optional maximum response text length to return.",
            "nullable": True,
        },
    }
    output_type = "object"

    def __init__(self, settings: PlatformSettings):
        self.settings = settings

    def forward(
        self,
        method: str,
        url: str,
        params: dict | None = None,
        headers: dict | None = None,
        json_body: object | None = None,
        body: str | None = None,
        timeout_seconds: float | None = None,
        raise_for_status: bool = False,
        max_text_chars: int | None = 100_000,
    ) -> dict:
        normalized_method = require_text(method, tool_name="http.fetch", field_name="method").upper()
        normalized_raise_for_status = require_optional_boolean(
            raise_for_status,
            field_name="raise_for_status",
        )
        if normalized_method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}:
            raise ValueError(f"Unsupported HTTP method '{method}'.")
        normalized_url = require_text(url, tool_name="http.fetch", field_name="url")
        if not (
            normalized_url.startswith("https://")
            or normalized_url.startswith("http://")
        ):
            raise ValueError("http.fetch requires an absolute http:// or https:// URL.")
        # SSRF policy is enforced per hop inside the redirect loop below.
        if body is not None and json_body is not None:
            raise ValueError("http.fetch accepts either body or json_body, not both.")
        if params is not None and not isinstance(params, dict):
            raise ValueError("http.fetch params must be an object.")
        if headers is not None and not isinstance(headers, dict):
            raise ValueError("http.fetch headers must be an object.")
        normalized_timeout_seconds = normalize_timeout_seconds(timeout_seconds)
        normalized_max_text_chars = normalize_max_text_chars(max_text_chars)
        request_timeout = (
            normalized_timeout_seconds
            if normalized_timeout_seconds is not None
            else self.settings.request_timeout_seconds
        )
        with build_http_client(self.settings) as client:
            current_url = normalized_url
            request_params = params
            response: httpx.Response | None = None
            # Follow redirects manually so every hop is re-validated against
            # the SSRF policy before its socket is opened. httpx's built-in
            # follow_redirects would jump straight to the redirect target.
            try:
                for _hop in range(_MAX_REDIRECT_HOPS + 1):
                    _check_url(current_url)
                    response = client.request(
                        normalized_method,
                        current_url,
                        params=request_params,
                        headers=headers,
                        json=json_body,
                        content=body.encode("utf-8") if body is not None else None,
                        timeout=request_timeout,
                        follow_redirects=False,
                    )
                    if response.status_code in _REDIRECT_CODES:
                        location = response.headers.get("location")
                        if not location:
                            break
                        current_url = urljoin(current_url, location)
                        request_params = None  # params apply to the first hop only
                        continue
                    break
                else:
                    raise SSRFBlockedError("http.fetch blocked: exceeded redirect limit")
                if response is None:  # defensive: the loop always assigns response
                    raise ValueError("http.fetch produced no response.")
                if normalized_raise_for_status:
                    response.raise_for_status()
            except httpx.HTTPError as exc:
                # Redact before surfacing: an httpx error string can carry the
                # request URL (query-string tokens) or an Authorization header
                # repr. SSRFBlockedError / ValueError raised above are policy
                # errors, not httpx.HTTPError, so they propagate unredacted.
                raise ValueError(
                    f"http.fetch upstream error: {exc.__class__.__name__}: "
                    f"{redact_secrets(str(exc))}"
                ) from exc
        text = response.text
        truncated = False
        if normalized_max_text_chars is not None and len(text) > normalized_max_text_chars:
            text = text[:normalized_max_text_chars]
            truncated = True
        return {
            "method": normalized_method,
            "url": str(response.url),
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "content_type": response.headers.get("content-type", ""),
            "text": text,
            "truncated": truncated,
            "json": _decode_json_response(response),
        }


def _decode_json_response(response: httpx.Response) -> object | None:
    try:
        return response.json()
    except (json.JSONDecodeError, ValueError):
        return None


def require_optional_boolean(value: object, *, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    raise ValueError(f"http.fetch {field_name} must be a boolean.")


def normalize_timeout_seconds(value: str | int | float | None) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError("http.fetch timeout_seconds must be a number.")
    normalized = float(value)
    if normalized <= 0:
        raise ValueError("http.fetch timeout_seconds must be > 0.")
    return normalized


def normalize_max_text_chars(value: str | int | float | None) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise ValueError("http.fetch max_text_chars must be an integer.")
    normalized = int(value)
    if normalized < 0:
        raise ValueError("http.fetch max_text_chars must be >= 0.")
    return normalized
