from __future__ import annotations

import ipaddress
import json
import socket
from urllib.parse import urlparse

import httpx

from ..config import PlatformSettings
from ..services.http import build_http_client
from ._common import Tool, require_text

_BLOCKED_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
)


def _check_ssrf(url: str) -> None:
    """Reject URLs targeting private/internal IP ranges."""
    parsed = urlparse(url)
    hostname = parsed.hostname
    if hostname is None:
        raise ValueError("Cannot parse hostname from URL.")
    try:
        addr = ipaddress.ip_address(hostname)
    except ValueError:
        # hostname is a domain name -- resolve and check all addresses
        try:
            resolved = socket.getaddrinfo(hostname, None)
        except socket.gaierror:
            return  # DNS failure will be handled downstream by httpx
        for info in resolved:
            resolved_addr = ipaddress.ip_address(info[4][0])
            for net in _BLOCKED_NETWORKS:
                if resolved_addr in net:
                    raise ValueError(
                        f"http.fetch blocked: {hostname} resolves to private IP {resolved_addr}"
                    )
        return
    # hostname is already an IP literal
    for net in _BLOCKED_NETWORKS:
        if addr in net:
            raise ValueError(
                f"http.fetch blocked: {hostname} is in private range {net}"
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
        _check_ssrf(normalized_url)
        if body is not None and json_body is not None:
            raise ValueError("http.fetch accepts either body or json_body, not both.")
        if params is not None and not isinstance(params, dict):
            raise ValueError("http.fetch params must be an object.")
        if headers is not None and not isinstance(headers, dict):
            raise ValueError("http.fetch headers must be an object.")
        normalized_timeout_seconds = normalize_timeout_seconds(timeout_seconds)
        normalized_max_text_chars = normalize_max_text_chars(max_text_chars)
        with build_http_client(self.settings) as client:
            response = client.request(
                normalized_method,
                normalized_url,
                params=params,
                headers=headers,
                json=json_body,
                content=body.encode("utf-8") if body is not None else None,
                timeout=normalized_timeout_seconds if normalized_timeout_seconds is not None else self.settings.request_timeout_seconds,
            )
            if normalized_raise_for_status:
                response.raise_for_status()
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
