from __future__ import annotations

from typing import ClassVar

__all__ = [
    "AILAError",
    "AuthenticationError",
    "RateLimitError",
    "NotFoundError",
    "ValidationError",
    "UpstreamError",
    "TimeoutError",
    # Phase 176a: typed exception taxonomy with ClassVar code + http_status (D-10b, D-20).
    "MissingApiKeyError",
    "SSHConnectionFailedError",
    "RouterError",
    "ModulePlatformNotReadyError",
    "ConfigValueMissingError",
    "WorkerUnreachableError",
]


class AILAError(Exception):
    """Base class for all AILA platform exceptions.

    Catch AILAError when you want to handle any platform error without
    importing each subclass. Maps to HTTP 500 when unhandled at the API layer.
    """


class AuthenticationError(AILAError):
    """Raised when a service rejects credentials.

    Covers SSH authentication failures and HTTP 401 responses from external
    providers. Maps to HTTP 401 at the API layer.
    """

    code: ClassVar[str] = "AUTHENTICATION_ERROR"
    http_status: ClassVar[int] = 401
    user_message: ClassVar[str] = "Authentication failed."


class RateLimitError(AILAError):
    """Raised when an external service enforces a request rate limit.

    Corresponds to HTTP 429 responses from NVD, EPSS, or other providers.
    Callers should back off and retry after a delay. Maps to HTTP 429 at the
    API layer.
    """

    code: ClassVar[str] = "RATE_LIMIT_ERROR"
    http_status: ClassVar[int] = 429
    user_message: ClassVar[str] = "Rate limit exceeded; retry after a delay."


class NotFoundError(AILAError):
    """Raised when a requested resource does not exist.

    Covers missing DB records (run_id not found, no cached report) and 404
    responses from external APIs. Maps to HTTP 404 at the API layer.
    """

    code: ClassVar[str] = "NOT_FOUND_ERROR"
    http_status: ClassVar[int] = 404
    user_message: ClassVar[str] = "The requested resource was not found."


class ValidationError(AILAError):
    """Raised when input fails validation at a service or workflow boundary.

    Distinguished from Pydantic's own ValidationError -- this is a domain-level
    error for semantically invalid inputs (e.g. an unresolvable SSH profile or
    an unsupported operation). Maps to HTTP 422 at the API layer.
    """

    code: ClassVar[str] = "VALIDATION_ERROR"
    http_status: ClassVar[int] = 422
    user_message: ClassVar[str] = "The request failed validation."


class UpstreamError(AILAError):
    """Raised when an external dependency fails.

    Covers SSH transport errors, NVD/EPSS HTTP failures, LLM errors, and other
    provider-level failures that are outside platform control. Maps to HTTP 502
    at the API layer.
    """

    code: ClassVar[str] = "UPSTREAM_ERROR"
    http_status: ClassVar[int] = 502
    user_message: ClassVar[str] = "An upstream dependency failed."


class TimeoutError(AILAError):
    """Raised when an external call exceeds its configured deadline.

    Covers SSH command timeouts and HTTP request timeouts on provider calls.
    Maps to HTTP 504 at the API layer.
    """

    code: ClassVar[str] = "TIMEOUT_ERROR"
    http_status: ClassVar[int] = 504
    user_message: ClassVar[str] = "The operation timed out."


# ---------------------------------------------------------------------------
# Phase 176a: typed exception taxonomy (D-10b).
#
# Each concrete class exposes ClassVar ``code`` and ``http_status`` attributes.
# The API error-envelope handler (aila.api.errors.handlers) reads these via
# getattr with a 500 fallback so pre-existing AILAError subclasses above -- which
# do NOT declare ``http_status`` -- remain compatible (preflight BE-E).
#
# Status codes are locked by phase decision D-20; do not mutate.
# ---------------------------------------------------------------------------


class MissingApiKeyError(AILAError):
    """Raised when a required LLM/provider API key is not configured.

    ``user_message`` is the ONLY string surfaced to API clients. ``str(exc)``
    (the constructor argument) is for server-side logs and must never reach
    the envelope -- it can carry internal paths, provider identifiers, or
    other sensitive context the caller passed in.
    """

    code: ClassVar[str] = "MISSING_API_KEY"
    http_status: ClassVar[int] = 503
    user_message: ClassVar[str] = "LLM API key is not configured."


class SSHConnectionFailedError(AILAError):
    """Raised when an SSH connection to a target system cannot be established."""

    code: ClassVar[str] = "SSH_CONNECTION_FAILED"
    http_status: ClassVar[int] = 502
    user_message: ClassVar[str] = "Could not reach SSH target."


class RouterError(AILAError):
    """Raised on an internal LLM/OmniRoute routing failure."""

    code: ClassVar[str] = "ROUTER_ERROR"
    http_status: ClassVar[int] = 500
    user_message: ClassVar[str] = "Internal routing error."


class ModulePlatformNotReadyError(AILAError):
    """Raised when a feature module's runtime is not yet initialized."""

    code: ClassVar[str] = "MODULE_PLATFORM_NOT_READY"
    http_status: ClassVar[int] = 503
    user_message: ClassVar[str] = "Module runtime is not ready."


class ConfigValueMissingError(AILAError):
    """Raised when a required platform config entry is absent."""

    code: ClassVar[str] = "CONFIG_VALUE_MISSING"
    http_status: ClassVar[int] = 500
    user_message: ClassVar[str] = "Required platform configuration is missing."


class WorkerUnreachableError(AILAError):
    """Raised when the background task worker cannot be reached."""

    code: ClassVar[str] = "WORKER_UNREACHABLE"
    http_status: ClassVar[int] = 503
    user_message: ClassVar[str] = "Background worker is not reachable."
