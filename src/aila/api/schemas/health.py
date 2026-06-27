"""Health check response schemas for the AILA REST API."""
from __future__ import annotations

from typing import Literal

from .common import APIModel

__all__ = ["HealthCheckResult", "HealthCheckResponse", "StatusResponse"]


class HealthCheckResult(APIModel):
    """Status for a single health check (API response schema).

    Distinct from aila.platform.modules.protocol.ModuleHealthResult (the
    protocol-layer dataclass). This Pydantic model is used only for
    serializing health data into the JSON response.

    Fields:
        status: 'up', 'degraded', or 'down'.
        latency_ms: Optional round-trip time in milliseconds.
        message: Optional human-readable detail (e.g. error message on failure).
    """

    status: Literal["up", "degraded", "down"]
    latency_ms: float | None = None
    message: str | None = None


class HealthCheckResponse(APIModel):
    """Response from GET /health.

    Returns 200 always -- never 503 (D-15). Callers check the top-level
    'status' field for overall health and the per-check 'checks' dict for
    granular status.

    Fields:
        status: 'healthy' (all up), 'degraded' (some degraded), or
            'unhealthy' (any down).
        checks: Dict mapping check name to HealthCheckResult.
            Core check: 'database'. Module checks prefixed with module_id.
    """

    status: Literal["healthy", "degraded", "unhealthy"]
    checks: dict[str, HealthCheckResult]


class StatusResponse(APIModel):
    """Response from GET /status.

    Fields:
        version: AILA package version string (from importlib.metadata).
        uptime_seconds: Seconds since the API process started.
    """

    version: str
    uptime_seconds: int
