"""Comprehensive health check response schemas (Phase 176d).

Defines the per-subsystem probe result shape used by GET /health/comprehensive.
Each subsystem returns a structured result with status, latency, and optional
details so the frontend can render a granular status grid.

All fields are safe to expose to authenticated admin users -- messages are
human-readable probe outcomes, not internal stack traces (T-176d-sec-01).
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from .common import APIModel

__all__ = [
    "ComprehensiveHealthResponse",
    "ModuleHealthSummary",
    "SshReachabilityResult",
    "SubsystemHealth",
]


SubsystemStatus = Literal[
    "healthy",
    "degraded",
    "unreachable",
    "rate_limited",
    "timed_out",
    "running",
    "stale",
    "offline",
    "unhealthy",
    "error",
    "unknown",
]


class SubsystemHealth(APIModel):
    """Status for a single subsystem probe.

    Fields:
        name: Stable identifier (e.g. 'redis', 'omniroute', 'arch_security').
        status: Probe outcome. See SubsystemStatus for allowed values.
        latency_ms: Round-trip latency in milliseconds when measurable.
        last_checked_at: ISO-8601 UTC timestamp when the probe completed.
        message: Human-readable summary, safe for admin display.
        details: Optional nested structured data (e.g. counts, per-system list).
    """

    name: str
    status: SubsystemStatus
    latency_ms: float | None = None
    last_checked_at: datetime
    message: str | None = None
    details: dict[str, Any] | None = None


class SshReachabilityResult(APIModel):
    """Per-system SSH TCP-connect probe result.

    We deliberately do NOT authenticate -- only verify the TCP port accepts
    a connection within the timeout. This is a cheap liveness signal, not an
    SSH credential test.
    """

    system_id: int
    system_name: str
    host: str
    port: int
    status: Literal["reachable", "unreachable", "timed_out", "error"]
    latency_ms: float | None = None
    message: str | None = None


class ModuleHealthSummary(APIModel):
    """Per-module activity summary used by the 'modules' subsystem entry."""

    module_id: str
    status: Literal["healthy", "stale", "error", "unknown"]
    last_activity_at: datetime | None = None
    activity_count: int | None = None
    message: str | None = None


class ComprehensiveHealthResponse(APIModel):
    """GET /health/comprehensive payload.

    Fields:
        overall_status: Aggregate summary across all subsystems.
        checked_at: When the overall probe batch began.
        subsystems: List of per-subsystem results, stable ordering.
    """

    overall_status: Literal["healthy", "degraded", "unhealthy"]
    checked_at: datetime
    subsystems: list[SubsystemHealth]
