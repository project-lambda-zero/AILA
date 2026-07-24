"""IntelServiceProtocol -- platform contract for CVE intel resolution.

A feature module (today: ``vulnerability``) owns the concrete IntelService
that orchestrates NVD + EPSS + KEV lookups with caching and graceful
fallback. Other modules must not reach into that module's runtime to use it
-- that welds them to a specific peer. Instead the providing module's
runtime publishes the service through ``provides_intel_service()``; the
platform builder collects it onto ``PlatformRuntime.intel_service``; and
consumers resolve CVE intel through the platform without naming the
provider.

The returned knowledge object is owned by the providing module and consumed
structurally by callers (the vr CVE resolver reads ``description``,
``cvss_score``, ``base_severity``, ``epss_score``, ``epss_percentile``,
``kev_listed``, ``kev_date_added``, ``attack_vector``,
``privileges_required``, ``user_interaction``, ``nvd_url``,
``published_at``, and ``notes``). The platform declares the method contract,
not the knowledge shape, so it stays free of any module's contracts.
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable

__all__ = ["IntelServiceProtocol"]


@runtime_checkable
class IntelServiceProtocol(Protocol):
    """Resolve enriched intel for a single CVE, cache-first.

    The concrete implementation lives in the providing module; the return is
    that module's knowledge type (or ``None`` when the upstream lookup
    produced no real record) and is consumed structurally by callers.
    """

    async def fetch_cve_intel(
        self, cve_id: str, force_refresh: bool = False
    ) -> Any:
        ...
