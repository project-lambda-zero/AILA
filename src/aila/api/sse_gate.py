"""Global SSE connection ceiling (#60).

Every SSE-emitting endpoint (events, tasks, scans, sessions, forensics
investigation + readiness, vr investigation + messages, malware
messages) shares the process-wide ``ACTIVE_SSE`` Prometheus gauge to
report live-connection count. This module wraps a single guard function
those endpoints call inside their SSE generator (before ``ACTIVE_SSE.inc()``)
to short-circuit with HTTP 503 when the cap is reached.

The ceiling is read from :attr:`aila.platform.config.PlatformConfigSchema.sse_max_connections`
via :meth:`ConfigRegistry.get_sync` so an operator can widen or narrow
it with ``PUT /config/platform/sse_max_connections`` and the next
opening SSE request picks up the new value without a service restart.
A value ``<= 0`` disables the cap (tests only). A cap read failure
falls back to the schema default so a broken ConfigRegistry never
throws every SSE request into 503.

Enforcement is best-effort: the gauge is read from Prometheus'
in-process registry which does not require a lock. A tiny race in
which two requests both see ``count == cap - 1`` and both proceed is
acceptable; the ceiling is a safety net against runaway reconnect
loops, not a hard concurrency contract.
"""
from __future__ import annotations

import logging
import threading
from typing import Final

from fastapi import HTTPException, status

from aila.api.metrics import ACTIVE_SSE
from aila.platform.config import PlatformConfigSchema

__all__ = [
    "SSE_CAP_DEFAULT",
    "enforce_sse_cap",
    "get_sse_max_connections",
]

_log = logging.getLogger(__name__)

# The Retry-After header value used on 503 replies. Keeps the browser's
# EventSource reconnect from hammering the endpoint the moment it clears.
_RETRY_AFTER_SECONDS: Final[str] = "5"

# Falls back to the schema default when ConfigRegistry read fails so a
# broken registry never turns every SSE request into a 503.
SSE_CAP_DEFAULT: Final[int] = PlatformConfigSchema().sse_max_connections


# Module-level ConfigRegistry so successive cap reads share its TTL cache
# instead of building a fresh registry (and losing every prior cache hit)
# on every open SSE connection.
_CONFIG_REGISTRY = None
_CONFIG_REGISTRY_LOCK = threading.Lock()


def _get_registry():
    """Return the module-cached ConfigRegistry, building it on first call."""
    global _CONFIG_REGISTRY
    if _CONFIG_REGISTRY is not None:
        return _CONFIG_REGISTRY
    with _CONFIG_REGISTRY_LOCK:
        if _CONFIG_REGISTRY is None:
            from aila.storage.registry import ConfigRegistry

            _CONFIG_REGISTRY = ConfigRegistry()
    return _CONFIG_REGISTRY


def get_sse_max_connections() -> int:
    """Return the currently-configured SSE connection ceiling.

    Resolution order matches the platform config resolution:
    ``AILA_PLATFORM_SSE_MAX_CONNECTIONS`` env override > DB row >
    schema default. Reads sync so this helper can be called from the
    async SSE endpoint without pulling the caller into an ``await``.
    The underlying :class:`ConfigRegistry` is module-cached so its
    per-instance TTL cache is shared across every open-SSE call.
    """
    try:
        raw = _get_registry().get_sync("platform", "sse_max_connections")
    except (OSError, RuntimeError, TimeoutError, ValueError, TypeError) as exc:
        _log.debug("sse_max_connections registry read failed: %s", exc)
        return SSE_CAP_DEFAULT
    try:
        return int(raw) if raw is not None else SSE_CAP_DEFAULT
    except (ValueError, TypeError):
        return SSE_CAP_DEFAULT


def _current_active_sse() -> int:
    """Read the live ACTIVE_SSE Prometheus gauge as an int.

    ``Gauge._value.get()`` is the CPython-internal read path used by
    the prometheus_client library. It is not documented public API but
    is stable across the library's minor versions and avoids the
    serialise + parse round-trip of ``ACTIVE_SSE.collect()``.
    """
    try:
        return int(ACTIVE_SSE._value.get())  # type: ignore[attr-defined]
    except (AttributeError, ValueError, TypeError):
        # Fall through to the collect path if the internal shape ever
        # changes; slower but always correct.
        try:
            samples = ACTIVE_SSE.collect()
            for family in samples:
                for sample in family.samples:
                    if sample.name.endswith(("_total", "_created")):
                        continue
                    return int(sample.value)
        except (OSError, ValueError, TypeError, AttributeError):
            return 0
    return 0


def enforce_sse_cap() -> None:
    """Raise ``HTTPException(503)`` when the SSE connection ceiling is hit.

    Call at the top of each SSE endpoint (before ``ACTIVE_SSE.inc()``);
    the caller's normal generator setup runs only when the cap is not
    yet reached. A cap ``<= 0`` disables the check entirely.

    The 503 carries a ``Retry-After`` hint so the browser's EventSource
    reconnect back-off waits before retrying instead of hammering the
    endpoint the moment the ceiling clears.
    """
    cap = get_sse_max_connections()
    if cap <= 0:
        return
    current = _current_active_sse()
    if current >= cap:
        _log.warning(
            "SSE connection ceiling reached: %d/%d -- rejecting new stream",
            current, cap,
        )
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=(
                f"SSE connection ceiling reached ({current}/{cap}). "
                "Retry after a short back-off; already-connected clients "
                "continue streaming. Operators tune the ceiling via "
                "PUT /config/platform/sse_max_connections."
            ),
            headers={"Retry-After": _RETRY_AFTER_SECONDS},
        )
