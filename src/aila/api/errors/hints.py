"""Operator-facing hint registry for the error envelope (Phase 176a, D-31).

One source of truth for every hint string so UI-path changes require a single
grep. Hints are operator-facing prescriptive next steps -- never HTTP numbers,
stack traces, or raw exception text.
"""
from __future__ import annotations

__all__ = ["ERROR_HINTS"]


ERROR_HINTS: dict[str, str] = {
    # Typed AILAError subclasses (D-10b / D-20).
    "MISSING_API_KEY": (
        "Go to Admin -> API Keys and add the provider key for this operation."
    ),
    "SSH_CONNECTION_FAILED": (
        "Check the target system's SSH credentials under Systems -> target -> Credentials."
    ),
    "ROUTER_ERROR": (
        "An internal routing error occurred. Contact support with the trace ID shown below."
    ),
    "MODULE_PLATFORM_NOT_READY": (
        "The module runtime is still starting. Wait a few seconds and retry."
    ),
    "CONFIG_VALUE_MISSING": (
        "Set this config value under Admin -> Platform Config before retrying."
    ),
    "WORKER_UNREACHABLE": (
        "The background worker is not reachable. Check the Workers panel under "
        "Admin -> System Health."
    ),
    # Framework-level codes.
    "VALIDATION_ERROR": "Fix the highlighted input fields and retry.",
    "INTERNAL_ERROR": (
        "An unexpected error occurred. Contact support with the trace ID shown below."
    ),
    # Fallback for any unmapped code.
    "DEFAULT": (
        "An unexpected error occurred. Contact support with the trace ID shown below."
    ),
}
