"""Process-local accessor for platform-runtime singletons that the hook
layer needs but cannot import via the normal runtime path.

The ARQ worker's ``_on_job_end`` runs outside the FastAPI request scope
where ``PlatformRuntime`` lives; it cannot reach the
``runtime_model.cost_tracker._mem`` reference. This module exposes a
single module-level slot the runtime sets once at startup so the hook
can find the same ``RunMemory`` instance for ``clear(run_id)`` calls
(§130) and any future cross-cut clean-up.

Set-once contract: ``set_shared_run_memory`` is called from
``build_platform_runtime`` (and from ARQ worker bootstrap once the
worker builds its own runtime). Subsequent calls overwrite the slot —
the most recent caller wins, which is the expected behaviour for tests
that swap in fakes.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from aila.platform.llm.run_memory import RunMemory

__all__ = ["get_shared_run_memory", "set_shared_run_memory"]

_SHARED_RUN_MEMORY: RunMemory | None = None


def set_shared_run_memory(run_memory: RunMemory | None) -> None:
    """Publish the process-wide RunMemory instance (§130 wiring)."""
    global _SHARED_RUN_MEMORY
    _SHARED_RUN_MEMORY = run_memory


def get_shared_run_memory() -> RunMemory | None:
    """Return the process-wide RunMemory instance, or None if not yet set."""
    return _SHARED_RUN_MEMORY
