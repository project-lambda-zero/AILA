"""Generic periodic-sweep registry for the platform reaper cron.

Modules register their per-tick maintenance sweeps via
:func:`register_periodic_sweep`. The platform worker's reaper block
(``_run_reaper_block``) iterates this registry on every cron tick — the
worker has no awareness of which modules own which sweeps. This closes
the layering violation where ``aila.platform.tasks.worker`` used to
hardcode imports from ``aila.modules.vr.*``.

Contract:

* Sweep name is a unique string, conventionally ``"<module>.<sweep>"``
  (e.g. ``"vr.stage_tracker"``). Names appear in operator-facing log
  messages so the convention helps the operator correlate a failing
  sweep to its module.
* Sweep callable is an async no-arg function returning anything
  JSON-loggable. The worker logs the result at INFO when truthy.
* Sweep failures are swallowed by the worker per the existing
  best-effort cron policy (``# noqa: BLE001`` block). Each module
  is responsible for its own retry / counter / alert escalation.

Registration is module-load-time. Each module's top-level
``__init__.py`` (or ``module.py`` factory) calls
:func:`register_periodic_sweep` for every sweep it owns. The registry
is process-local; ARQ workers and FastAPI processes each populate it
via the same import side-effect.

The registration order is preserved (insertion order on the dict). The
worker invokes sweeps in registration order so an operator can reason
about ordering by reading the module's init file.

Deregistration is intentionally not exposed: sweeps are static
declarations, not runtime state. Tests that need to isolate one
sweep should monkeypatch :data:`_PERIODIC_SWEEPS` directly.
"""
from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any

__all__ = [
    "PeriodicSweep",
    "all_periodic_sweeps",
    "register_periodic_sweep",
]


PeriodicSweep = Callable[[], Awaitable[Any]]

_PERIODIC_SWEEPS: dict[str, PeriodicSweep] = {}


def register_periodic_sweep(name: str, sweep: PeriodicSweep) -> None:
    """Register a periodic sweep under ``name``.

    Raises :class:`ValueError` if ``name`` is already registered. The
    duplicate-registration check is the canary that catches the
    double-import case (e.g. a module's ``__init__.py`` runs twice
    in a test fixture). Tests that genuinely need to re-register
    should clear the entry first.
    """
    if not name:
        raise ValueError(
            f"register_periodic_sweep: name must be a non-empty string, got {name!r}",
        )
    if name in _PERIODIC_SWEEPS:
        raise ValueError(
            f"register_periodic_sweep: name {name!r} already registered "
            f"to {_PERIODIC_SWEEPS[name]!r}; re-registration is a bug",
        )
    if not callable(sweep):
        raise ValueError(
            f"register_periodic_sweep: sweep for {name!r} must be callable, "
            f"got {type(sweep).__name__}",
        )
    _PERIODIC_SWEEPS[name] = sweep


def all_periodic_sweeps() -> dict[str, PeriodicSweep]:
    """Return a shallow copy of the registered sweeps, preserving order.

    Worker callers iterate the returned dict; the platform reaper
    block must NOT mutate ``_PERIODIC_SWEEPS`` directly so a copy is
    handed out.
    """
    return dict(_PERIODIC_SWEEPS)
