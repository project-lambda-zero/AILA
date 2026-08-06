"""Registry for automatable actions.

Modules register actions during startup. AutomationRunner uses the
registry to resolve action_id -> handler function.
"""
from __future__ import annotations

__all__ = ["AutomationAction", "AutomationRegistry"]

import logging
import threading
from collections.abc import Callable
from dataclasses import dataclass

_log = logging.getLogger(__name__)


@dataclass(frozen=True)
class AutomationAction:
    """Immutable descriptor of a single automatable action.

    action_id:    Dot-separated identifier, e.g. 'vulnerability.scan'.
    handler_fn:   Callable invoked by AutomationRunner when the schedule fires.
    description:  Human-readable summary shown in the API listing.
    module_id:    Owning module (or 'platform' for maintenance jobs).
    param_schema: Optional JSON Schema dict describing accepted kwargs.
    """

    action_id: str
    handler_fn: Callable[..., object]
    description: str
    module_id: str
    param_schema: dict | None = None


class AutomationRegistry:
    """Thread-safe registry of automatable actions.

    Populated at startup by modules and platform code. Consumed by
    AutomationRunner to resolve action_id -> handler, and by the
    CRUD API to list available actions.

    Duplicate action_id registrations are rejected with ValueError.

    Finding 46-8: a threading.Lock now guards register_action's
    check-then-set race (two threads calling register_action for the
    same id could each pass the ``action_id in self._actions`` guard
    and both insert; the last writer would silently overwrite the
    first) and list_actions' iteration (list()/sort() over a live
    dict view raises RuntimeError if another thread mutates the dict
    mid-iteration). Reads via get_action/require_action take the same
    lock; the operation is a single dict.get and the extra acquire is
    cheap, but the guarantee is now uniform across the surface.
    """

    def __init__(self) -> None:
        self._actions: dict[str, AutomationAction] = {}
        # Guards register_action (check-then-set), list_actions
        # (iteration over the dict view), and get_action/require_action
        # (uniform lock discipline; a single dict.get is atomic under
        # CPython but the lock keeps the public contract simple).
        self._lock = threading.Lock()

    def register_action(
        self,
        action_id: str,
        handler_fn: Callable[..., object],
        description: str,
        module_id: str,
        param_schema: dict | None = None,
    ) -> None:
        """Register an automatable action.

        Raises ValueError if action_id is already registered.
        """
        action = AutomationAction(
            action_id=action_id,
            handler_fn=handler_fn,
            description=description,
            module_id=module_id,
            param_schema=param_schema,
        )
        with self._lock:
            if action_id in self._actions:
                raise ValueError(f"Duplicate automation action: {action_id!r}")
            self._actions[action_id] = action
        _log.info(
            "Registered automation action: %s (module=%s)",
            action_id,
            module_id,
        )

    def get_action(self, action_id: str) -> AutomationAction | None:
        """Return the action for the given ID, or None if not registered."""
        with self._lock:
            return self._actions.get(action_id)

    def require_action(self, action_id: str) -> AutomationAction:
        """Return the action for the given ID, raising KeyError if absent."""
        with self._lock:
            action = self._actions.get(action_id)
        if action is None:
            raise KeyError(f"Unknown automation action: {action_id!r}")
        return action

    def list_actions(self) -> list[AutomationAction]:
        """Return all registered actions sorted by action_id.

        Sorted output gives the HTTP listing endpoint a stable, deterministic
        order independent of module load order. The lock takes a snapshot of
        the values so a concurrent register_action call cannot mutate the
        dict during list()/sort().
        """
        with self._lock:
            actions = list(self._actions.values())
        actions.sort(key=lambda a: a.action_id)
        return actions
