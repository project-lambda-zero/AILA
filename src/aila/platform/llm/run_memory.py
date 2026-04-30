"""Run-scoped in-memory key-value store (per D-18, D-19, D-21).

Three memory tiers in AILA:
  - persistent: KnowledgeStore (cross-run, PostgreSQL)
  - ephemeral: messages list (per-call, passed to LLM)
  - run-scoped: RunMemory (per-run, in-memory, cleared on completion)

RunMemory is module-agnostic. Modules decide what to store (scoring summaries,
host context, etc.) -- the platform provides the mechanism.

Thread-safe for concurrent reads/writes within a run via threading.Lock.
"""

from __future__ import annotations

import threading
from typing import Any


class RunMemory:
    """In-memory key-value store scoped by run_id.

    Each run_id gets an isolated dict. Entries persist for the duration
    of the run and are cleared when clear(run_id) is called.

    Thread-safe: uses a lock to protect the internal dict-of-dicts.
    """

    def __init__(self) -> None:
        self._store: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def put(self, run_id: str, key: str, value: Any) -> None:
        """Store a value under (run_id, key).

        Overwrites any existing value for the same (run_id, key).

        Args:
            run_id: The run identifier.
            key: The key within the run's namespace.
            value: Any serializable value.
        """
        with self._lock:
            if run_id not in self._store:
                self._store[run_id] = {}
            self._store[run_id][key] = value

    def get(self, run_id: str, key: str, default: Any = None) -> Any:
        """Retrieve a value by (run_id, key).

        Args:
            run_id: The run identifier.
            key: The key within the run's namespace.
            default: Returned if the key does not exist.

        Returns:
            The stored value, or default if not found.
        """
        with self._lock:
            run_data = self._store.get(run_id)
            if run_data is None:
                return default
            return run_data.get(key, default)

    def append(self, run_id: str, key: str, value: Any) -> None:
        """Append a value to a list stored at (run_id, key).

        If the key does not exist, creates a new list with the value.
        If the key exists but is not a list, raises TypeError.

        Args:
            run_id: The run identifier.
            key: The key within the run's namespace.
            value: The value to append.

        Raises:
            TypeError: If the existing value is not a list.
        """
        with self._lock:
            if run_id not in self._store:
                self._store[run_id] = {}
            existing = self._store[run_id].get(key)
            if existing is None:
                self._store[run_id][key] = [value]
            elif isinstance(existing, list):
                existing.append(value)
            else:
                raise TypeError(
                    f"Cannot append to non-list value at ({run_id!r}, {key!r})"
                )

    def keys(self, run_id: str) -> list[str]:
        """Return all keys for a run_id.

        Args:
            run_id: The run identifier.

        Returns:
            List of key strings. Empty list if run_id not found.
        """
        with self._lock:
            run_data = self._store.get(run_id)
            if run_data is None:
                return []
            return list(run_data.keys())

    def clear(self, run_id: str) -> None:
        """Remove all entries for a run_id.

        Called when a run completes. No-op if run_id not found.

        Args:
            run_id: The run identifier to clear.
        """
        with self._lock:
            self._store.pop(run_id, None)

    def active_runs(self) -> list[str]:
        """Return list of run_ids that have entries.

        Returns:
            List of active run_id strings.
        """
        with self._lock:
            return list(self._store.keys())
