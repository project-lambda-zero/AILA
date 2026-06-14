"""Run-scoped key-value store (per D-18, D-19, D-21).

Three memory tiers in AILA:
  - persistent: KnowledgeStore (cross-run, PostgreSQL)
  - ephemeral: messages list (per-call, passed to LLM)
  - run-scoped: RunMemory (per-run, in-memory dict + DB-backed token
    counters for cross-worker correctness)

RunMemory is module-agnostic. Modules decide what to store (scoring
summaries, host context, etc.); the platform provides the mechanism.

Two §128 / §129 / §130 corrections in this revision:

1. Token counters (``_cost_prompt_tokens`` /
   ``_cost_completion_tokens``) are no longer process-local. The
   ``ensure_cost_seeded`` helper queries ``llm_cost_records`` for the
   run on first access and seeds the in-memory totals from the durable
   ledger. A worker restart no longer resets the budget back to zero;
   two workers running siblings of the same investigation see the same
   spend.
2. Terminal-state handlers explicitly call :meth:`clear` so the
   process-local cache doesn't grow monotonically across thousands of
   investigations.

Thread-safe for concurrent reads/writes within a run via a lock.
"""

from __future__ import annotations

import logging
import threading
from typing import Any

from sqlalchemy.exc import SQLAlchemyError

_log = logging.getLogger(__name__)

# Cost counter keys (mirrored from ``cost.py`` for the DB-seed path).
_KEY_PROMPT = "_cost_prompt_tokens"
_KEY_COMPLETION = "_cost_completion_tokens"
_SEED_FLAG = "_cost_seeded_from_db"


class RunMemory:
    """In-memory key-value store scoped by run_id with DB-backed cost seed.

    Each run_id gets an isolated dict. Token-counter keys (set by
    :class:`CostTracker`) are seeded on first access from
    ``LLMCostRecord`` so the in-memory total tracks the durable ledger
    even across worker restarts and across multiple workers running
    siblings of the same investigation (fix §128 / §129).

    Thread-safe: uses a lock to protect the internal dict-of-dicts.
    """

    def __init__(self) -> None:
        self._store: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def put(self, run_id: str, key: str, value: Any) -> None:
        """Store a value under (run_id, key). Overwrites existing values."""
        with self._lock:
            if run_id not in self._store:
                self._store[run_id] = {}
            self._store[run_id][key] = value

    def get(self, run_id: str, key: str, default: Any = None) -> Any:
        """Retrieve a value by (run_id, key)."""
        with self._lock:
            run_data = self._store.get(run_id)
            if run_data is None:
                return default
            return run_data.get(key, default)

    def append(self, run_id: str, key: str, value: Any) -> None:
        """Append a value to a list stored at (run_id, key)."""
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
        """Return all keys for a run_id."""
        with self._lock:
            run_data = self._store.get(run_id)
            if run_data is None:
                return []
            return list(run_data.keys())

    def clear(self, run_id: str) -> None:
        """Remove all entries for a run_id (fix §130).

        Called from terminal-state handlers so the process-local cache
        doesn't grow without bound. Idempotent — no-op if the run_id was
        never touched.
        """
        with self._lock:
            self._store.pop(run_id, None)

    def active_runs(self) -> list[str]:
        """Return list of run_ids that have entries."""
        with self._lock:
            return list(self._store.keys())

    async def ensure_cost_seeded(self, run_id: str) -> None:
        """Seed in-memory token counters from LLMCostRecord on first touch.

        Worker restart used to wipe the in-memory total, so the next
        budget check saw zero spend even if the durable ledger had a
        million tokens charged against the run (§128). Two workers
        running siblings of the same investigation had independent
        totals (§129). Both bugs disappear when the in-memory total is
        seeded from the LLMCostRecord SUM(prompt + completion) on first
        access for a run_id.

        Idempotent: a per-run sentinel flag prevents repeat queries; if
        the lookup fails the in-memory total stays at whatever it was
        (operators still get a working — if optimistic — budget check).
        """
        if not run_id or run_id == "_no_run":
            return
        # Avoid the lock-while-IO antipattern: snapshot the sentinel,
        # do the DB query lock-free, then upgrade the in-memory state.
        if self.get(run_id, _SEED_FLAG, False):
            return
        try:
            from sqlalchemy import select as _select  # noqa: PLC0415
            from sqlalchemy.sql import func as _func  # noqa: PLC0415

            from aila.platform.llm.cost_record import LLMCostRecord  # noqa: PLC0415
            from aila.storage.database import async_session_scope  # noqa: PLC0415

            async with async_session_scope() as session:
                row = (
                    await session.execute(
                        _select(
                            _func.coalesce(
                                _func.sum(LLMCostRecord.prompt_tokens), 0,
                            ),
                            _func.coalesce(
                                _func.sum(LLMCostRecord.completion_tokens), 0,
                            ),
                        ).where(LLMCostRecord.run_id == run_id)
                    )
                ).first()
        except (SQLAlchemyError, OSError, RuntimeError) as exc:
            _log.debug(
                "run_memory.ensure_cost_seeded: seed failed for %s: %s",
                run_id, exc,
            )
            return
        if row is None:
            return
        prompt_total = int(row[0] or 0)
        completion_total = int(row[1] or 0)
        with self._lock:
            bucket = self._store.setdefault(run_id, {})
            # Take the MAX of the seeded value and any value already in
            # memory — a record() between the seed query and this commit
            # would otherwise be lost.
            bucket[_KEY_PROMPT] = max(
                int(bucket.get(_KEY_PROMPT, 0)), prompt_total,
            )
            bucket[_KEY_COMPLETION] = max(
                int(bucket.get(_KEY_COMPLETION, 0)), completion_total,
            )
            bucket[_SEED_FLAG] = True
