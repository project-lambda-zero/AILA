"""Per-run session memory and permanent cross-run memory for AILA agents.

Session memory (RunState.events) is ephemeral and held in-process -- it is
cleared automatically when the run ends and never written to the database.

Permanent memory (PermanentMemoryStore) persists key-value payloads across
runs via PermanentMemoryRecord.  It is scoped by namespace so different agents
can maintain isolated stores without collision.  Operators can inspect and clear
entries via the platform memory tool.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.exc import IntegrityError
from sqlmodel import select

from ..platform.contracts._common import utc_now
from ..platform.contracts.platform import WorkflowEvent
from ..platform.contracts.runtime import RunState
from .db_models import PermanentMemoryRecord


@dataclass(frozen=True, slots=True)
class StoredMemoryEntry:
    """Immutable view of a single persistent memory entry read from the database.

    Returned by PermanentMemoryStore.recall_entry() to give callers access to
    timestamps alongside the payload without exposing the raw ORM model.
    """

    namespace: str
    key: str
    payload: dict
    created_at: datetime
    updated_at: datetime


class PermanentMemoryStore:
    """CRUD store for cross-run persistent memory entries (AGENT-08 platform capability).

    Each entry is scoped by (namespace, key).  Namespace is typically the agent
    class name; key is an arbitrary string identifying the piece of memory.

    Memory written here survives process restarts.  It must be explicitly deleted
    via forget() -- the platform does not automatically prune entries when a run ends.
    For run-scoped ephemeral state, use RunState.events (in-process only).
    """

    async def remember(self, session, namespace: str, key: str, payload: dict, *, commit: bool = True) -> None:
        """Upsert a memory entry.  Creates a new row or updates the payload if one exists.

        Uses an optimistic insert with IntegrityError rollback to handle concurrent
        writers safely -- races are rare but possible when multiple agents write to
        the same namespace/key in a single run.

        Args:
            session: Active AsyncSession.
            namespace: Scope for the entry (e.g. agent class name).
            key: Unique key within the namespace.
            payload: Dict to persist as JSON.
            commit: If True, commits the transaction.  Set False when batching
                multiple writes in one transaction.

        Raises:
            RuntimeError: If the entry could not be created or reloaded after
                an IntegrityError -- indicates a DB-level consistency issue.
        """
        payload_json = json.dumps(payload, sort_keys=True)
        existing = (await session.exec(
            select(PermanentMemoryRecord).where(
                PermanentMemoryRecord.namespace == namespace,
                PermanentMemoryRecord.memory_key == key,
            )
        )).first()
        if existing is None:
            session.add(
                PermanentMemoryRecord(
                    namespace=namespace,
                    memory_key=key,
                    payload_json=payload_json,
                )
            )
            try:
                if commit:
                    await session.commit()
                else:
                    await session.flush()
                return
            except IntegrityError:
                await session.rollback()
                existing = (await session.exec(
                    select(PermanentMemoryRecord).where(
                        PermanentMemoryRecord.namespace == namespace,
                        PermanentMemoryRecord.memory_key == key,
                    )
                )).first()

        if existing is None:
            raise RuntimeError(f"Permanent memory entry {namespace}/{key} could not be created or reloaded.")
        existing.payload_json = payload_json
        existing.updated_at = utc_now()
        session.add(existing)
        if commit:
            await session.commit()
        else:
            await session.flush()

    async def recall(self, session, namespace: str, key: str) -> dict | None:
        """Return the stored payload dict for (namespace, key), or None if absent."""
        entry = await self.recall_entry(session, namespace, key)
        return entry.payload if entry else None

    async def recall_entry(self, session, namespace: str, key: str) -> StoredMemoryEntry | None:
        """Return the full StoredMemoryEntry for (namespace, key), or None if absent."""
        entry = (await session.exec(
            select(PermanentMemoryRecord).where(
                PermanentMemoryRecord.namespace == namespace,
                PermanentMemoryRecord.memory_key == key,
            )
        )).first()
        if entry is None:
            return None
        return StoredMemoryEntry(
            namespace=entry.namespace,
            key=entry.memory_key,
            payload=json.loads(entry.payload_json),
            created_at=entry.created_at,
            updated_at=entry.updated_at,
        )

    async def forget(self, session, namespace: str, key: str) -> bool:
        """Delete the memory entry for (namespace, key).

        Returns:
            True if the entry existed and was deleted; False if not found.
        """
        entry = (await session.exec(
            select(PermanentMemoryRecord).where(
                PermanentMemoryRecord.namespace == namespace,
                PermanentMemoryRecord.memory_key == key,
            )
        )).first()
        if entry is None:
            return False
        await session.delete(entry)
        await session.commit()
        return True


def append_run_event(run_state: RunState, state: str, note: str) -> None:
    """Append a workflow event to the in-process run state event log.

    Events are ephemeral session memory -- they live in the RunState object for
    the duration of the run and are never written to the database.  They are
    used for agent observation and progress reporting within a single run.

    Args:
        run_state: The current run's RunState instance.
        state: A workflow state label (e.g. "inventory_collected").
        note: Human-readable description of what happened.
    """
    run_state.events.append(WorkflowEvent(state=state, note=note))

