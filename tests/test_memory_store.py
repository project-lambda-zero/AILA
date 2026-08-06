"""Tests for PermanentMemoryStore and append_run_event.

Migrated to the shared PostgreSQL test_db fixture: every PermanentMemoryStore
method is async and takes an AsyncSession, so each test opens its own session
via async_session_scope() against aila_test. append_run_event stays sync (it
only mutates the in-process RunState events list, no DB touch).
"""
from __future__ import annotations

from aila.platform.contracts.runtime import RunState
from aila.storage.database import async_session_scope
from aila.storage.memory import PermanentMemoryStore, StoredMemoryEntry, append_run_event


class TestPermanentMemoryStore:
    async def test_remember_creates_entry(self, test_db):
        store = PermanentMemoryStore()
        async with async_session_scope() as session:
            await store.remember(session, "agent1", "key1", {"data": "value"})
        async with async_session_scope() as session:
            entry = await store.recall_entry(session, "agent1", "key1")
        assert entry is not None
        assert entry.payload == {"data": "value"}
        assert entry.namespace == "agent1"
        assert entry.key == "key1"

    async def test_remember_upserts_existing(self, test_db):
        store = PermanentMemoryStore()
        async with async_session_scope() as session:
            await store.remember(session, "agent1", "key1", {"v": 1})
        async with async_session_scope() as session:
            await store.remember(session, "agent1", "key1", {"v": 2})
        async with async_session_scope() as session:
            entry = await store.recall_entry(session, "agent1", "key1")
        assert entry.payload == {"v": 2}

    async def test_recall_entry_not_found(self, test_db):
        store = PermanentMemoryStore()
        async with async_session_scope() as session:
            entry = await store.recall_entry(session, "ns", "missing")
        assert entry is None

    async def test_forget_deletes_entry(self, test_db):
        store = PermanentMemoryStore()
        async with async_session_scope() as session:
            await store.remember(session, "ns", "k", {"d": 1})
        async with async_session_scope() as session:
            deleted = await store.forget(session, "ns", "k")
        assert deleted is True
        async with async_session_scope() as session:
            entry = await store.recall_entry(session, "ns", "k")
        assert entry is None

    async def test_forget_returns_false_when_not_found(self, test_db):
        store = PermanentMemoryStore()
        async with async_session_scope() as session:
            assert await store.forget(session, "ns", "missing") is False

    async def test_namespace_isolation(self, test_db):
        store = PermanentMemoryStore()
        async with async_session_scope() as session:
            await store.remember(session, "ns1", "key", {"v": "ns1"})
            await store.remember(session, "ns2", "key", {"v": "ns2"})
        async with async_session_scope() as session:
            ns1_entry = await store.recall_entry(session, "ns1", "key")
            ns2_entry = await store.recall_entry(session, "ns2", "key")
        assert ns1_entry.payload == {"v": "ns1"}
        assert ns2_entry.payload == {"v": "ns2"}

    async def test_stored_memory_entry_is_dataclass(self, test_db):
        store = PermanentMemoryStore()
        async with async_session_scope() as session:
            await store.remember(session, "ns", "k", {"d": 1})
        async with async_session_scope() as session:
            entry = await store.recall_entry(session, "ns", "k")
        assert isinstance(entry, StoredMemoryEntry)
        assert entry.created_at is not None
        assert entry.updated_at is not None


class TestAppendRunEvent:
    def test_appends_event(self):
        run_state = RunState(run_id="r1", query="test")
        append_run_event(run_state, "inventory_collected", "Collected 42 packages")
        assert len(run_state.events) == 1
        assert run_state.events[0].state == "inventory_collected"
        assert run_state.events[0].note == "Collected 42 packages"

    def test_appends_multiple(self):
        run_state = RunState(run_id="r1", query="test")
        append_run_event(run_state, "a", "first")
        append_run_event(run_state, "b", "second")
        assert len(run_state.events) == 2
        assert [e.state for e in run_state.events] == ["a", "b"]
