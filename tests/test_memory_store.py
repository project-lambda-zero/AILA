"""Tests for PermanentMemoryStore and append_run_event."""
from __future__ import annotations

import pytest
from sqlmodel import Session, SQLModel, create_engine

from aila.platform.contracts.runtime import RunState
from aila.storage.memory import PermanentMemoryStore, StoredMemoryEntry, append_run_event


@pytest.fixture
def engine():
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    SQLModel.metadata.create_all(eng)
    yield eng
    SQLModel.metadata.drop_all(eng)


@pytest.fixture
def session(engine):
    with Session(engine) as s:
        yield s


class TestPermanentMemoryStore:
    def test_remember_creates_entry(self, session):
        store = PermanentMemoryStore()
        store.remember(session, "agent1", "key1", {"data": "value"})
        entry = store.recall_entry(session, "agent1", "key1")
        assert entry is not None
        assert entry.payload == {"data": "value"}
        assert entry.namespace == "agent1"
        assert entry.key == "key1"

    def test_remember_upserts_existing(self, session):
        store = PermanentMemoryStore()
        store.remember(session, "agent1", "key1", {"v": 1})
        store.remember(session, "agent1", "key1", {"v": 2})
        entry = store.recall_entry(session, "agent1", "key1")
        assert entry.payload == {"v": 2}

    def test_recall_entry_not_found(self, session):
        store = PermanentMemoryStore()
        entry = store.recall_entry(session, "ns", "missing")
        assert entry is None

    def test_forget_deletes_entry(self, session):
        store = PermanentMemoryStore()
        store.remember(session, "ns", "k", {"d": 1})
        deleted = store.forget(session, "ns", "k")
        assert deleted is True
        assert store.recall_entry(session, "ns", "k") is None

    def test_forget_returns_false_when_not_found(self, session):
        store = PermanentMemoryStore()
        assert store.forget(session, "ns", "missing") is False

    def test_namespace_isolation(self, session):
        store = PermanentMemoryStore()
        store.remember(session, "ns1", "key", {"v": "ns1"})
        store.remember(session, "ns2", "key", {"v": "ns2"})
        assert store.recall_entry(session, "ns1", "key").payload == {"v": "ns1"}
        assert store.recall_entry(session, "ns2", "key").payload == {"v": "ns2"}

    def test_stored_memory_entry_is_dataclass(self, session):
        store = PermanentMemoryStore()
        store.remember(session, "ns", "k", {"d": 1})
        entry = store.recall_entry(session, "ns", "k")
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
