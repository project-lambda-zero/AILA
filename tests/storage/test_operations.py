from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from sqlmodel import Field, SQLModel

from aila.storage.database import async_session_scope
from aila.storage.operations import cached_fetch, db_delete, db_upsert

# --- Minimal model for testing (created in the Postgres test DB by storage_db) ---

class _FakeRecord(SQLModel, table=True):
    __tablename__ = "fake_records"
    __table_args__ = {"extend_existing": True}

    id: int | None = Field(default=None, primary_key=True)
    key: str = Field(index=True)
    value: str = Field(default="")


@pytest.fixture()
async def db_session(storage_db):
    """AsyncSession against the Postgres test DB with the schema created.

    db_upsert / db_delete are async and take an AsyncSession; they commit
    immediately, and storage_db truncates fake_records after each test.
    """
    async with async_session_scope() as session:
        yield session


# ---------------------------------------------------------------------------
# db_upsert
# ---------------------------------------------------------------------------

async def test_db_upsert_creates_new_record(db_session):
    record, created = await db_upsert(
        db_session,
        _FakeRecord,
        lookup_filter=_FakeRecord.key == "alpha",
        update_fields={"key": "alpha", "value": "v1"},
    )
    assert created is True
    assert record.key == "alpha"
    assert record.value == "v1"
    assert record.id is not None


async def test_db_upsert_updates_existing_record(db_session):
    # Insert first
    await db_upsert(
        db_session,
        _FakeRecord,
        lookup_filter=_FakeRecord.key == "beta",
        update_fields={"key": "beta", "value": "original"},
    )

    # Update
    record, created = await db_upsert(
        db_session,
        _FakeRecord,
        lookup_filter=_FakeRecord.key == "beta",
        update_fields={"key": "beta", "value": "updated"},
    )
    assert created is False
    assert record.value == "updated"


# ---------------------------------------------------------------------------
# db_delete
# ---------------------------------------------------------------------------

async def test_db_delete_removes_matching_records(db_session):
    await db_upsert(
        db_session, _FakeRecord, _FakeRecord.key == "gamma", {"key": "gamma", "value": "x"}
    )

    deleted = await db_delete(db_session, _FakeRecord, _FakeRecord.key == "gamma")
    assert len(deleted) == 1
    assert deleted[0].key == "gamma"


async def test_db_delete_returns_empty_list_on_no_match(db_session):
    deleted = await db_delete(db_session, _FakeRecord, _FakeRecord.key == "nonexistent")
    assert deleted == []


# ---------------------------------------------------------------------------
# cached_fetch (synchronous -- no DB, unchanged)
# ---------------------------------------------------------------------------

def test_cached_fetch_returns_cache_hit():
    cached_payload = {"data": [1, 2, 3]}
    get_fn = MagicMock(return_value=cached_payload)
    fetch_fn = MagicMock()
    set_fn = MagicMock()

    result, source = cached_fetch(get_fn=get_fn, fetch_fn=fetch_fn, set_fn=set_fn)

    assert source == "cache"
    assert result == cached_payload
    fetch_fn.assert_not_called()
    set_fn.assert_not_called()


def test_cached_fetch_calls_fetch_on_miss():
    get_fn = MagicMock(return_value=None)
    live_data = [4, 5, 6]
    fetch_fn = MagicMock(return_value=live_data)
    set_fn = MagicMock()

    result, source = cached_fetch(get_fn=get_fn, fetch_fn=fetch_fn, set_fn=set_fn)

    assert source == "live"
    assert result == live_data
    fetch_fn.assert_called_once()
    set_fn.assert_called_once_with(live_data)


def test_cached_fetch_force_refresh_bypasses_cache():
    cached_payload = {"data": "old"}
    get_fn = MagicMock(return_value=cached_payload)
    live_data = {"data": "fresh"}
    fetch_fn = MagicMock(return_value=live_data)
    set_fn = MagicMock()

    # force_refresh=True bypasses freshness check entirely
    result, source = cached_fetch(
        get_fn=get_fn, fetch_fn=fetch_fn, set_fn=set_fn, force_refresh=True
    )

    assert source == "live"
    assert result == live_data
    fetch_fn.assert_called_once()
    set_fn.assert_called_once_with(live_data)
