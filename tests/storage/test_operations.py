from __future__ import annotations

from unittest.mock import MagicMock

import pytest
from sqlmodel import Field, Session, SQLModel, create_engine


# --- Minimal in-memory model for testing ---

class _FakeRecord(SQLModel, table=True):
    __tablename__ = "fake_records"
    __table_args__ = {"extend_existing": True}

    id: int | None = Field(default=None, primary_key=True)
    key: str = Field(index=True)
    value: str = Field(default="")


@pytest.fixture(scope="function")
def session():
    engine = create_engine("sqlite:///:memory:")
    SQLModel.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


# ---------------------------------------------------------------------------
# db_upsert
# ---------------------------------------------------------------------------

def test_db_upsert_creates_new_record(session):
    from aila.storage.operations import db_upsert

    record, created = db_upsert(
        session,
        _FakeRecord,
        lookup_filter=_FakeRecord.key == "alpha",
        update_fields={"key": "alpha", "value": "v1"},
    )
    assert created is True
    assert record.key == "alpha"
    assert record.value == "v1"
    assert record.id is not None


def test_db_upsert_updates_existing_record(session):
    from aila.storage.operations import db_upsert

    # Insert first
    db_upsert(
        session,
        _FakeRecord,
        lookup_filter=_FakeRecord.key == "beta",
        update_fields={"key": "beta", "value": "original"},
    )

    # Update
    record, created = db_upsert(
        session,
        _FakeRecord,
        lookup_filter=_FakeRecord.key == "beta",
        update_fields={"key": "beta", "value": "updated"},
    )
    assert created is False
    assert record.value == "updated"


# ---------------------------------------------------------------------------
# db_delete
# ---------------------------------------------------------------------------

def test_db_delete_removes_matching_records(session):
    from aila.storage.operations import db_upsert, db_delete

    db_upsert(session, _FakeRecord, _FakeRecord.key == "gamma", {"key": "gamma", "value": "x"})

    deleted = db_delete(session, _FakeRecord, _FakeRecord.key == "gamma")
    assert len(deleted) == 1
    assert deleted[0].key == "gamma"


def test_db_delete_returns_empty_list_on_no_match(session):
    from aila.storage.operations import db_delete

    deleted = db_delete(session, _FakeRecord, _FakeRecord.key == "nonexistent")
    assert deleted == []


# ---------------------------------------------------------------------------
# cached_fetch
# ---------------------------------------------------------------------------

def test_cached_fetch_returns_cache_hit():
    from aila.storage.operations import cached_fetch

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
    from aila.storage.operations import cached_fetch

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
    from aila.storage.operations import cached_fetch

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
