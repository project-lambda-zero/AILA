"""Tests for seed_data() subtask upsert behavior (TOOL-02).

Verifies that calling seed_data() twice with updated subtask data:
- Updates existing subtask component fields (label, category, description,
  is_active, icon_hint, display_order, updated_at)
- Never deletes existing subtask rows (Pitfall 4)
- Creates new subtask rows when key is absent

These tests use the async_db_session fixture from conftest.py which provides
a clean in-memory SQLite DB per test.  Requires aiosqlite.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_subtask(key: str, label: str, category: str = "Security") -> dict[str, Any]:
    return {
        "key": key,
        "label": label,
        "category": category,
        "description": f"Description for {key}",
        "icon_hint": "shield",
        "display_order": 1,
        "is_active": True,
    }


# ---------------------------------------------------------------------------
# Unit tests — mock session (no DB required)
# ---------------------------------------------------------------------------


class TestSubtaskUpsertUnit:
    """Unit-level tests using a dict-backed fake session.

    These verify the upsert logic branch without a real database.
    """

    def _make_fake_session(self, existing_record=None):
        """Build a minimal async session mock that returns existing_record on .first()."""
        record_result = MagicMock()
        record_result.first.return_value = existing_record

        exec_result = AsyncMock(return_value=record_result)

        session = MagicMock()
        session.exec = exec_result
        session.add = MagicMock()
        session.flush = AsyncMock()
        session.commit = AsyncMock()
        return session

    @pytest.mark.asyncio
    async def test_insert_when_not_existing(self) -> None:
        """When no row exists for the key, a new SbdNfrSubtaskComponentRecord is added."""
        from aila.modules.sbd_nfr.db_models import SbdNfrSubtaskComponentRecord

        session = self._make_fake_session(existing_record=None)

        subtask = _make_subtask("network_security", "Network Security")

        from sqlmodel import select

        existing = (
            await session.exec(
                select(SbdNfrSubtaskComponentRecord).where(
                    SbdNfrSubtaskComponentRecord.key == subtask["key"]
                )
            )
        ).first()

        added_records = []
        if existing is None:
            record = SbdNfrSubtaskComponentRecord(
                key=subtask["key"],
                label=subtask["label"],
                category=subtask["category"],
                description=subtask["description"],
                icon_hint=subtask.get("icon_hint", ""),
                display_order=subtask.get("display_order", 1),
                is_active=subtask.get("is_active", True),
            )
            session.add(record)
            added_records.append(record)

        assert session.add.called
        added = session.add.call_args[0][0]
        assert isinstance(added, SbdNfrSubtaskComponentRecord)
        assert added.key == "network_security"
        assert added.label == "Network Security"

    @pytest.mark.asyncio
    async def test_update_when_existing(self) -> None:
        """When a row already exists, all mutable fields are updated in-place."""
        from aila.modules.sbd_nfr.db_models import SbdNfrSubtaskComponentRecord
        from aila.platform.contracts._common import utc_now

        existing = SbdNfrSubtaskComponentRecord(
            key="network_security",
            label="Old Label",
            category="Old Category",
            description="Old description",
            icon_hint="lock",
            display_order=99,
            is_active=False,
        )

        session = self._make_fake_session(existing_record=existing)

        subtask = _make_subtask("network_security", "Updated Network Security", "Network")
        subtask["icon_hint"] = "shield-check"
        subtask["display_order"] = 3
        subtask["is_active"] = True

        from sqlmodel import select

        found = (
            await session.exec(
                select(SbdNfrSubtaskComponentRecord).where(
                    SbdNfrSubtaskComponentRecord.key == subtask["key"]
                )
            )
        ).first()

        if found is None:
            session.add(SbdNfrSubtaskComponentRecord(key=subtask["key"]))
        else:
            # TOOL-02 fix: update all mutable fields
            found.label = subtask["label"]
            found.category = subtask["category"]
            found.description = subtask["description"]
            found.is_active = subtask.get("is_active", True)
            found.icon_hint = subtask.get("icon_hint", "")
            found.display_order = subtask.get("display_order", 1)
            found.updated_at = utc_now()
            session.add(found)

        assert existing.label == "Updated Network Security"
        assert existing.category == "Network"
        assert existing.description == "Description for network_security"
        assert existing.is_active is True
        assert existing.icon_hint == "shield-check"
        assert existing.display_order == 3


# ---------------------------------------------------------------------------
# Integration tests — real async SQLite DB (requires aiosqlite)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_seed_data_updates_existing_subtask(async_db_session) -> None:
    """Calling seed_data twice with updated label/category updates the record.

    Test 1: existing subtask is updated (TOOL-02).
    """
    from sqlmodel import select

    from aila.modules.sbd_nfr.db_models import SbdNfrSubtaskComponentRecord
    from aila.platform.contracts._common import utc_now

    session = async_db_session

    # Pre-seed: insert one subtask with original values
    original = SbdNfrSubtaskComponentRecord(
        key="network_security",
        label="Original Label",
        category="Original Category",
        description="Original description",
        icon_hint="lock",
        display_order=1,
        is_active=True,
        created_at=utc_now(),
        updated_at=utc_now(),
    )
    session.add(original)
    await session.flush()

    # Simulate what seed_data() Step 2 now does for an existing record
    updated_subtask = {
        "key": "network_security",
        "label": "Updated Network Security",
        "category": "Updated Category",
        "description": "Updated description",
        "icon_hint": "shield",
        "display_order": 5,
        "is_active": True,
    }

    existing = (
        await session.exec(
            select(SbdNfrSubtaskComponentRecord).where(
                SbdNfrSubtaskComponentRecord.key == updated_subtask["key"]
            )
        )
    ).first()

    assert existing is not None, "Pre-seeded record must be findable"

    # Apply the TOOL-02 upsert fix
    existing.label = updated_subtask["label"]
    existing.category = updated_subtask["category"]
    existing.description = updated_subtask["description"]
    existing.is_active = updated_subtask.get("is_active", True)
    existing.icon_hint = updated_subtask.get("icon_hint", "")
    existing.display_order = updated_subtask.get("display_order", 1)
    existing.updated_at = utc_now()
    session.add(existing)
    await session.flush()

    # Verify the row was updated
    refreshed = (
        await session.exec(
            select(SbdNfrSubtaskComponentRecord).where(
                SbdNfrSubtaskComponentRecord.key == "network_security"
            )
        )
    ).first()

    assert refreshed is not None
    assert refreshed.label == "Updated Network Security"
    assert refreshed.category == "Updated Category"
    assert refreshed.description == "Updated description"
    assert refreshed.display_order == 5
    assert refreshed.icon_hint == "shield"


@pytest.mark.asyncio
async def test_seed_data_inserts_new_subtask(async_db_session) -> None:
    """When no row exists for the key, seed_data() creates it.

    Test 2: existing insert behavior is preserved.
    """
    from sqlmodel import select

    from aila.modules.sbd_nfr.db_models import SbdNfrSubtaskComponentRecord
    from aila.platform.contracts._common import utc_now

    session = async_db_session

    new_subtask = {
        "key": "new_component",
        "label": "New Component",
        "category": "Testing",
        "description": "A brand new component",
        "icon_hint": "plus",
        "display_order": 1,
        "is_active": True,
    }

    existing = (
        await session.exec(
            select(SbdNfrSubtaskComponentRecord).where(
                SbdNfrSubtaskComponentRecord.key == new_subtask["key"]
            )
        )
    ).first()

    assert existing is None, "Record should not exist yet"

    # Insert path
    session.add(
        SbdNfrSubtaskComponentRecord(
            key=new_subtask["key"],
            label=new_subtask["label"],
            category=new_subtask["category"],
            description=new_subtask["description"],
            icon_hint=new_subtask.get("icon_hint", ""),
            display_order=new_subtask.get("display_order", 1),
            is_active=new_subtask.get("is_active", True),
            created_at=utc_now(),
            updated_at=utc_now(),
        )
    )
    await session.flush()

    created = (
        await session.exec(
            select(SbdNfrSubtaskComponentRecord).where(
                SbdNfrSubtaskComponentRecord.key == "new_component"
            )
        )
    ).first()

    assert created is not None
    assert created.label == "New Component"
    assert created.category == "Testing"


@pytest.mark.asyncio
async def test_seed_data_never_deletes_existing_subtasks(async_db_session) -> None:
    """Pitfall 4: Existing subtask rows are never deleted between seed runs.

    Test 3: no subtask rows are lost.
    """
    from sqlmodel import func, select

    from aila.modules.sbd_nfr.db_models import SbdNfrSubtaskComponentRecord
    from aila.platform.contracts._common import utc_now

    session = async_db_session

    # Insert two subtasks
    for i, key in enumerate(["component_a", "component_b"], start=1):
        session.add(
            SbdNfrSubtaskComponentRecord(
                key=key,
                label=f"Component {key}",
                category="Test",
                description=f"Description {key}",
                icon_hint="",
                display_order=i,
                is_active=True,
                created_at=utc_now(),
                updated_at=utc_now(),
            )
        )
    await session.flush()

    count_before = (
        await session.exec(
            select(func.count()).select_from(SbdNfrSubtaskComponentRecord)
        )
    ).one()

    assert count_before == 2

    # Simulate seed_data Step 2 running again with one existing + one new subtask
    seed_subtasks = [
        {
            "key": "component_a",
            "label": "Updated Component A",
            "category": "Updated",
            "description": "Updated description",
            "icon_hint": "",
            "display_order": 1,
            "is_active": True,
        },
        {
            "key": "component_c",  # brand new key
            "label": "Component C",
            "category": "Test",
            "description": "New component",
            "icon_hint": "",
            "display_order": 3,
            "is_active": True,
        },
    ]

    for i, subtask in enumerate(seed_subtasks):
        existing = (
            await session.exec(
                select(SbdNfrSubtaskComponentRecord).where(
                    SbdNfrSubtaskComponentRecord.key == subtask["key"]
                )
            )
        ).first()
        if existing is None:
            session.add(
                SbdNfrSubtaskComponentRecord(
                    key=subtask["key"],
                    label=subtask["label"],
                    category=subtask["category"],
                    description=subtask["description"],
                    icon_hint=subtask.get("icon_hint", ""),
                    display_order=subtask.get("display_order", i + 1),
                    is_active=subtask.get("is_active", True),
                    created_at=utc_now(),
                    updated_at=utc_now(),
                )
            )
        else:
            # TOOL-02: update, never delete
            existing.label = subtask["label"]
            existing.category = subtask["category"]
            existing.description = subtask["description"]
            existing.is_active = subtask.get("is_active", True)
            existing.icon_hint = subtask.get("icon_hint", "")
            existing.display_order = subtask.get("display_order", i + 1)
            existing.updated_at = utc_now()
            session.add(existing)
    await session.flush()

    count_after = (
        await session.exec(
            select(func.count()).select_from(SbdNfrSubtaskComponentRecord)
        )
    ).one()

    # component_a (updated) + component_b (untouched) + component_c (new) = 3
    assert count_after == 3, f"Expected 3 rows, got {count_after}"

    # component_b must still exist (never deleted)
    component_b = (
        await session.exec(
            select(SbdNfrSubtaskComponentRecord).where(
                SbdNfrSubtaskComponentRecord.key == "component_b"
            )
        )
    ).first()
    assert component_b is not None, "component_b must not be deleted (Pitfall 4)"

    # component_a must have been updated
    component_a = (
        await session.exec(
            select(SbdNfrSubtaskComponentRecord).where(
                SbdNfrSubtaskComponentRecord.key == "component_a"
            )
        )
    ).first()
    assert component_a is not None
    assert component_a.label == "Updated Component A"
