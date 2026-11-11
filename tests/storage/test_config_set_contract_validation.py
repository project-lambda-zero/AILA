"""ConfigRegistry.set() enforces the full field contract before any write.

Covers pydantic bounds (ge/le/max_length), type casting, the unchanged-value
short-circuit ordering, and valid roundtrip types. Runs against the Postgres
test DB via the storage_db fixture (D-48/D-49: no SQLite).
"""

from __future__ import annotations

import re
from datetime import datetime

import pytest
from pydantic import BaseModel, Field
from sqlmodel import select

from aila.storage.database import async_session_scope
from aila.storage.db_models import ConfigEntryRecord
from aila.storage.registry import ConfigRegistry

NAMESPACE = "contract"


class _ContractSchema(BaseModel):
    turn_cap: int = Field(default=500, ge=10, le=10000)
    coverage_floor: float = Field(default=0.95, ge=0.0, le=1.0)
    branches: int = Field(default=12, ge=1, le=64)
    # Default deliberately below its own bound: register() persists defaults
    # without validating them, so the stored value can be invalid.
    legacy_cap: int = Field(default=5, ge=10)
    enabled: bool = True
    label: str = Field(default="ok", max_length=5)
    plain: str = "x"


async def _stored_row(key: str) -> tuple[str, datetime] | None:
    async with async_session_scope() as session:
        row = (await session.exec(
            select(ConfigEntryRecord).where(
                ConfigEntryRecord.namespace == NAMESPACE,
                ConfigEntryRecord.key == key,
            )
        )).first()
        return None if row is None else (row.value, row.updated_at)


async def _stored_value(key: str) -> str | None:
    row = await _stored_row(key)
    return None if row is None else row[0]


@pytest.fixture()
async def registry(storage_db) -> ConfigRegistry:
    reg = ConfigRegistry()
    await reg.register(NAMESPACE, _ContractSchema)
    return reg


def _default_str(key: str) -> str:
    return str(_ContractSchema.model_fields[key].default)


class TestRejectedOutOfRange:
    """Values outside a bound raise ValueError naming the field and leave the DB untouched."""

    @pytest.mark.parametrize(
        ("key", "value"),
        [
            ("turn_cap", "9"),
            ("turn_cap", "10001"),
            ("branches", "0"),
            ("branches", "65"),
            ("coverage_floor", "1.5"),
            ("coverage_floor", "-0.1"),
            ("label", "toolong"),
        ],
    )
    async def test_out_of_range_raises_and_keeps_stored_value(
        self, registry: ConfigRegistry, key: str, value: str,
    ) -> None:
        with pytest.raises(ValueError, match=re.escape(f"{NAMESPACE}.{key}")):
            await registry.set(NAMESPACE, key, value)
        assert await _stored_value(key) == _default_str(key)


class TestConstraintMessages:
    """The raised message names the violated constraint, not just the field."""

    async def test_ge_bound_named(self, registry: ConfigRegistry) -> None:
        with pytest.raises(ValueError, match="greater than or equal to 10"):
            await registry.set(NAMESPACE, "turn_cap", "9")

    async def test_le_bound_named(self, registry: ConfigRegistry) -> None:
        with pytest.raises(ValueError, match="less than or equal to 64"):
            await registry.set(NAMESPACE, "branches", "65")

    async def test_max_length_named(self, registry: ConfigRegistry) -> None:
        with pytest.raises(ValueError, match="at most 5 characters"):
            await registry.set(NAMESPACE, "label", "toolong")


class TestRejectedBadTypes:
    """Values that cannot be cast to the declared type raise ValueError naming the field."""

    @pytest.mark.parametrize(
        ("key", "value"),
        [
            ("turn_cap", "abc"),
            ("coverage_floor", "abc"),
            ("branches", "1.5"),
            ("enabled", "maybe"),
        ],
    )
    async def test_bad_type_raises_and_keeps_stored_value(
        self, registry: ConfigRegistry, key: str, value: str,
    ) -> None:
        with pytest.raises(ValueError, match=re.escape(f"{NAMESPACE}.{key}")):
            await registry.set(NAMESPACE, key, value)
        assert await _stored_value(key) == _default_str(key)


class TestBoundaryAccepted:
    """Values exactly on an inclusive bound are accepted and round-trip."""

    @pytest.mark.parametrize(
        ("key", "value", "expected"),
        [
            ("turn_cap", "10", 10),
            ("turn_cap", "10000", 10000),
            ("branches", "1", 1),
            ("branches", "64", 64),
            ("coverage_floor", "0.0", 0.0),
            ("coverage_floor", "1.0", 1.0),
            ("label", "12345", "12345"),
        ],
    )
    async def test_boundary_value_accepted(
        self, registry: ConfigRegistry, key: str, value: str, expected: object,
    ) -> None:
        await registry.set(NAMESPACE, key, value)
        assert await registry.get(NAMESPACE, key) == expected


class TestInvalidEqualToStored:
    """An invalid value equal to the stored value is still rejected (no early return)."""

    async def test_invalid_value_matching_stored_raises(self, registry: ConfigRegistry) -> None:
        # The stored legacy_cap is 5 (persisted default), which violates ge=10.
        assert await _stored_value("legacy_cap") == "5"
        with pytest.raises(ValueError, match="greater than or equal to 10"):
            await registry.set(NAMESPACE, "legacy_cap", "5")
        assert await _stored_value("legacy_cap") == "5"


class TestUnchangedValidWrite:
    """A valid value equal to the stored value still skips the write."""

    async def test_unchanged_valid_value_does_not_rewrite_row(self, registry: ConfigRegistry) -> None:
        before = await _stored_row("turn_cap")
        assert before is not None
        await registry.set(NAMESPACE, "turn_cap", "500")
        after = await _stored_row("turn_cap")
        assert after == before


class TestInvalidDifferentFromStored:
    """An invalid value different from the stored value leaves the stored row intact."""

    async def test_invalid_value_does_not_overwrite_stored(self, registry: ConfigRegistry) -> None:
        await registry.set(NAMESPACE, "turn_cap", "300")
        with pytest.raises(ValueError, match="less than or equal to 10000"):
            await registry.set(NAMESPACE, "turn_cap", "10001")
        assert await _stored_value("turn_cap") == "300"
        assert await registry.get(NAMESPACE, "turn_cap") == 300


class TestValidRoundtrip:
    """Valid writes persist and read back as the declared Python type."""

    @pytest.mark.parametrize(
        ("key", "value", "expected"),
        [
            ("turn_cap", "2000", 2000),
            ("coverage_floor", "0.25", 0.25),
            ("enabled", "false", False),
            ("enabled", "yes", True),
            ("label", "abc", "abc"),
            ("plain", "anything at all", "anything at all"),
        ],
    )
    async def test_valid_value_roundtrips_with_declared_type(
        self, registry: ConfigRegistry, key: str, value: str, expected: object,
    ) -> None:
        await registry.set(NAMESPACE, key, value)
        actual = await registry.get(NAMESPACE, key)
        assert actual == expected
        assert type(actual) is type(expected)
