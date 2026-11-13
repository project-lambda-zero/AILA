"""Forensics config schema coverage for the panel turn cap (#313).

Schema-level tests assert the declared Pydantic constraints. Registry
tests assert the set/read-back path through ``ConfigRegistry`` against the
shared test DB.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError
from sqlmodel import select

from aila.modules.forensics.config_schema import (
    FORENSICS_DEFAULTS,
    FORENSICS_HARD_TURN_CAP,
    ForensicsConfigSchema,
)
from aila.storage.database import session_scope
from aila.storage.db_models import ConfigEntryRecord
from aila.storage.registry import ConfigRegistry


@pytest.fixture()
def registry(test_db, monkeypatch):
    """Return a registry without host environment overrides."""
    for key in (
        "AILA_FORENSICS_MAX_TURNS_PER_TASK",
        "AILA_FORENSICS_RETRIEVE_MAX_BYTES",
    ):
        monkeypatch.delenv(key, raising=False)
    return ConfigRegistry()


def _stored_row(namespace: str, key: str) -> ConfigEntryRecord:
    with session_scope() as s:
        return s.exec(select(ConfigEntryRecord).where(
            ConfigEntryRecord.namespace == namespace,
            ConfigEntryRecord.key == key,
        )).one()


# ---------------------------------------------------------------------------
# Declared constraints (no DB)
# ---------------------------------------------------------------------------


class TestForensicsConfigSchemaConstraints:

    def test_max_turns_accepts_lower_bound(self):
        assert ForensicsConfigSchema(max_turns_per_task=1).max_turns_per_task == 1

    def test_max_turns_accepts_integer_in_range(self):
        assert ForensicsConfigSchema(max_turns_per_task=12).max_turns_per_task == 12

    def test_max_turns_accepts_upper_bound(self):
        cap = FORENSICS_HARD_TURN_CAP
        assert ForensicsConfigSchema(max_turns_per_task=cap).max_turns_per_task == cap

    def test_max_turns_rejects_above_hard_cap(self):
        with pytest.raises(ValidationError):
            ForensicsConfigSchema(max_turns_per_task=FORENSICS_HARD_TURN_CAP + 1)

    def test_max_turns_rejects_zero(self):
        with pytest.raises(ValidationError):
            ForensicsConfigSchema(max_turns_per_task=0)

    def test_max_turns_rejects_negative(self):
        with pytest.raises(ValidationError):
            ForensicsConfigSchema(max_turns_per_task=-4)

    def test_max_turns_rejects_non_numeric_string(self):
        with pytest.raises(ValidationError):
            ForensicsConfigSchema(max_turns_per_task="many")

    def test_unknown_key_still_rejected(self):
        with pytest.raises(ValidationError):
            ForensicsConfigSchema(max_turns_cap=5)


# ---------------------------------------------------------------------------
# ConfigRegistry set / read-back against the DB
# ---------------------------------------------------------------------------


class TestForensicsConfigRegistry:

    async def test_registration_seeds_max_turns_with_default(self, registry):
        await registry.register("forensics", ForensicsConfigSchema)

        assert await registry.get("forensics", "max_turns_per_task") == FORENSICS_DEFAULTS.max_turns_per_task
        assert _stored_row("forensics", "max_turns_per_task").value_type == "int"

    async def test_set_max_turns_per_task_round_trips_as_int(self, registry):
        await registry.register("forensics", ForensicsConfigSchema)

        await registry.set("forensics", "max_turns_per_task", "5")

        value = await registry.get("forensics", "max_turns_per_task")
        assert value == 5
        assert isinstance(value, int)
        row = _stored_row("forensics", "max_turns_per_task")
        assert row.value == "5"
        assert row.value_type == "int"

    async def test_set_max_turns_per_task_accepts_hard_cap(self, registry):
        await registry.register("forensics", ForensicsConfigSchema)

        await registry.set("forensics", "max_turns_per_task", str(FORENSICS_HARD_TURN_CAP))

        assert await registry.get("forensics", "max_turns_per_task") == FORENSICS_HARD_TURN_CAP

    async def test_set_max_turns_per_task_rejects_above_hard_cap(self, registry):
        await registry.register("forensics", ForensicsConfigSchema)

        with pytest.raises(ValueError):
            await registry.set(
                "forensics", "max_turns_per_task", str(FORENSICS_HARD_TURN_CAP + 1),
            )

        assert await registry.get("forensics", "max_turns_per_task") == FORENSICS_DEFAULTS.max_turns_per_task

    async def test_set_max_turns_per_task_rejects_non_integer(self, registry):
        await registry.register("forensics", ForensicsConfigSchema)

        with pytest.raises(ValueError):
            await registry.set("forensics", "max_turns_per_task", "not_a_number")

        assert await registry.get("forensics", "max_turns_per_task") == FORENSICS_DEFAULTS.max_turns_per_task

    async def test_unrelated_forensics_key_still_round_trips(self, registry):
        await registry.register("forensics", ForensicsConfigSchema)

        await registry.set("forensics", "retrieve_max_bytes", "2048")

        assert await registry.get("forensics", "retrieve_max_bytes") == 2048
