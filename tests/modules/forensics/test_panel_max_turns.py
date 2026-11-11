"""Panel per-task turn cap resolution (#313).

``_read_max_turns`` clamps the persisted ``max_turns_per_task`` to
``[1, FORENSICS_HARD_TURN_CAP]`` and falls back to the schema default when the
registry read fails. The registry is stubbed so no database is needed.
"""
from __future__ import annotations

import pytest

from aila.modules.forensics.config_schema import (
    FORENSICS_DEFAULTS,
    FORENSICS_HARD_TURN_CAP,
)
from aila.modules.forensics.workflow.panel import loop
from aila.platform.exceptions import AILAError


def _stub_get_int(monkeypatch: pytest.MonkeyPatch, value: int) -> None:
    async def _get_int(key: str) -> int:
        assert key == "max_turns_per_task"
        return value

    monkeypatch.setattr(loop._cfg, "get_int", _get_int)


def _stub_get_int_raises(monkeypatch: pytest.MonkeyPatch, exc: Exception) -> None:
    async def _get_int(key: str) -> int:
        raise exc

    monkeypatch.setattr(loop._cfg, "get_int", _get_int)


async def test_in_range_value_is_returned_unchanged(monkeypatch) -> None:
    _stub_get_int(monkeypatch, 7)
    assert await loop._read_max_turns() == 7


async def test_value_at_hard_cap_is_returned_unchanged(monkeypatch) -> None:
    _stub_get_int(monkeypatch, FORENSICS_HARD_TURN_CAP)
    assert await loop._read_max_turns() == FORENSICS_HARD_TURN_CAP


async def test_zero_is_clamped_up_to_one(monkeypatch) -> None:
    _stub_get_int(monkeypatch, 0)
    assert await loop._read_max_turns() == 1


async def test_negative_is_clamped_up_to_one(monkeypatch) -> None:
    _stub_get_int(monkeypatch, -4)
    assert await loop._read_max_turns() == 1


async def test_above_hard_cap_is_clamped_down(monkeypatch) -> None:
    _stub_get_int(monkeypatch, FORENSICS_HARD_TURN_CAP + 500)
    assert await loop._read_max_turns() == FORENSICS_HARD_TURN_CAP


async def test_registry_key_error_falls_back_to_schema_default(monkeypatch) -> None:
    _stub_get_int_raises(monkeypatch, KeyError("max_turns_per_task"))
    assert await loop._read_max_turns() == FORENSICS_DEFAULTS.max_turns_per_task


async def test_registry_value_error_falls_back_to_schema_default(monkeypatch) -> None:
    _stub_get_int_raises(monkeypatch, ValueError("not an int"))
    assert await loop._read_max_turns() == FORENSICS_DEFAULTS.max_turns_per_task


async def test_registry_aila_error_falls_back_to_schema_default(monkeypatch) -> None:
    _stub_get_int_raises(monkeypatch, AILAError("registry unavailable"))
    assert await loop._read_max_turns() == FORENSICS_DEFAULTS.max_turns_per_task
