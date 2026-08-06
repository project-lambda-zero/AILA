"""Configurable core panel: 3-role baseline, override, safe fallback."""
from __future__ import annotations

import aila.modules.vr.services.config_helpers as cfg
from aila.modules.vr.contracts.branch import PersonaVoice
from aila.modules.vr.workflow.states.investigation_setup import (
    _core_sibling_personas,
)


async def test_baseline_is_three_role_spine(test_db) -> None:
    del test_db
    # halvar primary (researcher) + these two = the 3-role spine.
    assert await _core_sibling_personas() == (
        PersonaVoice.MADDIE, PersonaVoice.RENZO,
    )


async def test_config_override(test_db, monkeypatch) -> None:
    del test_db

    async def _fake(_key: str) -> str:
        return "halvar,maddie,noor"

    monkeypatch.setattr(cfg, "get_str", _fake)
    assert await _core_sibling_personas() == (
        PersonaVoice.HALVAR, PersonaVoice.MADDIE, PersonaVoice.NOOR,
    )


async def test_none_falls_back_to_baseline(test_db, monkeypatch) -> None:
    del test_db

    async def _none(_key: str) -> str:
        return "None"  # registry.get -> None becomes str "None"

    monkeypatch.setattr(cfg, "get_str", _none)
    assert await _core_sibling_personas() == (
        PersonaVoice.MADDIE, PersonaVoice.RENZO,
    )


async def test_unknown_names_skipped(test_db, monkeypatch) -> None:
    del test_db

    async def _bogus(_key: str) -> str:
        return "maddie, bogus , renzo"

    monkeypatch.setattr(cfg, "get_str", _bogus)
    assert await _core_sibling_personas() == (
        PersonaVoice.MADDIE, PersonaVoice.RENZO,
    )
