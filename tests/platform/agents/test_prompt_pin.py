"""Tests for RFC-09 criterion 4: pin-per-investigation prompt resolution.

The pin makes a live production-alias flip safe: an already-running
investigation keeps the version it first resolved so its evidence trail
does not shift under it. A brand-new investigation gets whatever the
alias points at when its first turn runs.

These tests exercise the shared platform helper
(``platform.prompts.pinning.resolve_pinned_prompt``) through the VR
researcher's ``_load_prompt`` binding. The malware researcher uses the
identical helper with its own table class, so a VR-side test suffices
to cover the shared behavior.

Fail-open is tested by monkeypatching the store's ``resolve`` to raise
one of the whitelisted exception types.
"""
from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

import pytest
from sqlmodel import select

from aila.modules.vr.agents import vuln_researcher
from aila.modules.vr.agents.vuln_researcher import (
    _PROMPT_VERSION_STORE,
    _load_prompt,
    _prompt_key,
)
from aila.modules.vr.contracts.investigation import InvestigationKind
from aila.modules.vr.db_models import (
    VRInvestigationRecord,
    VRTargetRecord,
    VRWorkspaceRecord,
)
from aila.platform.contracts.enums import InvestigationStatus
from aila.platform.prompts import LoadedPrompt
from aila.storage.database import async_session_scope

pytestmark = pytest.mark.usefixtures("test_db")


async def _make_investigation(pins: dict[str, str] | None = None) -> str:
    """Seed workspace + target + investigation and return the investigation id."""
    suffix = uuid4().hex[:8]
    ws_id = f"ws-{suffix}"
    tgt_id = f"tgt-{suffix}"
    inv_id = f"inv-{suffix}"
    async with async_session_scope() as session:
        session.add(VRWorkspaceRecord(id=ws_id, name="ws", slug=ws_id))
        await session.flush()
        session.add(VRTargetRecord(
            id=tgt_id, workspace_id=ws_id,
            display_name="tgt", kind="native_binary",
        ))
        await session.flush()
        session.add(VRInvestigationRecord(
            id=inv_id,
            target_id=tgt_id,
            kind=InvestigationKind.AUDIT.value,
            title="test",
            initial_question="",
            status=InvestigationStatus.CREATED.value,
            strategy_family="vulnerability_research.audit",
            prompt_pins_json=json.dumps(pins) if pins else "{}",
        ))
        await session.commit()
    return inv_id


async def _read_pins(investigation_id: str) -> dict[str, str]:
    async with async_session_scope() as session:
        row = (await session.exec(
            select(VRInvestigationRecord).where(
                VRInvestigationRecord.id == investigation_id,
            )
        )).first()
        assert row is not None
        return json.loads(row.prompt_pins_json or "{}")


@pytest.mark.asyncio
async def test_first_resolve_pins_the_production_version() -> None:
    key = _prompt_key("vulnerability_research.audit")
    v1 = await _PROMPT_VERSION_STORE.register(key, "VERSION ONE BODY")
    await _PROMPT_VERSION_STORE.set_alias(key, "production", v1)

    inv_id = await _make_investigation()

    loaded = await _load_prompt(
        "vulnerability_research.audit",
        investigation_id=inv_id,
    )
    assert isinstance(loaded, LoadedPrompt)
    assert loaded.body == "VERSION ONE BODY"
    assert loaded.version == v1

    pins = await _read_pins(inv_id)
    assert pins.get(key) == v1


@pytest.mark.asyncio
async def test_alias_flip_does_not_reroute_running_investigation() -> None:
    """After the very first resolve pins v1, flipping ``production`` to v2
    must NOT change what a following turn on the SAME investigation
    resolves. That is the whole point of the pin -- a live deploy is
    safe against runs already in flight (RFC-09 criterion 4)."""
    key = _prompt_key("vulnerability_research.audit")
    v1 = await _PROMPT_VERSION_STORE.register(key, "OLD BODY")
    await _PROMPT_VERSION_STORE.set_alias(key, "production", v1)

    inv_id = await _make_investigation()
    first = await _load_prompt(
        "vulnerability_research.audit",
        investigation_id=inv_id,
    )
    assert first.body == "OLD BODY"
    assert first.version == v1

    # Operator ships a new prompt and flips production -> v2.
    v2 = await _PROMPT_VERSION_STORE.register(key, "NEW BODY")
    await _PROMPT_VERSION_STORE.set_alias(
        key, "production", v2, actor="op", reason="test flip",
    )

    # Second turn on the same investigation: still v1.
    second = await _load_prompt(
        "vulnerability_research.audit",
        investigation_id=inv_id,
    )
    assert second.body == "OLD BODY"
    assert second.version == v1

    pins = await _read_pins(inv_id)
    assert pins.get(key) == v1


@pytest.mark.asyncio
async def test_second_investigation_gets_the_new_production_version() -> None:
    """A brand-new investigation created AFTER the alias flip must pin
    against the current production version, not the earlier one."""
    key = _prompt_key("vulnerability_research.audit")
    v1 = await _PROMPT_VERSION_STORE.register(key, "OLD BODY")
    await _PROMPT_VERSION_STORE.set_alias(key, "production", v1)

    old_inv = await _make_investigation()
    old_loaded = await _load_prompt(
        "vulnerability_research.audit",
        investigation_id=old_inv,
    )
    assert old_loaded.version == v1

    v2 = await _PROMPT_VERSION_STORE.register(key, "NEW BODY")
    await _PROMPT_VERSION_STORE.set_alias(
        key, "production", v2, actor="op", reason="cutover",
    )

    new_inv = await _make_investigation()
    new_loaded = await _load_prompt(
        "vulnerability_research.audit",
        investigation_id=new_inv,
    )
    assert new_loaded.body == "NEW BODY"
    assert new_loaded.version == v2

    new_pins = await _read_pins(new_inv)
    assert new_pins.get(key) == v2

    # And the old one is unchanged: pinned to v1 still.
    old_pins = await _read_pins(old_inv)
    assert old_pins.get(key) == v1


@pytest.mark.asyncio
async def test_store_error_falls_back_to_file_registry(monkeypatch) -> None:
    """A store fault (SQLAlchemyError / OSError / RuntimeError) must not
    block a turn: the loader degrades to the file-backed registry and
    returns a LoadedPrompt whose ``version`` is None (nothing was
    resolved from the version store)."""

    async def _boom(*_args: Any, **_kwargs: Any) -> None:
        raise RuntimeError("simulated store outage")

    monkeypatch.setattr(
        vuln_researcher._PROMPT_VERSION_STORE, "resolve", _boom,
    )

    inv_id = await _make_investigation()
    loaded = await _load_prompt(
        "vulnerability_research.audit",
        investigation_id=inv_id,
    )
    assert isinstance(loaded, LoadedPrompt)
    assert loaded.version is None
    # File body ships the canonical audit prompt phrase.
    assert "audit-only investigation" in loaded.body

    # No pin was written because nothing was resolved from the store.
    pins = await _read_pins(inv_id)
    assert pins == {}
