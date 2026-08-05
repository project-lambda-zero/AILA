"""RFC-09 criteria 2 + 4 activation for the forensics free-flow prompt.

Covers the wiring landed in migration 115 + ForensicsModule.seed_prompts +
HonestInvestigator._run_turn:

* :func:`aila.modules.forensics.agents.investigator.seed_prompt_versions`
  registers the assembled free-flow prompt (base + OS hint) into the
  version store under the ``forensics/freeflow/<os>`` key and sets the
  ``production`` alias to the seeded version when no prior alias exists.
* :func:`aila.modules.forensics.agents.investigator._resolve_freeflow_prompt`
  routes through the shared platform pin helper so the first resolve on
  an investigation writes the pin onto ``forensics_investigations.prompt_pins_json``
  and a later production-alias flip does NOT rewrite the running
  investigation's prompt version -- the pin-per-investigation guarantee.

The pin helper (``platform.prompts.pinning.resolve_pinned_prompt``) is
already covered end-to-end by
``tests/platform/agents/test_prompt_pin.py`` against the VR record; this
test proves the wiring holds when the concrete row class is the
forensics ``InvestigationRunRecord`` (which does NOT extend
``InvestigationRecordBase``).
"""
from __future__ import annotations

import json
from uuid import uuid4

import pytest
from sqlmodel import select

from aila.modules.forensics.agents import investigator
from aila.modules.forensics.agents.investigator import (
    _PROMPT_VERSION_STORE,
    _freeflow_prompt_key,
    _resolve_freeflow_prompt,
    seed_prompt_versions,
)
from aila.modules.forensics.db_models import (
    ForensicsProjectRecord,
    InvestigationRunRecord,
)
from aila.platform.prompts import LoadedPrompt
from aila.storage.database import async_session_scope

pytestmark = pytest.mark.usefixtures("test_db")


async def _seed_investigation() -> tuple[str, str]:
    """Insert a project + one CREATED investigation and return (project_id, inv_id)."""
    suffix = uuid4().hex[:8]
    project_id = f"proj-{suffix}"
    inv_id = f"inv-{suffix}"
    async with async_session_scope() as session:
        session.add(ForensicsProjectRecord(
            id=project_id,
            name=f"test-{suffix}",
            system_id=0,
            evidence_directory="/evidence",
            analyzer_os="linux",
        ))
        await session.flush()
        session.add(InvestigationRunRecord(
            id=inv_id,
            project_id=project_id,
            question="what happened",
            status="created",
        ))
        await session.commit()
    return project_id, inv_id


async def _read_pins(inv_id: str) -> dict[str, str]:
    async with async_session_scope() as session:
        row = (await session.exec(
            select(InvestigationRunRecord).where(
                InvestigationRunRecord.id == inv_id,
            )
        )).first()
        assert row is not None
        return json.loads(row.prompt_pins_json or "{}")


# ---------------------------------------------------------------------------
# Seed hook: registers every assembled variant + sets the production alias.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_seed_registers_and_aliases_both_analyzer_os_variants() -> None:
    """seed_prompt_versions MUST register both variants and set production
    aliases pointing at the assembled ``base + hint`` bytes, matching the
    file-fallback path byte-for-byte so a pin never re-wires the resolved
    body onto a different assembly than the code path would produce."""
    seeded = await seed_prompt_versions()
    # Both linux and windows keys had no production alias -> both flipped.
    assert seeded == 2

    for analyzer_os in ("linux", "windows"):
        key = _freeflow_prompt_key(analyzer_os)
        record = await _PROMPT_VERSION_STORE.resolve(key, alias="production")
        assert record is not None, f"no production alias for {key}"

        expected = investigator._load_freeflow_prompt(analyzer_os)
        assert record.body == expected

    # Second call is a no-op (idempotent): the production aliases are
    # already set so no new promotions happen.
    reseed = await seed_prompt_versions()
    assert reseed == 0


# ---------------------------------------------------------------------------
# _resolve_freeflow_prompt: version returned + pin persisted on first turn.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_resolve_returns_version_and_writes_pin_on_first_resolve() -> None:
    """RFC-09 criterion 2: the resolver returns the production version so
    the caller can stamp it onto the correlation scope. RFC-09 criterion 4:
    the first resolve persists the resolved version onto the row's
    ``prompt_pins_json`` so a later alias flip never re-routes this
    investigation's prompt."""
    await seed_prompt_versions()

    key = _freeflow_prompt_key("linux")
    prod = await _PROMPT_VERSION_STORE.resolve(key, alias="production")
    assert prod is not None
    seeded_version = prod.version

    _project_id, inv_id = await _seed_investigation()

    loaded = await _resolve_freeflow_prompt("linux", investigation_id=inv_id)
    assert isinstance(loaded, LoadedPrompt)
    assert loaded.version == seeded_version
    # Body identity: whatever the store resolves must match the file
    # baseline. If seed drift ever changed the assembled body under the
    # same alias, we would catch it here.
    assert loaded.body == investigator._load_freeflow_prompt("linux")

    pins = await _read_pins(inv_id)
    assert pins.get(key) == seeded_version


# ---------------------------------------------------------------------------
# Pin-per-investigation: a production-alias flip does NOT rewrite the row.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_alias_flip_does_not_reroute_running_forensics_investigation() -> None:
    """After the first turn pins v1, an operator flip of ``production`` to
    v2 must not change what a later turn on the SAME investigation
    resolves -- the pin holds."""
    await seed_prompt_versions()
    key = _freeflow_prompt_key("linux")

    _project_id, inv_id = await _seed_investigation()

    first = await _resolve_freeflow_prompt("linux", investigation_id=inv_id)
    v1 = first.version
    assert v1 is not None

    # Operator ships a new prompt body and flips production -> v2.
    v2 = await _PROMPT_VERSION_STORE.register(
        key, "FORENSICS NEW BODY", author="op", notes="test flip",
    )
    assert v2 != v1
    await _PROMPT_VERSION_STORE.set_alias(
        key, "production", v2, actor="op", reason="test flip",
    )

    # Same investigation, next turn: still v1.
    second = await _resolve_freeflow_prompt("linux", investigation_id=inv_id)
    assert second.version == v1
    assert second.body == first.body

    pins = await _read_pins(inv_id)
    assert pins.get(key) == v1


# ---------------------------------------------------------------------------
# Fresh investigation post-flip binds to the newly-promoted version.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_new_investigation_after_alias_flip_pins_new_version() -> None:
    """A brand-new investigation started AFTER an alias flip must pin the
    current production version, not the one an earlier investigation is
    stuck to."""
    await seed_prompt_versions()
    key = _freeflow_prompt_key("linux")

    _proj_a, inv_old = await _seed_investigation()
    old_loaded = await _resolve_freeflow_prompt(
        "linux", investigation_id=inv_old,
    )
    v1 = old_loaded.version
    assert v1 is not None

    v2 = await _PROMPT_VERSION_STORE.register(
        key, "FORENSICS BODY V2", author="op", notes="test cutover",
    )
    await _PROMPT_VERSION_STORE.set_alias(
        key, "production", v2, actor="op", reason="test cutover",
    )

    _proj_b, inv_new = await _seed_investigation()
    new_loaded = await _resolve_freeflow_prompt(
        "linux", investigation_id=inv_new,
    )
    assert new_loaded.version == v2
    assert new_loaded.body == "FORENSICS BODY V2"

    new_pins = await _read_pins(inv_new)
    assert new_pins.get(key) == v2

    # The old investigation is unchanged: still pinned to v1.
    old_pins = await _read_pins(inv_old)
    assert old_pins.get(key) == v1
