"""User-extensible specialist-agent registry CRUD + lookup."""
from __future__ import annotations

from aila.platform.services.specialist_registry import (
    SpecialistAgentCreate,
    SpecialistAgentRegistry,
)


async def test_seed_defaults_is_idempotent(test_db) -> None:
    del test_db
    reg = SpecialistAgentRegistry()
    first = await reg.seed_defaults("vr")
    assert first == 7  # snake, jak, kratos, lara, gordon, garrett, ratchet
    again = await reg.seed_defaults("vr")
    assert again == 0  # nothing re-inserted
    names = {s.name for s in await reg.list_by_module("vr")}
    assert names == {"snake", "jak", "kratos", "lara", "gordon", "garrett", "ratchet"}


async def test_resolve_capability_specialist_vs_core(test_db) -> None:
    del test_db
    reg = SpecialistAgentRegistry()
    await reg.seed_defaults("vr")
    # A registered specialist resolves to its capability.
    assert await reg.resolve_capability("vr", "snake") == "binary-audit"
    # A core role (not in the registry) resolves to None -> walks all phases.
    assert await reg.resolve_capability("vr", "halvar") is None


async def test_user_defined_specialist_crud(test_db) -> None:
    del test_db
    reg = SpecialistAgentRegistry()
    created = await reg.upsert(SpecialistAgentCreate(
        module_id="vr", name="kernel", capability="kernel-audit",
        strategy_family="vr.kernel", description="Linux kernel specialist",
    ))
    assert created.name == "kernel"
    assert created.capability == "kernel-audit"
    assert created.strategy_family == "vr.kernel"

    found = await reg.find_by_capability("vr", "kernel-audit")
    assert found is not None
    assert found.name == "kernel"

    # Update in place (upsert on the same module+name).
    updated = await reg.upsert(SpecialistAgentCreate(
        module_id="vr", name="kernel", capability="kernel-audit",
        description="updated", enabled=False,
    ))
    assert updated.enabled is False
    # Disabled specialist no longer resolves.
    assert await reg.resolve_capability("vr", "kernel") is None
    assert await reg.find_by_capability("vr", "kernel-audit") is None

    assert await reg.delete("vr", "kernel") is True
    assert await reg.delete("vr", "kernel") is False


async def test_module_scoping_isolates_specialists(test_db) -> None:
    del test_db
    reg = SpecialistAgentRegistry()
    await reg.seed_defaults("vr")
    await reg.seed_defaults("malware")
    vr_names = {s.name for s in await reg.list_by_module("vr")}
    mw_names = {s.name for s in await reg.list_by_module("malware")}
    assert "vincent" in mw_names
    assert "vincent" not in vr_names  # malware-only specialist
    # Each specialist name resolves to its capability within its own module.
    assert await reg.resolve_capability("vr", "snake") == "binary-audit"
    assert await reg.resolve_capability("malware", "alucard") == "re"
