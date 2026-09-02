"""Tests for ``GET /platform/agents/persona-registry`` (req 31).

The endpoint's IO is exercised through the pure
:func:`aila.api.routers.agents.build_persona_registry` helper: a
fake platform that lists real ``PersonaRouter`` subclasses proves
the introspection path without spinning the whole FastAPI app +
DB fixture. The endpoint itself is registered by
:mod:`aila.api.app` (the ``include_router`` call), so wiring is
proved by an import-time assertion on the router object.
"""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from aila.api.routers.agents import (
    PersonaRegistryModule,
    _module_label_for,
    build_persona_registry,
)
from aila.api.routers.agents import router as agents_router
from aila.modules.malware.agents.persona_router import (
    PersonaRouter as MalwarePersonaRouter,
)
from aila.modules.vr.agents.persona_router import PersonaRouter as VRPersonaRouter


class _FakeModule:
    """Minimal module double: only the two attrs the endpoint reads."""

    def __init__(self, module_id: str, router_cls: type | None) -> None:
        self.module_id = module_id
        self._router_cls = router_cls

    def persona_router(self):
        return self._router_cls


class _PersonaLessModule:
    """A module WITHOUT a ``persona_router`` method (forensics shape).

    Endpoint MUST list this module with ``personas: []`` via the
    ``hasattr`` guard rather than crashing.
    """

    def __init__(self, module_id: str) -> None:
        self.module_id = module_id


def _fake_platform(*modules) -> object:
    return SimpleNamespace(
        runtime=SimpleNamespace(
            module_registry=SimpleNamespace(modules=list(modules)),
        ),
    )


def _entry_by_id(entries: list[PersonaRegistryModule], module_id: str) -> PersonaRegistryModule:
    for entry in entries:
        if entry.module_id == module_id:
            return entry
    raise AssertionError(f"module_id {module_id!r} missing from entries")


def test_router_registered_with_expected_prefix() -> None:
    """The router MUST expose the spec-fixed path so app.include_router
    surfaces ``GET /platform/agents/persona-registry``."""
    assert agents_router.prefix == "/platform/agents"
    routes = {getattr(r, "path", None) for r in agents_router.routes}
    assert "/platform/agents/persona-registry" in routes


def test_vr_module_lists_six_voices_with_researcher_implementer_critic() -> None:
    platform = _fake_platform(_FakeModule("vr", VRPersonaRouter))
    entries = build_persona_registry(platform)

    vr = _entry_by_id(entries, "vr")
    assert vr.module_label == "VR"
    voices = {p.voice for p in vr.personas}
    assert voices == {"halvar", "noor", "renzo", "wei", "maddie", "yuki"}

    allowed_roles = {"researcher", "implementer", "critic"}
    for persona in vr.personas:
        assert persona.role in allowed_roles, (
            f"vr persona {persona.voice!r} role={persona.role!r} "
            f"MUST be one of {allowed_roles}"
        )
        assert persona.task_type_options, (
            f"vr persona {persona.voice!r} task_type_options MUST be non-empty"
        )
        # Every option the UI offers MUST be one the router can emit --
        # includes the default_task_type fallback.
        assert "vulnerability_research.audit" in persona.task_type_options
        assert "vulnerability_research.researcher" in persona.task_type_options
        assert "vulnerability_research.implementer" in persona.task_type_options
        assert "vulnerability_research.critic" in persona.task_type_options


def test_malware_module_lists_six_voices_with_role_none() -> None:
    platform = _fake_platform(_FakeModule("malware", MalwarePersonaRouter))
    entries = build_persona_registry(platform)

    malware = _entry_by_id(entries, "malware")
    assert malware.module_label == "Malware"
    voices = {p.voice for p in malware.personas}
    assert voices == {"halvar", "noor", "renzo", "wei", "maddie", "yuki"}
    for persona in malware.personas:
        # Malware routes per-voice with no role indirection.
        assert persona.role is None, (
            f"malware persona {persona.voice!r} role MUST be None "
            f"(module has empty persona_role_map)"
        )
        assert persona.task_type_options, (
            f"malware persona {persona.voice!r} options MUST be non-empty"
        )
        # Every persona of a module sees the same finite option set.
        assert "malware_analysis.panel" in persona.task_type_options
        assert f"malware_analysis.{persona.voice}" in persona.task_type_options


def test_persona_less_module_lists_with_empty_personas() -> None:
    """forensics / hello_world / _template have no persona_router
    hook -- endpoint MUST include them with personas: []."""
    platform = _fake_platform(_PersonaLessModule("forensics"))
    entries = build_persona_registry(platform)

    forensics = _entry_by_id(entries, "forensics")
    assert forensics.module_label == "Forensics"
    assert forensics.personas == []


def test_persona_router_returning_none_lists_persona_less() -> None:
    """A module whose ``persona_router()`` returns ``None`` (the
    optional protocol default) MUST list with personas: [] rather
    than crashing the endpoint."""
    platform = _fake_platform(_FakeModule("hello_world", None))
    entries = build_persona_registry(platform)

    hello = _entry_by_id(entries, "hello_world")
    assert hello.module_label == "Hello World"
    assert hello.personas == []


def test_none_platform_returns_empty_list() -> None:
    """Endpoint MUST not crash when app.state.platform is not wired."""
    assert build_persona_registry(None) == []


def test_full_registry_shape_matches_contract() -> None:
    """Contract: one entry per registered module, each entry is a
    :class:`PersonaRegistryModule`, personas are
    :class:`PersonaRegistryPersona`. Extra fields on either model
    are rejected (extra='forbid')."""
    platform = _fake_platform(
        _FakeModule("vr", VRPersonaRouter),
        _FakeModule("malware", MalwarePersonaRouter),
        _PersonaLessModule("forensics"),
    )
    entries = build_persona_registry(platform)

    assert [e.module_id for e in entries] == ["vr", "malware", "forensics"]
    for entry in entries:
        # Round-trip validates the response shape the endpoint returns.
        dumped = entry.model_dump()
        assert set(dumped.keys()) == {"module_id", "module_label", "personas"}
        for persona in entry.personas:
            persona_dumped = persona.model_dump()
            assert set(persona_dumped.keys()) == {
                "voice", "role", "task_type_options",
            }


def test_persona_router_raising_lists_persona_less() -> None:
    """A module whose ``persona_router()`` raises (a genuinely broken
    module) MUST NOT tear down the whole registry response -- the
    endpoint degrades that module to persona-less."""

    class _BrokenModule:
        module_id = "broken"

        def persona_router(self):
            raise RuntimeError("persona_router boom")

    platform = _fake_platform(_BrokenModule())
    entries = build_persona_registry(platform)

    broken = _entry_by_id(entries, "broken")
    assert broken.personas == []


@pytest.mark.parametrize(
    ("module_id", "expected"),
    [
        ("vr", "VR"),
        ("malware", "Malware"),
        ("hello_world", "Hello World"),
        ("forensics", "Forensics"),
        ("_template", " Template"),
    ],
)
def test_module_label_derivation(module_id: str, expected: str) -> None:
    assert _module_label_for(module_id) == expected
