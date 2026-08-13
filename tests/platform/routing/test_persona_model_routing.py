"""Tests for :mod:`aila.platform.routing.persona_model` (issue #151).

Covers:

* Empty map -- :func:`resolve_effective_task_type` returns the base
  task_type unchanged for every persona, byte-identical to the
  pre-#151 call path (behavior-preserving default).
* Populated map -- a mapped persona resolves to its operator-supplied
  model_role; an unmapped persona keeps the base task_type. The turn
  runner's LLM call would then route the mapped persona to a distinct
  base model (the whole point of #151) while leaving siblings alone.
* Live wiring -- the shared turn runner imports and awaits
  :func:`resolve_effective_task_type` on the branch spawn -> LLM
  path so no dead map can accumulate.

The router is exercised directly; no ConfigRegistry / DB is required
because the router accepts an in-memory ``source_map`` for tests. The
same code path runs in production, differing only in map source (the
process-wide singleton loads the map from ConfigRegistry). Live
wiring is proved by grepping the runner source for the seam call
plus the import.
"""
from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from aila.platform.agents import turn_runner as turn_runner_mod
from aila.platform.contracts.enums import PersonaVoice
from aila.platform.routing import (
    PERSONA_MODEL_ROLE_MAP_KEY,
    PersonaModelRouter,
    get_default_persona_model_router,
    reset_default_persona_model_router,
    resolve_effective_task_type,
)


@pytest.fixture(autouse=True)
def _reset_default_router() -> None:
    """Ensure the process-wide singleton does not leak across cases."""
    reset_default_persona_model_router()
    yield
    reset_default_persona_model_router()


class TestEmptyMapBehaviorPreserving:
    """Empty map -> resolve_model_role returns None; task_type unchanged."""

    @pytest.mark.asyncio
    async def test_empty_router_returns_none_for_every_persona(self) -> None:
        router = PersonaModelRouter(source_map={})
        for voice in PersonaVoice:
            assert await router.resolve_model_role(voice) is None

    @pytest.mark.asyncio
    async def test_empty_router_returns_none_for_specialist_string(self) -> None:
        router = PersonaModelRouter(source_map={})
        assert await router.resolve_model_role("variant") is None

    @pytest.mark.asyncio
    async def test_none_persona_returns_none(self) -> None:
        router = PersonaModelRouter(source_map={"halvar": "vr.researcher.alt"})
        # Even with a populated map, a None persona must produce None
        # -- the base task_type applies.
        assert await router.resolve_model_role(None) is None

    @pytest.mark.asyncio
    async def test_effective_task_type_byte_identical_when_empty(self) -> None:
        """The core acceptance: empty map == today's default per persona."""
        router = PersonaModelRouter(source_map={})
        base = "vulnerability_research.researcher"
        # Every core persona keeps the base task_type unchanged.
        for voice in (
            PersonaVoice.HALVAR, PersonaVoice.NOOR,
            PersonaVoice.RENZO, PersonaVoice.WEI,
            PersonaVoice.MADDIE, PersonaVoice.YUKI,
        ):
            resolved = await resolve_effective_task_type(base, voice, router=router)
            assert resolved == base, (
                f"unmapped persona {voice.value!r} MUST return the base "
                f"task_type ({base!r}); got {resolved!r} instead"
            )

    @pytest.mark.asyncio
    async def test_effective_task_type_none_persona_returns_base(self) -> None:
        router = PersonaModelRouter(source_map={})
        resolved = await resolve_effective_task_type(
            "some.base.task_type", None, router=router,
        )
        assert resolved == "some.base.task_type"


class TestPopulatedMapOverride:
    """Populated map -> mapped persona routes to its assigned model_role."""

    @pytest.mark.asyncio
    async def test_mapped_persona_returns_configured_model_role(self) -> None:
        # A test-supplied map is deliberately not brand names -- the
        # abstract routing key (a task_type) is what the LLM/route layer
        # already understands. Operator populates real values in prod.
        router = PersonaModelRouter(source_map={
            "halvar": "vulnerability_research.researcher.alpha",
            "noor":   "vulnerability_research.researcher.beta",
        })
        assert await router.resolve_model_role(PersonaVoice.HALVAR) == (
            "vulnerability_research.researcher.alpha"
        )
        assert await router.resolve_model_role(PersonaVoice.NOOR) == (
            "vulnerability_research.researcher.beta"
        )

    @pytest.mark.asyncio
    async def test_unmapped_persona_returns_none_with_populated_map(self) -> None:
        router = PersonaModelRouter(source_map={
            "halvar": "vulnerability_research.researcher.alpha",
        })
        # maddie is NOT in the map -- override must not apply.
        assert await router.resolve_model_role(PersonaVoice.MADDIE) is None

    @pytest.mark.asyncio
    async def test_effective_task_type_mixed_map(self) -> None:
        """The mechanism acceptance: mapped persona uses override,
        unmapped persona keeps the base task_type."""
        base = "vulnerability_research.researcher"
        router = PersonaModelRouter(source_map={
            "halvar": "vulnerability_research.researcher.alpha",
        })
        # Mapped persona -> the operator's model_role wins.
        halvar_task_type = await resolve_effective_task_type(
            base, PersonaVoice.HALVAR, router=router,
        )
        assert halvar_task_type == "vulnerability_research.researcher.alpha"
        # Unmapped persona -> byte-identical to today.
        noor_task_type = await resolve_effective_task_type(
            base, PersonaVoice.NOOR, router=router,
        )
        assert noor_task_type == base

    @pytest.mark.asyncio
    async def test_string_persona_matches_enum_persona(self) -> None:
        """Branch rows carry the persona as a string; enum + string match."""
        router = PersonaModelRouter(source_map={
            "halvar": "vulnerability_research.researcher.alpha",
        })
        # Same lookup via the raw string form the branch row stores.
        assert await router.resolve_model_role("halvar") == (
            "vulnerability_research.researcher.alpha"
        )
        assert await router.resolve_model_role("HALVAR") == (
            "vulnerability_research.researcher.alpha"
        )


class TestRegistryLoad:
    """Registry-sourced map with a stub registry (no DB)."""

    @pytest.mark.asyncio
    async def test_registry_json_map_parses(self) -> None:
        class _StubRegistry:
            def __init__(self, payload: str) -> None:
                self._payload = payload

            async def get(self, namespace: str, key: str) -> str:
                assert namespace == "platform"
                assert key == PERSONA_MODEL_ROLE_MAP_KEY
                return self._payload

        stub = _StubRegistry(
            '{"halvar": "vulnerability_research.researcher.alpha", '
            '"noor": "vulnerability_research.researcher.beta"}',
        )
        router = PersonaModelRouter(registry=stub)  # type: ignore[arg-type]
        assert await router.resolve_model_role(PersonaVoice.HALVAR) == (
            "vulnerability_research.researcher.alpha"
        )
        assert await router.resolve_model_role(PersonaVoice.NOOR) == (
            "vulnerability_research.researcher.beta"
        )
        assert await router.resolve_model_role(PersonaVoice.MADDIE) is None

    @pytest.mark.asyncio
    async def test_registry_empty_string_is_empty_map(self) -> None:
        class _StubRegistry:
            async def get(self, namespace: str, key: str) -> str:
                return ""
        router = PersonaModelRouter(registry=_StubRegistry())  # type: ignore[arg-type]
        assert await router.resolve_model_role(PersonaVoice.HALVAR) is None

    @pytest.mark.asyncio
    async def test_registry_missing_key_is_empty_map(self) -> None:
        class _StubRegistry:
            async def get(self, namespace: str, key: str) -> None:
                return None
        router = PersonaModelRouter(registry=_StubRegistry())  # type: ignore[arg-type]
        assert await router.resolve_model_role(PersonaVoice.HALVAR) is None

    @pytest.mark.asyncio
    async def test_registry_malformed_json_falls_back_empty(self) -> None:
        class _StubRegistry:
            async def get(self, namespace: str, key: str) -> str:
                return "{not-json"
        router = PersonaModelRouter(registry=_StubRegistry())  # type: ignore[arg-type]
        # Malformed -> empty map, NOT a crash -- an operator typo
        # cannot break the LLM turn.
        assert await router.resolve_model_role(PersonaVoice.HALVAR) is None

    @pytest.mark.asyncio
    async def test_registry_non_object_json_falls_back_empty(self) -> None:
        class _StubRegistry:
            async def get(self, namespace: str, key: str) -> str:
                return '["halvar", "noor"]'  # a list, not an object
        router = PersonaModelRouter(registry=_StubRegistry())  # type: ignore[arg-type]
        assert await router.resolve_model_role(PersonaVoice.HALVAR) is None


class TestDefaultSingleton:
    """The process-wide singleton is used when no router is injected."""

    @pytest.mark.asyncio
    async def test_default_router_used_when_no_router_arg(self) -> None:
        pinned = PersonaModelRouter(source_map={
            "halvar": "vulnerability_research.researcher.alpha",
        })
        reset_default_persona_model_router(pinned)
        # No router= kwarg -> resolve_effective_task_type picks up the
        # process-wide singleton, which is our pinned instance.
        resolved = await resolve_effective_task_type(
            "vulnerability_research.researcher", PersonaVoice.HALVAR,
        )
        assert resolved == "vulnerability_research.researcher.alpha"

    def test_get_default_returns_stable_instance(self) -> None:
        first = get_default_persona_model_router()
        second = get_default_persona_model_router()
        assert first is second


class TestLiveSpawnPathWiring:
    """The seam must call resolve_effective_task_type on the live path.

    Grep-based liveness proof: the shared turn runner both imports the
    resolver and awaits it on the same code path that computes the
    ``task_type`` handed to the reasoning engine. Without both, the
    persona -> model_role map would be dead (issue-#151 anti-pattern:
    a config surface that no live reader consults).
    """

    def test_turn_runner_imports_resolve_effective_task_type(self) -> None:
        source = Path(inspect.getsourcefile(turn_runner_mod)).read_text(
            encoding="utf-8",
        )
        tree = ast.parse(source)
        imported = False
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module == (
                "aila.platform.routing.persona_model"
            ):
                for alias in node.names:
                    if alias.name == "resolve_effective_task_type":
                        imported = True
                        break
        assert imported, (
            "turn_runner MUST import resolve_effective_task_type from "
            "aila.platform.routing.persona_model -- the persona -> "
            "model_role override lives on the branch spawn -> LLM "
            "path in turn_runner.run_turn."
        )

    def test_turn_runner_calls_resolver_between_task_type_and_engine(self) -> None:
        """Structural proof the override sits AFTER _resolve_task_type
        and BEFORE the engine call, so the mapped task_type is what
        reaches _engine.decide_next_turn (and thus the LLM client)."""
        source = Path(inspect.getsourcefile(turn_runner_mod)).read_text(
            encoding="utf-8",
        )
        # Ordering evidence -- three markers must appear in this order
        # in the shared run_turn body:
        #   1. task_type = self._resolve_task_type(...)
        #   2. await resolve_effective_task_type(task_type, ...)
        #   3. self._engine.decide_next_turn(task_type=task_type, ...)
        idx_resolve = source.find("task_type = self._resolve_task_type(")
        idx_override = source.find("await resolve_effective_task_type(")
        idx_engine = source.find("self._engine.decide_next_turn(")
        assert idx_resolve >= 0, "_resolve_task_type call missing"
        assert idx_override > idx_resolve, (
            "resolve_effective_task_type MUST be awaited AFTER "
            "_resolve_task_type has produced the base task_type"
        )
        assert idx_engine > idx_override, (
            "resolve_effective_task_type MUST run BEFORE the engine "
            "call so the mapped task_type reaches the LLM client"
        )
