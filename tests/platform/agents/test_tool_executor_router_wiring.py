"""RFC-07 wiring -- unit tests for the ToolRouter integration inside
:meth:`ToolExecutorHelpersBase._dispatch_via_router`.

The router-mediated dispatch stays hidden behind a subclass hook
(:meth:`_router_module_scope`); when the hook returns ``None`` the
helper falls straight to the pre-wiring direct dispatch. When it
returns a module id, the helper resolves candidates via the RFC-11
capability registry + :class:`McpInstanceCatalog` and routes each
attempt through the :class:`ToolRouter`. These tests exercise both
sides at the helper level so the base class is proven independently of
any concrete module executor.

The two acceptance-cases the parent task pinned:
  (a) success path returns the bridge result unchanged;
  (b) on a simulated infra failure with two candidates the router
      reroutes to the second and returns its result.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import pytest

from aila.platform.agents.tool_executor import ToolExecutorHelpersBase
from aila.platform.mcp.client import ResolvedInstance
from aila.platform.runtime.tool_router import ToolRouter


class _StubExecutor(ToolExecutorHelpersBase):
    """Minimal helper subclass -- only overrides the router scope hook.

    The base class needs a ``_message_model`` / ``_branch_model`` for
    the persistence helpers, but the router-wiring path never touches
    those, so we leave them unset. Tests inject candidates by
    monkeypatching :meth:`_resolve_router_candidates` directly rather
    than seeding a live capability registry + DB.
    """

    def _router_module_scope(self) -> str | None:
        return "testmod"


@dataclass
class _FakeBridge:
    """Records every ``forward()`` call and returns a scripted reply
    keyed on the URL the router pointed us at.

    ``_resolved`` mirrors the real bridge attribute the router-wiring
    mutates per attempt. The router's dispatch coroutine sets
    ``self._resolved = instance`` before ``forward()`` and restores it
    after, so ``forward`` reads the current URL from ``_resolved`` to
    decide what to return.
    """

    replies: dict[str, dict[str, Any]] = field(default_factory=dict)
    calls: list[tuple[str, str, dict[str, Any]]] = field(default_factory=list)
    _resolved: ResolvedInstance | None = None

    async def forward(self, *, action: str, **kwargs: Any) -> dict[str, Any]:
        url = self._resolved.url if self._resolved is not None else "<unset>"
        self.calls.append((url, action, dict(kwargs)))
        if url in self.replies:
            return self.replies[url]
        return {"status": "ready", "url": url}


def _candidate(url: str, instance_id: str) -> ResolvedInstance:
    return ResolvedInstance(
        url=url,
        source="catalog",
        instance_id=instance_id,
        capability_tags=("cap",),
        name="audit_mcp",
        module_scope="testmod",
    )


class TestHappyPath:
    """The success path MUST return the bridge dict verbatim."""

    @pytest.mark.asyncio
    async def test_single_candidate_returns_bridge_result_unchanged(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        executor = _StubExecutor()
        bridge = _FakeBridge(
            replies={"http://one": {"status": "ready", "payload": "hello"}},
        )
        candidates = [_candidate("http://one", "i-one")]

        async def _resolve(
            server_id: str, module_scope: str,  # noqa: ARG001
        ) -> list[ResolvedInstance]:
            return candidates

        monkeypatch.setattr(executor, "_resolve_router_candidates", _resolve)

        raw = await executor._dispatch_via_router(
            bridge, "audit_mcp", "read_function", {"name": "foo"},
        )

        assert raw == {"status": "ready", "payload": "hello"}
        assert bridge.calls == [
            ("http://one", "read_function", {"name": "foo"}),
        ]
        # Counter is clean; success reset it.
        router = executor._get_tool_router()
        assert router.get_consecutive_failures("i-one") == 0

    @pytest.mark.asyncio
    async def test_disabled_router_scope_bypasses_router(self) -> None:
        """A subclass that does not override _router_module_scope MUST
        take the direct bridge.forward path (pre-wiring behaviour)."""

        class _NoScope(ToolExecutorHelpersBase):
            # Default _router_module_scope returns None.
            pass

        executor = _NoScope()
        bridge = _FakeBridge(replies={"<unset>": {"status": "ready"}})

        raw = await executor._dispatch_via_router(
            bridge, "audit_mcp", "read_function", {},
        )

        assert raw == {"status": "ready"}
        # Router path never touched _resolved.
        assert bridge._resolved is None

    @pytest.mark.asyncio
    async def test_empty_candidates_falls_back_to_direct_forward(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Scope set but catalog empty for the descriptor -- the router
        stays inert and bridge.forward runs directly."""
        executor = _StubExecutor()
        bridge = _FakeBridge(replies={"<unset>": {"status": "ready"}})

        async def _resolve(
            server_id: str, module_scope: str,  # noqa: ARG001
        ) -> list[ResolvedInstance]:
            return []

        monkeypatch.setattr(executor, "_resolve_router_candidates", _resolve)
        raw = await executor._dispatch_via_router(
            bridge, "audit_mcp", "read_function", {},
        )
        assert raw == {"status": "ready"}
        # Direct-forward path -- router never mutated _resolved.
        assert bridge._resolved is None


class TestReroute:
    """The core RFC-07 behaviour: infra failure on instance A reroutes
    to instance B and returns B's response."""

    @pytest.mark.asyncio
    async def test_infra_error_envelope_reroutes_to_second_candidate(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        executor = _StubExecutor()
        bridge = _FakeBridge(
            replies={
                # Instance A dies with a bridge-emitted infra envelope
                # (exactly what audit_mcp / android_mcp / ida_headless
                # return on httpx.ConnectError). The wire-in reclassifies
                # this as a ToolInfraError so the router reroutes.
                "http://a": {
                    "status": "error",
                    "error": "Cannot reach audit-mcp at http://a. ...",
                },
                # Instance B succeeds cleanly.
                "http://b": {"status": "ready", "payload": "from-b"},
            },
        )
        candidates = [
            _candidate("http://a", "i-a"),
            _candidate("http://b", "i-b"),
        ]

        async def _resolve(
            server_id: str, module_scope: str,  # noqa: ARG001
        ) -> list[ResolvedInstance]:
            return candidates

        monkeypatch.setattr(executor, "_resolve_router_candidates", _resolve)

        raw = await executor._dispatch_via_router(
            bridge, "audit_mcp", "read_function", {"name": "foo"},
        )

        # The winning response is instance B's dict verbatim.
        assert raw == {"status": "ready", "payload": "from-b"}
        # Both instances got attempted, in order, with the same args.
        assert [c[0] for c in bridge.calls] == ["http://a", "http://b"]
        # Counter: A failed once, B succeeded (counter reset).
        router = executor._get_tool_router()
        assert router.get_consecutive_failures("i-a") == 1
        assert router.get_consecutive_failures("i-b") == 0

    @pytest.mark.asyncio
    async def test_semantic_error_envelope_does_not_reroute(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """An application error (not one of the infra prefixes) MUST
        pass through unchanged -- the router only routes around
        infrastructure, never around tool semantics."""
        executor = _StubExecutor()
        bridge = _FakeBridge(
            replies={
                "http://a": {
                    "status": "error",
                    "error": "unknown kwarg 'threshold'",  # semantic, not infra
                },
                "http://b": {"status": "ready"},
            },
        )
        candidates = [
            _candidate("http://a", "i-a"),
            _candidate("http://b", "i-b"),
        ]

        async def _resolve(
            server_id: str, module_scope: str,  # noqa: ARG001
        ) -> list[ResolvedInstance]:
            return candidates

        monkeypatch.setattr(executor, "_resolve_router_candidates", _resolve)

        raw = await executor._dispatch_via_router(
            bridge, "audit_mcp", "read_function", {"threshold": 0.5},
        )

        # Semantic error surfaces verbatim; instance B is never called.
        assert raw == {
            "status": "error", "error": "unknown kwarg 'threshold'",
        }
        assert [c[0] for c in bridge.calls] == ["http://a"]
        # Counter stays clean (not an infra failure).
        router = executor._get_tool_router()
        assert router.get_consecutive_failures("i-a") == 0

    @pytest.mark.asyncio
    async def test_all_candidates_infra_fail_returns_synthetic_envelope(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Every enabled instance died -- the wire-in emits a uniform
        ``{status='error', error=...}`` envelope so the rest of
        execute() (status whitelist, breakers) sees the same shape."""
        executor = _StubExecutor()
        bridge = _FakeBridge(
            replies={
                "http://a": {
                    "status": "error", "error": "Cannot reach x at http://a",
                },
                "http://b": {
                    "status": "error", "error": "Timeout (5s) calling read_function.",
                },
            },
        )
        candidates = [
            _candidate("http://a", "i-a"),
            _candidate("http://b", "i-b"),
        ]

        async def _resolve(
            server_id: str, module_scope: str,  # noqa: ARG001
        ) -> list[ResolvedInstance]:
            return candidates

        monkeypatch.setattr(executor, "_resolve_router_candidates", _resolve)

        raw = await executor._dispatch_via_router(
            bridge, "audit_mcp", "read_function", {"name": "foo"},
        )

        assert raw["status"] == "error"
        assert "audit_mcp" in raw["error"]
        assert "Timeout" in raw["error"]  # last attempt error surfaced
        # Both instances got a shot.
        assert [c[0] for c in bridge.calls] == ["http://a", "http://b"]


class TestDefensiveFallback:
    """The router MUST NEVER break a tool call that would otherwise work."""

    @pytest.mark.asyncio
    async def test_candidate_resolver_error_falls_back_to_direct_forward(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        executor = _StubExecutor()
        bridge = _FakeBridge(replies={"<unset>": {"status": "ready"}})

        async def _boom(
            server_id: str, module_scope: str,  # noqa: ARG001
        ) -> list[ResolvedInstance]:
            raise RuntimeError("catalog exploded")

        monkeypatch.setattr(executor, "_resolve_router_candidates", _boom)
        raw = await executor._dispatch_via_router(
            bridge, "audit_mcp", "read_function", {},
        )
        # Direct dispatch answered even though the resolver crashed.
        assert raw == {"status": "ready"}


class TestRouterSingleton:
    """The router is per-executor and reused so failure counters persist."""

    @pytest.mark.asyncio
    async def test_get_tool_router_returns_same_instance(self) -> None:
        executor = _StubExecutor()
        first = executor._get_tool_router()
        second = executor._get_tool_router()
        assert first is second
        assert isinstance(first, ToolRouter)

    @pytest.mark.asyncio
    async def test_router_state_accumulates_across_calls(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        executor = _StubExecutor()
        bridge = _FakeBridge(
            replies={
                "http://a": {
                    "status": "error", "error": "Cannot reach x at http://a",
                },
                "http://b": {"status": "ready"},
            },
        )
        candidates = [
            _candidate("http://a", "i-a"),
            _candidate("http://b", "i-b"),
        ]

        async def _resolve(
            server_id: str, module_scope: str,  # noqa: ARG001
        ) -> list[ResolvedInstance]:
            return candidates

        monkeypatch.setattr(executor, "_resolve_router_candidates", _resolve)
        router = executor._get_tool_router()

        # First call: A fails, B succeeds.
        await executor._dispatch_via_router(
            bridge, "audit_mcp", "read_function", {},
        )
        assert router.get_consecutive_failures("i-a") == 1

        # Second call: A fails again, B succeeds again -- counter climbs.
        await executor._dispatch_via_router(
            bridge, "audit_mcp", "read_function", {},
        )
        assert router.get_consecutive_failures("i-a") == 2
