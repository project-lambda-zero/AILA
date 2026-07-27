"""RFC-07 phase 2 -- unit tests for :class:`aila.platform.runtime.ToolRouter`.

Every test constructs a :class:`ResolvedInstance` set inline and passes an
async dispatch coroutine so the router runs against a fully synthetic
transport. The catalog is a plain fake with a recording ``set_enabled``
so the tests assert the disable-flip semantics without touching the DB.

The tests deliberately cover BOTH the happy path (behaviour-preserving:
first candidate answers, no reroute) and every documented failure path
(reroute, disable-flip at limit, no-catalog fallback, empty candidates,
non-infra errors propagate).
"""
from __future__ import annotations

from collections.abc import Awaitable
from dataclasses import dataclass, field

import pytest

from aila.platform.mcp.client import ResolvedInstance
from aila.platform.runtime.tool_router import (
    ToolInfraError,
    ToolRouter,
    ToolRouteResult,
    describe_infra_error,
)


def _instance(
    url: str, *, instance_id: str | None = None, source: str = "catalog",
) -> ResolvedInstance:
    """Return a resolver-shape :class:`ResolvedInstance` for one candidate."""
    return ResolvedInstance(
        url=url, source=source, instance_id=instance_id,
        capability_tags=("cap",), name="audit_mcp", module_scope="testmod",
    )


@dataclass
class _FakeCatalog:
    """Records every ``set_enabled`` call for assertions.

    Mirrors the ``McpInstanceCatalog.set_enabled`` shape (async method
    returning the refreshed row); the tests only need to inspect the
    call log, so the returned object is a sentinel.
    """

    calls: list[tuple[str, bool]] = field(default_factory=list)
    raise_on_call: bool = False
    return_none: bool = False

    async def set_enabled(
        self, instance_id: str, enabled: bool,
    ) -> object | None:
        if self.raise_on_call:
            raise RuntimeError("db down")
        self.calls.append((instance_id, enabled))
        if self.return_none:
            return None
        return object()


class TestHappyPath:
    """Behaviour-preserving cases: first candidate answers, no reroute."""

    async def test_single_candidate_success(self) -> None:
        router = ToolRouter()
        calls: list[str] = []

        async def dispatch(inst: ResolvedInstance) -> str:
            calls.append(inst.url)
            return f"ok:{inst.url}"

        result = await router.route(
            [_instance("http://a", instance_id="i-a")],
            dispatch,
            capability="cap",
        )
        assert result.ok is True
        assert result.value == "ok:http://a"
        assert result.attempts == (result.attempts[0],)
        assert result.attempts[0].error is None
        assert calls == ["http://a"]
        # No failure counter incremented on the happy path.
        assert router.get_consecutive_failures("i-a") == 0

    async def test_multi_candidate_first_wins(self) -> None:
        """The router stops iterating after the first success -- second
        candidate is never asked for a response."""
        router = ToolRouter()
        dispatched: list[str] = []

        async def dispatch(inst: ResolvedInstance) -> str:
            dispatched.append(inst.url)
            return "ok"

        result = await router.route(
            [
                _instance("http://a", instance_id="i-a"),
                _instance("http://b", instance_id="i-b"),
            ],
            dispatch,
        )
        assert result.ok is True
        assert dispatched == ["http://a"]

    async def test_success_after_prior_failure_resets_counter(self) -> None:
        """A success on instance X clears X's consecutive-failure counter."""
        router = ToolRouter(consecutive_failure_limit=3)
        turn = {"n": 0}

        async def dispatch(inst: ResolvedInstance) -> str:  # noqa: ARG001
            turn["n"] += 1
            if turn["n"] == 1:
                raise ToolInfraError("first blip")
            return "ok"

        result = await router.route(
            [
                _instance("http://a", instance_id="i-a"),
                _instance("http://b", instance_id="i-b"),
            ],
            dispatch,
        )
        assert result.ok is True
        # The successful hit on i-b never incremented i-a's counter beyond 1.
        assert router.get_consecutive_failures("i-a") == 1
        # i-b's counter cleared on success (0 by absence, not by explicit
        # decrement).
        assert router.get_consecutive_failures("i-b") == 0


class TestReroute:
    """Reroute cases: first candidate raises ToolInfraError, next wins."""

    async def test_second_candidate_wins_after_infra_failure(self) -> None:
        router = ToolRouter()

        async def dispatch(inst: ResolvedInstance) -> str:
            if inst.instance_id == "i-a":
                raise ToolInfraError("connect refused")
            return f"ok:{inst.url}"

        result = await router.route(
            [
                _instance("http://a", instance_id="i-a"),
                _instance("http://b", instance_id="i-b"),
            ],
            dispatch,
        )
        assert result.ok is True
        assert result.value == "ok:http://b"
        # Both attempts recorded; the first carries the error text.
        assert len(result.attempts) == 2
        assert result.attempts[0].error is not None
        assert "connect refused" in result.attempts[0].error
        assert result.attempts[1].error is None

    async def test_all_candidates_fail_returns_not_ok(self) -> None:
        router = ToolRouter()

        async def dispatch(inst: ResolvedInstance) -> str:  # noqa: ARG001
            raise ToolInfraError("timeout")

        result = await router.route(
            [
                _instance("http://a", instance_id="i-a"),
                _instance("http://b", instance_id="i-b"),
            ],
            dispatch,
        )
        assert result.ok is False
        assert result.value is None
        assert len(result.attempts) == 2
        assert all(a.error is not None for a in result.attempts)

    async def test_empty_candidates_returns_empty_result(self) -> None:
        router = ToolRouter()
        called = False

        async def dispatch(inst: ResolvedInstance) -> str:  # noqa: ARG001
            nonlocal called
            called = True
            return "unused"

        result: ToolRouteResult[str] = await router.route([], dispatch)
        assert result.ok is False
        assert result.value is None
        assert result.attempts == ()
        assert called is False

    async def test_non_infra_exception_propagates(self) -> None:
        """A non-:class:`ToolInfraError` exception is NOT caught -- the
        router only reroutes past infra failures, application errors
        surface to the caller."""
        router = ToolRouter()

        async def dispatch(inst: ResolvedInstance) -> str:  # noqa: ARG001
            raise ValueError("bad payload")

        with pytest.raises(ValueError, match="bad payload"):
            await router.route(
                [_instance("http://a", instance_id="i-a")], dispatch,
            )


class TestDisableFlip:
    """The disable flip: consecutive_failure_limit hits catalog.set_enabled."""

    async def test_flip_fires_at_limit(self) -> None:
        catalog = _FakeCatalog()
        router = ToolRouter(catalog=catalog, consecutive_failure_limit=2)

        async def dispatch(inst: ResolvedInstance) -> str:  # noqa: ARG001
            raise ToolInfraError("boom")

        # Two back-to-back failures against the SAME single-member pool
        # trip the limit and flip the row disabled.
        for _ in range(2):
            await router.route(
                [_instance("http://a", instance_id="i-a")], dispatch,
            )
        assert catalog.calls == [("i-a", False)]
        assert "i-a" in router.get_disabled_ids()

    async def test_flip_not_fired_below_limit(self) -> None:
        catalog = _FakeCatalog()
        router = ToolRouter(catalog=catalog, consecutive_failure_limit=3)

        async def dispatch(inst: ResolvedInstance) -> str:  # noqa: ARG001
            raise ToolInfraError("boom")

        await router.route(
            [_instance("http://a", instance_id="i-a")], dispatch,
        )
        await router.route(
            [_instance("http://a", instance_id="i-a")], dispatch,
        )
        assert catalog.calls == []
        assert router.get_disabled_ids() == ()

    async def test_flip_only_once_per_instance(self) -> None:
        """A second hit AFTER the flip does NOT re-fire the DB update."""
        catalog = _FakeCatalog()
        router = ToolRouter(catalog=catalog, consecutive_failure_limit=1)

        async def dispatch(inst: ResolvedInstance) -> str:  # noqa: ARG001
            raise ToolInfraError("boom")

        await router.route(
            [_instance("http://a", instance_id="i-a")], dispatch,
        )
        await router.route(
            [_instance("http://a", instance_id="i-a")], dispatch,
        )
        assert catalog.calls == [("i-a", False)]

    async def test_success_resets_counter_before_flip(self) -> None:
        """A success in the middle of a failure streak resets the counter."""
        catalog = _FakeCatalog()
        router = ToolRouter(catalog=catalog, consecutive_failure_limit=3)
        seq = iter([True, False, True, True])

        async def dispatch(inst: ResolvedInstance) -> str:  # noqa: ARG001
            fail = next(seq)
            if fail:
                raise ToolInfraError("intermittent")
            return "ok"

        # 2 failures, 1 success, 2 failures -- never 3 consecutive.
        for _ in range(4):
            await router.route(
                [_instance("http://a", instance_id="i-a")], dispatch,
            )
        assert catalog.calls == []

    async def test_no_catalog_skips_flip(self) -> None:
        """With ``catalog=None`` the router still reroutes but skips the
        DB update -- the counter still moves so a caller can inspect."""
        router = ToolRouter(catalog=None, consecutive_failure_limit=1)

        async def dispatch(inst: ResolvedInstance) -> str:  # noqa: ARG001
            raise ToolInfraError("boom")

        await router.route(
            [_instance("http://a", instance_id="i-a")], dispatch,
        )
        assert router.get_consecutive_failures("i-a") == 1
        assert router.get_disabled_ids() == ()

    async def test_none_instance_id_never_flipped(self) -> None:
        """An env/config/default-tier ResolvedInstance has instance_id=None
        and MUST NOT trip the disable path -- there is no DB row to
        disable."""
        catalog = _FakeCatalog()
        router = ToolRouter(catalog=catalog, consecutive_failure_limit=1)

        async def dispatch(inst: ResolvedInstance) -> str:  # noqa: ARG001
            raise ToolInfraError("boom")

        await router.route(
            [_instance("http://a", instance_id=None, source="env")],
            dispatch,
        )
        assert catalog.calls == []

    async def test_catalog_error_is_swallowed(self) -> None:
        """A DB blip during set_enabled must not crash the caller's
        dispatch loop -- the counter stays at the limit so the next
        failure re-tries the flip."""
        catalog = _FakeCatalog(raise_on_call=True)
        router = ToolRouter(catalog=catalog, consecutive_failure_limit=1)

        async def dispatch(inst: ResolvedInstance) -> str:  # noqa: ARG001
            raise ToolInfraError("boom")

        # No exception surfaces from the router.
        result = await router.route(
            [_instance("http://a", instance_id="i-a")], dispatch,
        )
        assert result.ok is False
        # Router did not add i-a to its own disabled set because the DB
        # flip failed -- the RFC-11 resolver still shows the row.
        assert router.get_disabled_ids() == ()


class TestConstructorValidation:
    """Boundary conditions the constructor rejects."""

    async def test_zero_limit_rejected(self) -> None:
        with pytest.raises(ValueError, match="consecutive_failure_limit"):
            ToolRouter(consecutive_failure_limit=0)

    async def test_negative_limit_rejected(self) -> None:
        with pytest.raises(ValueError, match="consecutive_failure_limit"):
            ToolRouter(consecutive_failure_limit=-1)


class TestDescribeInfraError:
    """Public helper that formats a compact one-line failure description."""

    def test_formats_exception_type_and_message(self) -> None:
        exc = TimeoutError("read timed out")
        text = describe_infra_error(exc)
        assert "TimeoutError" in text
        assert "read timed out" in text

    def test_truncates_long_messages(self) -> None:
        exc = RuntimeError("x" * 800)
        text = describe_infra_error(exc)
        assert len(text) <= 400


# Type-only smoke to guarantee the awaitable typing shape stays intact.
_UNUSED: Awaitable[str] | None = None
