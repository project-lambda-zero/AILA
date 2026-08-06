"""RFC-11 Tier C -- IDA headless middleware behaviour port.

Pins the six IDABridgeTool behaviours that the ``IdaMiddleware`` plugin
MUST preserve after the bespoke bridge class collapses onto the generic
:class:`aila.platform.mcp.bridge_tool.McpBridgeTool`:

* IDA auto-name -> ``0x<hex>`` coercion on address kwargs
  (``sub_474FC0`` becomes ``0x474FC0`` before the payload reaches the
  MCP server).
* ``encoding`` value aliasing on the string-family tools (``utf16``
  becomes ``utf16le`` so filters round-trip against the server's own
  label).
* Pending -> ready pending-poll retry loop (the initial ``pending``
  triggers a re-POST that surfaces the follow-up ready payload).
* Dead-worker fail-fast (``exiting_idle`` + stale heartbeat produces
  the structured ``dead_worker_diagnostic`` error rather than a 240s
  poll timeout).
* Per-call dedup cache (identical read-only calls within TTL replay
  the first payload with ``_ida_bridge_dedup: "hit"``).
* Plain-success round-trip unchanged (a ready payload passes through
  the middleware byte-identical).

No live MCP server: the client's transport (``client.post``) is
monkeypatched with an in-memory fake that returns the responses each
test needs and records what the middleware asked for.
"""
from __future__ import annotations

from typing import Any

import pytest

from aila.platform.mcp.bridge_tool import McpBridgeTool
from aila.platform.mcp.client import ResolvedInstance
from aila.platform.mcp.middleware.ida import IdaMiddleware
from aila.platform.mcp.server_specs import SERVER_SPECS

__all__: list[str] = []


# ── shared fake transport helpers ────────────────────────────────────


def _fake_resolved() -> ResolvedInstance:
    """Return a synthetic ResolvedInstance so the client never resolves live."""
    return ResolvedInstance(
        url="http://fake",
        source="default",
        instance_id=None,
        capability_tags=(),
        name="ida_headless",
        module_scope="vr",
    )


def _fresh_bridge() -> McpBridgeTool:
    """Build a middleware + bridge pair with the resolver pinned to fake."""
    mw = IdaMiddleware(
        spec=SERVER_SPECS["ida_headless"], module_id="vr",
    )
    bridge = McpBridgeTool(middleware=mw, module_id="vr", recorder=None)
    bridge._resolved = _fake_resolved()
    return bridge


class _FakePostRecorder:
    """Records every ``client.post`` call and returns queued payloads.

    Payloads are consumed FIFO from ``responses``; when the list runs
    dry the fake raises AssertionError so a test that assumes N calls
    against a queue of N-1 fails loud.
    """

    def __init__(self, responses: list[dict[str, Any]]) -> None:
        self.responses = list(responses)
        self.calls: list[dict[str, Any]] = []

    async def post(
        self,
        action: str,
        payload: dict[str, Any],
        *,
        timeout: float | None = None,
        ctx: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self.calls.append({
            "action": action, "payload": payload, "ctx_present": ctx is not None,
        })
        if not self.responses:
            raise AssertionError(
                f"fake post exhausted (call {len(self.calls)} action={action!r})",
            )
        body = self.responses.pop(0)
        # Mirror the real client's ctx-status accounting so middleware
        # logic that reads ctx (currently just for post-write override
        # of the audit row) sees a plausible starting value.
        if ctx is not None:
            status = body.get("status")
            if status in ("ready", "completed", "ok"):
                ctx["status"] = "ready"
            elif status in ("pending", "queued", "running"):
                ctx["status"] = "pending"
            elif status == "error":
                ctx["status"] = "error"
                err = body.get("error")
                if isinstance(err, str):
                    ctx["error_excerpt"] = err[:400]
            elif status is None:
                ctx["status"] = "ready"
        return body


# ── tests ────────────────────────────────────────────────────────────


class TestIdaMiddleware:
    def test_wrapping_bridge_derives_vr_name(self) -> None:
        """Sanity: the generic bridge exposes the pre-Tier-C tool name."""
        bridge = _fresh_bridge()
        assert bridge.name == "vr.ida_bridge"
        assert bridge.module_id == "vr"
        assert bridge.server_id == "ida_headless"

    @pytest.mark.asyncio
    async def test_autoname_coerced_before_dispatch(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """IDA-style auto-name on an address kwarg becomes 0x<hex>."""
        bridge = _fresh_bridge()
        fake = _FakePostRecorder([{"status": "ready", "tree": []}])
        monkeypatch.setattr(bridge._client, "post", fake.post)

        result = await bridge.forward(
            action="build_call_tree",
            binary_id="b_abc",
            root_address="sub_474FC0",
        )
        assert result == {"status": "ready", "tree": []}
        assert len(fake.calls) == 1
        assert fake.calls[0]["payload"]["root_address"] == "0x474FC0"
        # binary_id passes through untouched.
        assert fake.calls[0]["payload"]["binary_id"] == "b_abc"

    @pytest.mark.asyncio
    async def test_encoding_alias_utf16_to_utf16le(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """``encoding=utf16`` on list_strings normalizes to ``utf16le``."""
        bridge = _fresh_bridge()
        fake = _FakePostRecorder([{"status": "ready", "hits": []}])
        monkeypatch.setattr(bridge._client, "post", fake.post)

        await bridge.forward(
            action="list_strings",
            binary_id="b",
            encoding="utf16",
        )
        assert fake.calls[0]["payload"]["encoding"] == "utf16le"

    @pytest.mark.asyncio
    async def test_pending_poll_returns_ready(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """First response pending, next retry ready -> ready surfaces."""
        bridge = _fresh_bridge()
        fake = _FakePostRecorder([
            # Primary: pending, live worker (heartbeat fresh so
            # dead-worker check does not trip).
            {
                "status": "pending",
                "worker_phase": "processing",
                "heartbeat_age_s": 1,
            },
            # Retry: ready.
            {"status": "ready", "result": "done"},
        ])
        monkeypatch.setattr(bridge._client, "post", fake.post)

        # Zero out the retry sleep so the loop resolves in-line.
        async def _no_sleep(_delay: float) -> None:
            return None
        monkeypatch.setattr(
            "aila.platform.mcp.middleware.ida.asyncio.sleep", _no_sleep,
        )

        result = await bridge.forward(
            action="build_call_tree", binary_id="b", root_address="0x1",
        )
        assert result == {"status": "ready", "result": "done"}
        # Primary POST recorded ctx; retry POST did NOT (single audit
        # row per forward call, per the contract).
        assert len(fake.calls) == 2
        assert fake.calls[0]["ctx_present"] is True
        assert fake.calls[1]["ctx_present"] is False

    @pytest.mark.asyncio
    async def test_dead_worker_short_circuits_with_diagnostic(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """dead-arbiter signature fails fast rather than polling for 240s."""
        bridge = _fresh_bridge()
        fake = _FakePostRecorder([{
            "status": "pending",
            "worker_phase": "exiting_idle",
            "heartbeat_age_s": 75000,
            "binary_id": "b_dead",
            "queue_depth": 3,
        }])
        monkeypatch.setattr(bridge._client, "post", fake.post)

        result = await bridge.forward(
            action="xrefs_to", binary_id="b_dead", address="0x100",
        )
        assert result["status"] == "error"
        assert "IDA worker is not alive" in result["error"]
        assert "restart ida-headless" in result["error"]
        assert result["dead_worker_diagnostic"]["sha"] == "b_dead"
        assert result["dead_worker_diagnostic"]["action"] == "xrefs_to"
        # ONLY the primary call went out; no poll loop.
        assert len(fake.calls) == 1

    @pytest.mark.asyncio
    async def test_dedup_hit_on_second_identical_read_only_call(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """Second identical xrefs_to call replays cache with dedup marker."""
        bridge = _fresh_bridge()
        fake = _FakePostRecorder([
            {"status": "ready", "hits": [{"addr": "0x1"}]},
        ])
        monkeypatch.setattr(bridge._client, "post", fake.post)

        first = await bridge.forward(
            action="xrefs_to", binary_id="b", address="0x100",
        )
        assert first["status"] == "ready"
        assert first.get("_ida_bridge_dedup") is None

        # Second call: hits the cache; fake.post is NOT called (queue
        # exhausted would raise AssertionError otherwise).
        second = await bridge.forward(
            action="xrefs_to", binary_id="b", address="0x100",
        )
        assert second["_ida_bridge_dedup"] == "hit"
        assert second["hits"] == first["hits"]
        assert len(fake.calls) == 1

    @pytest.mark.asyncio
    async def test_plain_success_round_trips_unchanged(
        self, monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """A ready payload passes through the middleware unmodified.

        Uses a non-dedup action so no ``_ida_bridge_dedup`` marker is
        added on later calls -- proves the middleware only mutates
        payloads for the specific policies under test.
        """
        bridge = _fresh_bridge()
        fake = _FakePostRecorder([
            {"status": "ready", "state": "READY", "sha256": "abc123"},
        ])
        monkeypatch.setattr(bridge._client, "post", fake.post)

        result = await bridge.forward(
            action="open_binary", file_path="/tmp/b.exe",
        )
        assert result == {
            "status": "ready", "state": "READY", "sha256": "abc123",
        }
        assert len(fake.calls) == 1
        assert fake.calls[0]["ctx_present"] is True
