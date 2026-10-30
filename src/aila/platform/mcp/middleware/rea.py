"""REA (morluto/rea) middleware -- server-side target affinity.

REA is stateful: one active analysis target per MCP session, selected
by ``open_binary(path=...)``; every analysis tool (``list_procedures``,
``analyze_function``, ``get_call_graph`` ...) answers against whichever
target is active. Reopening the same path retains its analysis database
(cheap); opening a different path switches the target (on Windows a
fresh Ghidra import -- REA cannot reuse a project there).

AILA dispatches REA from many concurrent agent branches, and in one
process every bridge shares ONE session (see
:func:`aila.platform.mcp.mcp_session.shared_session`). So the target a
call needs is not something the agent should manage: the module's
tool executor injects ``target_path`` server-side (the investigation's
binary on local disk) and this middleware guarantees the call runs with
that target active.

Affinity protocol (reader/writer on ``session.affinity``):

* A call for the ACTIVE target joins immediately and runs concurrently
  with other calls on it (REA dispatches up to 8 at once).
* A call for a DIFFERENT target waits until in-flight calls drain, then
  switches with ``open_binary`` while holding the condition -- so no
  call ever observes a target switch mid-flight.
* A lost server session (stdio child exit, HTTP session evicted) clears
  ``session.state``; the next call re-opens its target transparently.

Calls without ``target_path`` (``binary_session``, settings, explicit
``open_binary`` / ``close_binary``) pass straight through.
"""
from __future__ import annotations

import os
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aila.platform.mcp.client import McpClient
    from aila.platform.mcp.mcp_session import McpSession
    from aila.platform.mcp.server_specs import ServerSpec

__all__ = ["REA_TARGET_KWARG", "ReaMiddleware"]

# Server-injected kwarg naming the absolute local path of the target the
# call must run against. Never forwarded to REA.
REA_TARGET_KWARG = "target_path"

_STATE_ACTIVE = "active_target"
_STATE_INFLIGHT = "inflight"
# Opening a target can import + auto-analyze it (Ghidra cold start).
_OPEN_ACTIONS = frozenset({"open_binary", "close_binary"})

# Offline file-inspection tools: they parse an explicit local path and
# do NOT need an open analysis target, but their schema requires
# ``path``. The module tool executor injects ``target_path`` (the
# investigation's binary on disk) without the agent knowing the path,
# so the middleware defaults ``path`` from it; an explicit agent-supplied
# ``path`` (a DIFFERENT file) always wins. Everything else is answered
# against the active session target and must not receive a spurious
# ``path`` kwarg (schema validation rejects unrecognized keys).
_PATH_ARG_TOOLS = frozenset({
    "inspect_pe_imports",
    "inspect_native_exports",
    "inspect_byte_entropy",
})


class ReaMiddleware:
    """Pass-through middleware with per-session target affinity."""

    def __init__(self, *, spec: ServerSpec, module_id: str) -> None:
        self.server_id = spec.server_id
        self.tool_name = spec.tool_name
        self.env_var = spec.env_var
        self.config_key = spec.config_key
        self.default_url = spec.default_url
        self.persistent_pool = spec.persistent_pool
        env_timeout = os.environ.get("REA_TIMEOUT")
        self.default_timeout = (
            float(env_timeout) if env_timeout else spec.default_timeout
        )
        self.module_id = module_id

    async def forward(
        self,
        client: McpClient,
        action: str | None,
        kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        """Run ``action`` with ``target_path`` active; list tools on empty."""
        if not action:
            return {"status": "ready", "tools": await self.list_tool_specs(client)}
        payload = {k: v for k, v in kwargs.items() if k != REA_TARGET_KWARG}
        target = kwargs.get(REA_TARGET_KWARG)
        if (
            action in _PATH_ARG_TOOLS
            and isinstance(target, str)
            and target
            and "path" not in payload
        ):
            payload["path"] = target
        if not isinstance(target, str) or not target or action in _OPEN_ACTIONS:
            result = await client.call_tool(action, payload)
            if action in _OPEN_ACTIONS:
                # An explicit open/close changes the active target out of
                # band; forget it so the next affinity call re-opens.
                session = await client.mcp_session()
                session.state.pop(_STATE_ACTIVE, None)
            return result
        session = await client.mcp_session()
        opened = await self._acquire(client, session, target)
        if opened is not None:
            return opened
        try:
            return await client.call_tool(action, payload)
        finally:
            await self._release(session)

    async def _acquire(
        self, client: McpClient, session: McpSession, target: str,
    ) -> dict[str, Any] | None:
        """Make ``target`` active and register one in-flight call.

        Returns ``None`` on success, or the ``open_binary`` error envelope
        (no in-flight slot held) when the target cannot be opened.
        """
        cond = session.affinity
        async with cond:
            await cond.wait_for(
                lambda: session.state.get(_STATE_ACTIVE) == target
                or session.state.get(_STATE_INFLIGHT, 0) == 0,
            )
            if session.state.get(_STATE_ACTIVE) != target:
                opened = await client.call_tool("open_binary", {"path": target})
                if opened.get("status") == "error":
                    session.state.pop(_STATE_ACTIVE, None)
                    cond.notify_all()
                    return opened
                session.state[_STATE_ACTIVE] = target
            session.state[_STATE_INFLIGHT] = session.state.get(_STATE_INFLIGHT, 0) + 1
        return None

    @staticmethod
    async def _release(session: McpSession) -> None:
        cond = session.affinity
        async with cond:
            # ``state`` may have been cleared by a session reset while the
            # call was in flight; never go negative.
            session.state[_STATE_INFLIGHT] = max(
                0, session.state.get(_STATE_INFLIGHT, 0) - 1,
            )
            cond.notify_all()

    async def list_tool_specs(self, client: McpClient) -> list[dict[str, Any]]:
        """Return REA's live ``tools/list`` catalogue, compacted."""
        return await client.list_tool_specs()
