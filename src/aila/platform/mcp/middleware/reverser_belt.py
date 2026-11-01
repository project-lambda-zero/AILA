"""reverser-belt-mcp middleware -- target handle affinity + pending poll.

The reverser-belt server (package ``reverser_belt_mcp``, Kuna decompiler
backend) is handle-based: ``open_binary(path=...)`` returns a
``binary_id`` and every analysis tool takes that ``binary_id``. AILA's
modules, by contrast, address a target by its absolute local path
(server-injected as ``target_path`` -- the agent never supplies it). This
middleware is the MCP-layer adapter between the two conventions:

* On any tool that declares ``binary_id``, it ensures the target has been
  opened (``open_binary`` once per path, cached on the session) and
  rewrites the call to carry the resulting ``binary_id``. ``target_path``
  is never forwarded.
* ``open_binary`` itself passes ``path`` straight through; tools that take
  neither a handle nor a path (``worker_status``, ``list_binaries``,
  ``miasm_simplify_expression``, the ``diff_*`` / ``cross_binary_*``
  pair-of-handles tools) forward unchanged.
* The backend queues analysis on a worker and answers ``status: pending``
  (or ``queued`` / ``running``) until it finishes. This middleware
  re-issues the call on a bounded wall-clock budget until it lands
  ``ready`` / ``error`` -- the same poll loop the retired HTTP bridge
  ran, now over native MCP.

Unlike :class:`ReaMiddleware` there is no exclusive single-target lock:
the belt keys everything by ``binary_id`` and serves several open
binaries at once, so distinct targets open concurrently and only a
per-path open is serialized to avoid a duplicate import.
"""
from __future__ import annotations

import asyncio
import logging
import os
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aila.platform.mcp.client import McpClient
    from aila.platform.mcp.server_specs import ServerSpec

__all__ = ["REVERSER_BELT_TARGET_KWARG", "ReverserBeltMiddleware"]

_log = logging.getLogger(__name__)

# Server-injected absolute local path of the target; translated to a
# binary_id here and never forwarded to the server.
REVERSER_BELT_TARGET_KWARG = "target_path"

_STATE_BINARIES = "belt_binaries"   # path -> binary_id
_STATE_OPEN_LOCKS = "belt_open_locks"  # path -> asyncio.Lock
# Tools that must NOT be handle-rewritten (open by path, or take no
# single target handle).
_PASSTHROUGH = frozenset({
    "open_binary", "close_binary", "list_binaries", "worker_status",
    "get_generation", "miasm_simplify_expression",
    "diff_binary", "diff_function", "diff_survey", "cross_binary_similarity",
})
_PENDING_STATES = frozenset({"pending", "queued", "running"})
_READY_STATES = frozenset({"ready", "completed", "ok"})


class ReverserBeltMiddleware:
    """Pass-through middleware with open_binary handle affinity + poll."""

    def __init__(self, *, spec: ServerSpec, module_id: str) -> None:
        self.server_id = spec.server_id
        self.tool_name = spec.tool_name
        self.env_var = spec.env_var
        self.config_key = spec.config_key
        self.default_url = spec.default_url
        self.persistent_pool = spec.persistent_pool
        env_timeout = os.environ.get("REVERSER_BELT_TIMEOUT")
        self.default_timeout = (
            float(env_timeout) if env_timeout else spec.default_timeout
        )
        self.module_id = module_id
        # Wall-clock cap for re-issuing a pending call until the worker
        # finishes; override with REVERSER_BELT_PENDING_POLL_TIMEOUT.
        self._poll_timeout = float(
            os.environ.get("REVERSER_BELT_PENDING_POLL_TIMEOUT", "240"),
        )
        self._poll_interval = float(
            os.environ.get("REVERSER_BELT_PENDING_POLL_INTERVAL", "2"),
        )
        self._handle_tools: frozenset[str] | None = None

    async def forward(
        self,
        client: McpClient,
        action: str | None,
        kwargs: dict[str, Any],
    ) -> dict[str, Any]:
        """Open the target if needed, inject binary_id, poll pending work."""
        if not action:
            return {"status": "ready", "tools": await self.list_tool_specs(client)}
        target = kwargs.pop(REVERSER_BELT_TARGET_KWARG, None)
        payload = {k: v for k, v in kwargs.items() if k != REVERSER_BELT_TARGET_KWARG}

        if action == "open_binary":
            if "path" not in payload and isinstance(target, str) and target:
                payload["path"] = target
            return await self._call_with_poll(client, action, payload)

        if action not in _PASSTHROUGH and await self._accepts_binary_id(client, action):
            if not isinstance(target, str) or not target:
                return {
                    "status": "error",
                    "error": (
                        f"Unreachable: reverser_belt.{action} needs a target "
                        "binary but none was resolved for this call"
                    ),
                }
            binary_id = await self._ensure_open(client, target)
            if isinstance(binary_id, dict):  # open_binary error envelope
                return binary_id
            payload.setdefault("binary_id", binary_id)

        return await self._call_with_poll(client, action, payload)

    async def _accepts_binary_id(self, client: McpClient, action: str) -> bool:
        if self._handle_tools is None:
            specs = await self.list_tool_specs(client)
            self._handle_tools = frozenset(
                s["name"] for s in specs
                if any(p.get("name") == "binary_id" for p in s.get("params", []))
            )
        return action in self._handle_tools

    async def _ensure_open(
        self, client: McpClient, target_path: str,
    ) -> str | dict[str, Any]:
        """Return the binary_id for ``target_path``, opening it once."""
        session = await client.mcp_session()
        binaries: dict[str, str] = session.state.setdefault(_STATE_BINARIES, {})
        existing = binaries.get(target_path)
        if existing is not None:
            return existing
        locks: dict[str, asyncio.Lock] = session.state.setdefault(_STATE_OPEN_LOCKS, {})
        lock = locks.setdefault(target_path, asyncio.Lock())
        async with lock:
            existing = binaries.get(target_path)
            if existing is not None:
                return existing
            opened = await self._call_with_poll(
                client, "open_binary", {"path": target_path},
            )
            if opened.get("status") == "error":
                return opened
            structured = opened.get("_mcp_structured")
            binary_id = opened.get("binary_id")
            if not binary_id and isinstance(structured, dict):
                binary_id = structured.get("binary_id")
            if not isinstance(binary_id, str) or not binary_id:
                return {
                    "status": "error",
                    "error": (
                        f"Unreachable: reverser_belt.open_binary({target_path!r}) "
                        "returned no binary_id"
                    ),
                }
            binaries[target_path] = binary_id
            return binary_id

    async def _call_with_poll(
        self, client: McpClient, action: str, payload: dict[str, Any],
    ) -> dict[str, Any]:
        """One recorded call; re-issue while the worker reports pending."""
        async with client.recorder_context(action) as ctx:
            result = await client.post(action, payload, ctx=ctx)
            status = result.get("status") if isinstance(result, dict) else None
            if status not in _PENDING_STATES or action == "poll_analysis":
                return result
            deadline = asyncio.get_running_loop().time() + self._poll_timeout
            attempt = 0
            while asyncio.get_running_loop().time() < deadline:
                await asyncio.sleep(self._poll_interval)
                attempt += 1
                result = await client.post(action, payload, ctx=ctx)
                status = result.get("status") if isinstance(result, dict) else None
                if status not in _PENDING_STATES:
                    _log.info(
                        "reverser_belt %s: resolved after %d poll(s): %s",
                        action, attempt, status,
                    )
                    return result
            _log.warning(
                "reverser_belt %s: still pending after %.0fs budget; surfacing",
                action, self._poll_timeout,
            )
            ctx["status"] = "pending"
            return result

    async def list_tool_specs(self, client: McpClient) -> list[dict[str, Any]]:
        """Return the belt's live, compacted tool catalogue."""
        return await client.list_tool_specs()
