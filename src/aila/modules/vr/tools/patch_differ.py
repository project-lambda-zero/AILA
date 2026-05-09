"""Binary diff tool — proxies IDA headless MCP diff capabilities.

Compares two binary versions to surface security patches: structural diffs
across whole binaries and pseudocode diffs for individual functions. The
tool is a thin dispatcher that forwards to ``IDABridgeTool``; all heavy
analysis state lives in the MCP server.
"""
from __future__ import annotations

from typing import Any

from aila.platform.tools._common import Tool

from .ida_bridge import IDABridgeTool

__all__ = ["PatchDifferTool"]


class PatchDifferTool(Tool):
    """Multi-action tool for n-day patch analysis via IDA headless MCP."""

    name = "vr.patch_differ"
    description = (
        "Diff two binary versions to identify security patches. Uses IDA "
        "headless MCP. Actions: diff_binaries (structural diff across whole "
        "binaries), diff_function (pseudocode diff for one function), "
        "find_patched_functions (ranked list of changed functions)."
    )
    inputs = {
        "action": {
            "type": "string",
            "description": (
                "diff_binaries | diff_function | find_patched_functions"
            ),
        },
    }
    output_type = "object"
    skip_forward_signature_validation = True

    def __init__(self, ida_bridge: IDABridgeTool) -> None:
        self._ida = ida_bridge

    async def forward(self, action: str | None = None, **kwargs: Any) -> dict:
        """Dispatch to the requested diff action.

        Args:
            action: One of ``diff_binaries``, ``diff_function``,
                ``find_patched_functions``.
            **kwargs: Action-specific parameters forwarded to MCP.

        Returns:
            Result dict from the underlying MCP call (``status`` field is
            ``ready``, ``pending``, or ``error``) — or an aggregated result
            for ``find_patched_functions``.
        """
        if action == "diff_binaries":
            return await self._ida.forward(action="diff_binary", **kwargs)
        if action == "diff_function":
            return await self._ida.forward(action="diff_function", **kwargs)
        if action == "find_patched_functions":
            return await self._find_patched(**kwargs)
        return {
            "status": "error",
            "error": (
                f"Unknown action: {action!r}. Expected diff_binaries, "
                "diff_function, or find_patched_functions."
            ),
        }

    async def _find_patched(
        self,
        binary_id_old: str | None = None,
        binary_id_new: str | None = None,
        limit: int = 20,
        **_extra: Any,
    ) -> dict:
        """Diff two binaries and return ranked changed functions.

        Ranking prioritizes the largest behavioral deltas: complexity
        differences first, then size deltas as a tiebreaker. Added and
        removed functions surface separately so callers can distinguish
        "patched" code paths from new/dropped ones.
        """
        if not binary_id_old or not binary_id_new:
            return {
                "status": "error",
                "error": "binary_id_old and binary_id_new are required.",
            }
        result = await self._ida.forward(
            action="diff_binary",
            binary_id_old=binary_id_old,
            binary_id_new=binary_id_new,
        )
        if result.get("status") != "ready":
            return result
        changed = result.get("changed", []) or []
        ranked = sorted(
            changed,
            key=lambda f: (
                abs(f.get("complexity_diff", 0) or 0),
                abs(f.get("size_diff", 0) or 0),
            ),
            reverse=True,
        )
        return {
            "status": "ready",
            "patched_functions": ranked[: max(1, int(limit))],
            "total_changed": len(ranked),
            "added": result.get("added", []),
            "removed": result.get("removed", []),
        }
