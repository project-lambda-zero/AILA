"""KnowledgeBridgeTool -- in-process agent bridge for read-only knowledge retrieval (RFC-12).

The RFC-12 read loop (Phase 1) proactively injects prior knowledge into the
RETRIEVED prompt tier at setup. This bridge is the agentic counterpart: it
exposes ONE read-only tool, ``knowledge.retrieve``, so a reasoning agent can
pull focused prior knowledge on demand mid-turn, the same way it navigates
target code through audit_mcp. Retrieval goes through the adaptive
``retrieve_routed`` path, so every hit is relevance-floored and passes the
sanitize/classify gate before it reaches the agent.

Scope is set SERVER-SIDE: the module tool executor injects the resolved,
workspace-scoped namespace list as ``_namespaces`` in
``_pre_dispatch_correct_args`` before dispatch. The bridge refuses a call
with no injected scope so an agent (or a prompt-injected instruction) can
never widen retrieval beyond its own workspace. No mutating action exists on
this bridge -- the agent surface is read-only by construction.
"""
from __future__ import annotations

from typing import Any

from aila.platform.services.knowledge import KnowledgeService
from aila.platform.tools import Tool

from ._recorder import BridgeRecorder, noop_recorder

__all__ = ["KnowledgeBridgeTool"]

# Relevance floor for the agentic retrieval path (the same floor the Phase 1
# setup resolvers use). Hits below this cosine-blend score never reach the
# agent.
_RETRIEVE_FLOOR: float = 0.3
_RETRIEVE_LIMIT_DEFAULT: int = 8
_RETRIEVE_LIMIT_MAX: int = 20
_HIT_CONTENT_CHARS: int = 600


class KnowledgeBridgeTool(Tool):
    """In-process bridge exposing read-only, workspace-scoped knowledge
    retrieval to the reasoning agent (RFC-12 agentic path)."""

    name = "knowledge_bridge"
    description = (
        "Read-only knowledge retrieval bridge: exposes knowledge.retrieve "
        "over the platform knowledge base, workspace-scoped server-side."
    )

    # The single tool the agent may dispatch. A store/write path is
    # deliberately absent so the agent surface is read-only.
    _READ_TOOL = "retrieve"

    def __init__(self, recorder: BridgeRecorder | None = None) -> None:
        self._recorder: BridgeRecorder = recorder or noop_recorder

    async def list_tool_specs(self) -> list[dict[str, Any]]:
        """Return the one read-only tool spec for the prompt catalog."""
        return [
            {
                "name": self._READ_TOOL,
                "description": (
                    "Retrieve prior knowledge (audit memos, findings, "
                    "strategy notes) from earlier investigations on this "
                    "workspace's similar targets. Read-only; results are "
                    "relevance-floored and sanitize/classify gated. The "
                    "search scope is your own workspace, set automatically."
                ),
                "parameters": [
                    {
                        "name": "query",
                        "type": "string",
                        "required": True,
                        "description": "Natural-language query.",
                    },
                    {
                        "name": "limit",
                        "type": "integer",
                        "required": False,
                        "default": _RETRIEVE_LIMIT_DEFAULT,
                        "description": f"Max hits (1-{_RETRIEVE_LIMIT_MAX}).",
                    },
                    {
                        "name": "route",
                        "type": "string",
                        "required": False,
                        "description": (
                            "Optional route override: 'simple' | 'graph' | "
                            "'stable_core'. Omit to auto-classify."
                        ),
                    },
                ],
            },
        ]

    async def forward(self, action: str, **kwargs: Any) -> dict[str, Any]:
        """Dispatch a knowledge tool call. Only ``retrieve`` is served."""
        async with self._recorder(
            server_id="knowledge", base_url="in-process", action=action,
        ) as ctx:
            result = await self._dispatch(action, kwargs)
            ctx["status"] = result.get("status", "error")
            if result.get("status") == "error":
                ctx["error_excerpt"] = str(result.get("error", ""))[:200]
            return result

    async def _dispatch(self, action: str, kwargs: dict[str, Any]) -> dict[str, Any]:
        if action != self._READ_TOOL:
            return {
                "status": "error",
                "error": (
                    f"knowledge bridge exposes only '{self._READ_TOOL}'; "
                    f"got {action!r}"
                ),
            }
        query = str(kwargs.get("query") or "").strip()
        if not query:
            return {
                "status": "error",
                "error": "knowledge.retrieve requires a non-empty 'query'",
            }
        # Scope is injected server-side by the module executor's
        # _pre_dispatch_correct_args. No injected scope -> refuse rather
        # than run an unscoped (cross-workspace) query.
        namespaces = kwargs.get("_namespaces")
        if not isinstance(namespaces, (list, tuple)) or not namespaces:
            return {
                "status": "error",
                "error": "knowledge scope not resolved for this investigation",
            }
        limit = kwargs.get("limit")
        try:
            limit_int = int(limit) if limit is not None else _RETRIEVE_LIMIT_DEFAULT
        except (TypeError, ValueError):
            limit_int = _RETRIEVE_LIMIT_DEFAULT
        limit_int = max(1, min(limit_int, _RETRIEVE_LIMIT_MAX))
        route = kwargs.get("route")
        route_arg = str(route) if route else None

        routed = await KnowledgeService().retrieve_routed(
            query=query,
            route=route_arg,
            limit=limit_int,
            min_score=_RETRIEVE_FLOOR,
            namespaces=list(namespaces),
        )
        results = [
            {
                "namespace": h.get("namespace", ""),
                "content": (
                    h.get("sanitized_content") or h.get("content") or ""
                )[:_HIT_CONTENT_CHARS],
                "score": round(float(h.get("score", 0.0) or 0.0), 3),
            }
            for h in routed.get("results", [])
        ]
        return {
            "status": "ok",
            "route": routed.get("route"),
            "count": len(results),
            "results": results,
        }
