"""Typed payload-kind vocabulary for MCP-adapter responses.

This enum names the structured shapes the MCP-adapter pipeline emits
(``platform/mcp/adapters/*``) so message renderers and the operator UI
can branch on a single discriminator instead of guessing from payload
shape. The vocabulary itself is platform-level: it is consumed by
every module that runs reasoning loops backed by an MCP, not just the
``vr`` module where it originated.

History: previously lived at ``aila.modules.vr.contracts.message.PayloadKind``.
Hoisted here so platform-level adapters can reference it without
violating the platform→modules direction rule. VR re-exports the same
symbol for backward compatibility from ``modules.vr.contracts.message``.
"""
from __future__ import annotations

from enum import StrEnum

__all__ = ["PayloadKind"]


class PayloadKind(StrEnum):
    """The D-44 typed payload kinds. Payload shape is per-kind dict.

    Payload contents are not strictly typed by Pydantic — frontend
    renderers branch on ``payload_kind`` and consume the dict fields
    they need. Add typed Pydantic shapes per kind when a real consumer
    asks for one.
    """

    TEXT = "text"
    TOOL_CALL = "tool_call"
    CODE_POINTER = "code_pointer"
    GRAPH_VIEW = "graph_view"
    TAINT_FLOW = "taint_flow"
    XREF_VIEW = "xref_view"
    PATCH_DIFF = "patch_diff"
    DECOMPILED_FUNCTION = "decompiled_function"
    HYPOTHESIS_UPDATE = "hypothesis_update"
    OUTCOME_PENDING = "outcome_pending"
    OUTCOME_REVIEW = "outcome_review"
