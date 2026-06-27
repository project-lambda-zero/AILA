"""Module capability declarations for the template module.

Replace MODULE_DESCRIPTION with a concrete description the routing agent
will use to decide when to dispatch requests to this module. The description
and examples are embedded directly in LLM prompts -- write for LLM consumption.
"""
from __future__ import annotations

MODULE_DESCRIPTION = "Replace this with a concrete module capability description."
MODULE_TOOLS: list[str] = ["replace.with_real_tool_key"]
MODULE_EXAMPLES: list[str] = ["replace this with a real example query"]

__all__ = ["MODULE_DESCRIPTION", "MODULE_EXAMPLES", "MODULE_TOOLS"]
