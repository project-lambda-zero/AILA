"""Module capability declarations for the hello_world module.

Minimal capabilities for platform contract smoke testing. The description
and examples are embedded in LLM routing prompts.
"""
from __future__ import annotations

MODULE_DESCRIPTION = "Minimal hello-world module for platform contract smoke testing."
MODULE_TOOLS: list[str] = ["hello_world.greet"]
MODULE_EXAMPLES: list[str] = ["say hello", "run hello world test"]

__all__ = ["MODULE_DESCRIPTION", "MODULE_EXAMPLES", "MODULE_TOOLS"]
