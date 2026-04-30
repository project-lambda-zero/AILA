"""Tool key constants for the hello_world module.

Tool keys are stable identifiers. Do not change a key after it has been
registered -- callers in capabilities.py and required_tools() use these
strings and must stay in sync.
"""
from __future__ import annotations

HELLO_WORLD_GREET_TOOL = "hello_world.greet"

__all__ = ["HELLO_WORLD_GREET_TOOL"]
