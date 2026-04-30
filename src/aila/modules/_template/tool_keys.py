"""Tool key constants for the template module.

Tool keys are stable identifiers. Do not change a key after it has been
registered — callers in capabilities.py and required_tools() use these
strings and must stay in sync.
"""
from __future__ import annotations

TEMPLATE_SAMPLE_TOOL = "template.sample_tool"

__all__ = ["TEMPLATE_SAMPLE_TOOL"]
