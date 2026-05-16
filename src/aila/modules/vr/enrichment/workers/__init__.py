"""Enrichment workers — barrel re-export.

The ARQ-wrapped entrypoints live here. Worker functions are thin
wrappers that wire production dependencies (IDA Bridge, audit-mcp
client, SSH service) into the enrichment services and call them.
"""
from __future__ import annotations

from .mitigation_worker import run_mitigation_analysis

__all__ = ["run_mitigation_analysis"]
