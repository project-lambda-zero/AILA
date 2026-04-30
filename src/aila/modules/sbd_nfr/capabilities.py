"""Capability declarations for the SbD NFR module."""

from __future__ import annotations

MODULE_DESCRIPTION = (
    "SbD NFR assessment module — questionnaire-driven security requirements analysis. "
    "Guides requesters through scope selection and NFR compliance questions, "
    "generates the Secure by Design workbook, and produces Jira handoff drafts."
)
MODULE_EXAMPLES: list[str] = ("Start a new SbD NFR assessment",)
MODULE_TOOLS: list[str] = ["module_status"]

__all__ = ["MODULE_DESCRIPTION", "MODULE_EXAMPLES", "MODULE_TOOLS"]
