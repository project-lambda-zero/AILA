"""Template outcome kind enum -- copy-me scaffold.

The template ships a MINIMAL outcome shape: one kind, ``ASSESSMENT_REPORT``,
which is terminal-no-downstream. A real module extends this enum with
its module-specific outcome kinds and adds dispatch handlers for each
new kind in ``agents/outcome_dispatcher.py``.
"""
from __future__ import annotations

from enum import StrEnum

__all__ = ["TemplateOutcomeKind"]


class TemplateOutcomeKind(StrEnum):
    """Outcome kinds emitted by the template investigation engine.

    Extend with module-specific kinds. Each new kind MUST have a
    matching branch in ``TemplateOutcomeDispatcher._handle_kind``.
    """

    ASSESSMENT_REPORT = "assessment_report"
