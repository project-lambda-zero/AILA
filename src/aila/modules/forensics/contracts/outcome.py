"""Outcome kinds a forensics panel branch submits."""
from __future__ import annotations

from enum import StrEnum

__all__ = ["ForensicsOutcomeKind"]


class ForensicsOutcomeKind(StrEnum):
    """``outcome_kind`` of a forensics panel outcome row.

    A panel answers one forensic question, so every terminal submit is the
    branch's answer to that question.
    """

    FORENSIC_ANSWER = "forensic_answer"
