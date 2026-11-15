"""Forensics panel + sibling-review-quorum spine (#18).

The panel graph runs a forensics investigation as a panel of role
personas (researcher / critic / implementer) that each get their own
branch off the primary investigation. When a branch submits a
terminal outcome, the platform quorum kernel gates it via
sibling review before the outcome dispatches. Mirrors the
ultimate-argument pattern VR and malware implement (RFC-02 / RFC-04).

Panel mode is selected per investigation at the start route. Settlement and
write-up orchestration live in :mod:`.finalize` and :mod:`.writeup`.
"""
from __future__ import annotations

from .definitions import FORENSICS_INVESTIGATE_PANEL_V1
from .task import run_forensics_panel_investigate
from .writeup import run_forensics_panel_writeup

__all__ = [
    "FORENSICS_INVESTIGATE_PANEL_V1",
    "run_forensics_panel_investigate",
    "run_forensics_panel_writeup",
]
