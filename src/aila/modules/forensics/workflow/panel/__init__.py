"""Forensics panel + sibling-review-quorum spine (#18).

The panel graph runs a forensics investigation as a panel of role
personas (researcher / critic / implementer) that each get their own
branch off the primary investigation. When a branch submits a
terminal outcome, the platform quorum kernel gates it via
sibling review before the outcome dispatches. Mirrors the
ultimate-argument pattern VR and malware implement (RFC-02 / RFC-04).

The pre-existing free-flow / hub / dispatcher graphs stay untouched --
this module ships bound onto its own workflow definition and is opted
in per-investigation by the task entry (see :mod:`.task`).
"""
from __future__ import annotations

from .definitions import FORENSICS_INVESTIGATE_PANEL_V1
from .task import run_forensics_panel_investigate

__all__ = [
    "FORENSICS_INVESTIGATE_PANEL_V1",
    "run_forensics_panel_investigate",
]
