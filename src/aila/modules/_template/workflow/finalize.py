"""Template finalize chokepoint (scaffold).

The emit state calls ``finalize_investigation`` after every terminal
completion; the returned :class:`FinalizeResult` steers optional post-
completion work (synthesis, cap-exceeded halt, orphan close). The
template scaffold ships a NO-OP finalizer: it decides no trigger
fires and returns immediately so the emit path is idempotent.

A real module wires the four trigger primitives (all_outcomes,
rejected_quorum, wall_clock_idle_grace, all_terminal_no_outcome) --
see :mod:`aila.modules.vr.workflow.finalize` for the production shape.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

__all__ = [
    "FinalizeResult",
    "FinalizeTrigger",
    "finalize_investigation",
]

_log = logging.getLogger(__name__)


class FinalizeTrigger:
    """Stable trigger-name constants surfaced in operator logs."""

    NO_TRIGGER: str = "no_trigger"
    NOT_RUNNING: str = "not_running"


@dataclass(slots=True, frozen=True)
class FinalizeResult:
    """Structured result of one :func:`finalize_investigation` call."""

    inv_id: str
    trigger: str
    action_taken: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "inv_id": self.inv_id,
            "trigger": self.trigger,
            "action_taken": self.action_taken,
        }


async def finalize_investigation(investigation_id: str) -> FinalizeResult:
    """Template scaffold: no trigger fires by construction.

    Copiers replace this with the module-specific trigger detector
    (mirror :func:`aila.modules.vr.workflow.finalize.finalize_investigation`
    for the four-trigger shape).
    """
    return FinalizeResult(
        inv_id=investigation_id, trigger=FinalizeTrigger.NO_TRIGGER,
    )
