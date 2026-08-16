"""Scan-lifecycle response schemas.

Housed separately from ``tasks.py`` so the ``/scans`` router can evolve
without polluting the generic task-lifecycle envelope. ``TaskActionResponse``
in ``tasks.py`` keys off ``task_id``; ``/scans/*`` callers speak in
``run_id`` terms and the frontend switches its state machine based on
which field is present, so a distinct response model is the honest fit.
"""
from __future__ import annotations

from pydantic import Field

from .common import APIModel

__all__ = ["ScanCancelResponse"]


class ScanCancelResponse(APIModel):
    """Response for ``POST /scans/{run_id}/cancel``.

    Returned with HTTP 202 whether the ARQ job was actively aborted, the
    row was flipped from queued/running to cancelled, or the row was
    already terminal at request time. ``status`` reflects the row's post-
    action state -- ``cancelled`` for a successful transition; the prior
    terminal value (``done``/``failed``/``cancelled``/``dead_letter``)
    for an already-terminal record so the caller sees the truth instead
    of a lie.
    """

    run_id: str = Field(description="TaskRecord UUID / workflow run identifier")
    status: str = Field(description="Task lifecycle status after the cancel attempt")
