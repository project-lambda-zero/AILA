"""TaskContext -- runtime context injected into every @platform_task body.

Phase 179 (D-04): the platform no longer leaks ARQ's `ctx: dict` shape into
module code. Module tasks receive a frozen ``TaskContext`` with exactly the
fields they need. The ``@platform_task`` wrapper constructs this object from
ARQ's ``ctx['job_id']`` + ``ctx['job_try']`` plus a ``TaskRecord`` lookup for
``user_id`` / ``team_id``.

Frozen + ``slots=True`` so a rogue handler cannot mutate ``job_try`` or the
team scope mid-execution.
"""
from __future__ import annotations

from dataclasses import dataclass

__all__ = ["TaskContext"]


@dataclass(frozen=True, slots=True)
class TaskContext:
    """Runtime context for a single @platform_task attempt.

    Attributes:
        task_id: UUID of the owning ``TaskRecord``. Per Phase 178 D-31 this
            also equals the ARQ ``_job_id``, so the engine ``run_id`` and
            ARQ job id are the same string end-to-end.
        job_try: 1-based retry counter (ARQ's ``ctx['job_try']``). First
            attempt is ``1``, second attempt is ``2``, etc.
        user_id: Owner of the ``TaskRecord`` (used for structlog binding
            and Phase 180 authorization checks).
        team_id: Team scope. ``None`` for admin / system tasks.
    """

    task_id: str
    job_try: int
    user_id: str
    team_id: str | None
