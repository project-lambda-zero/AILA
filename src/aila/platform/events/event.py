from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class PlatformEvent:
    """An immutable platform lifecycle event emitted at each workflow stage transition.

    PlatformEvents flow through ThreadSafeEventEmitter to three built-in
    destinations: audit DB, run history, and progress callback. The frozen
    dataclass prevents mutation after emission, ensuring all destinations
    see an identical, consistent record.

    Consumed by: AuditService (DB), storage.memory.append_run_event (run history),
    and the progress_callback path for CLI/SSE progress display.
    """

    stage: str
    action: str
    key: str
    message: str
    details: dict = field(default_factory=dict)
    run_id: str = ""
    current: int | None = None
    total: int | None = None
    progress_message: str | None = None


__all__ = ["PlatformEvent"]
