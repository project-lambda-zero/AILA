"""Default backoff function for workflow retries.

Per CONTEXT D-40: exponential backoff with jitter, capped at 60 seconds.
The cap prevents multi-hour defers that would exceed ARQ's `job_timeout`.

Handlers may override via ``StateSpec.backoff`` (a ``Callable[[int], float]``).
"""
from __future__ import annotations

import random

_MAX_BACKOFF_S: float = 60.0


def default_backoff(retries: int) -> float:
    """Return a defer-seconds value for the given retry count.

    Formula: ``min((2 ** retries) + random.uniform(0, 1), 60.0)``.

    - ``retries=0`` returns a value in ``[1.0, 2.0)``.
    - ``retries=5`` returns a value in ``[32.0, 33.0)``.
    - ``retries>=6`` saturates at the 60.0 cap (D-40).

    Negative values are clamped to ``retries=0`` semantics so callers cannot
    accidentally request a zero/negative defer.
    """
    effective = max(retries, 0)
    # 2 ** effective can overflow for large effective; clamp first.
    if effective >= 6:  # 2**6 = 64 already exceeds cap
        return _MAX_BACKOFF_S
    return min(float(2 ** effective) + random.uniform(0.0, 1.0), _MAX_BACKOFF_S)
