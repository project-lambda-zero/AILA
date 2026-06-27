"""Named constants for the platform task queue infrastructure.

Centralizes Redis key templates, numeric tuning values, and ARQ configuration
that were previously scattered as magic literals across queue.py, worker.py,
progress.py, and SSE router code.
"""
from __future__ import annotations

__all__ = [
    # Redis key templates
    "ARQ_QUEUE_KEY_TEMPLATE",
    "ARQ_IN_PROGRESS_PREFIX",
    "ARQ_JOB_PREFIX",
    "ARQ_RETRY_PREFIX",
    "ARQ_DEAD_LETTER_KEY_TEMPLATE",
    "TASK_PROGRESS_KEY_TEMPLATE",
    "SCAN_PROGRESS_KEY_TEMPLATE",
    # Numeric tuning
    "HEARTBEAT_INTERVAL_S",
    "REAPER_ZOMBIE_THRESHOLD_S",
    "REAPER_HEARTBEAT_THRESHOLD_S",
    "ARQ_JOB_TIMEOUT_S",
    "ARQ_KEEP_RESULT_S",
    "ARQ_MAX_TRIES",
    "POISON_PILL_THRESHOLD",
    "WORKER_HEARTBEAT_UNHEALTHY_S",
    "XREAD_BLOCK_MS",
    "PROGRESS_STREAM_MAXLEN",
    # Config registry keys
    "CONFIG_NS_PLATFORM",
    "CONFIG_KEY_REDIS_URL",
]

# --- Redis key templates ---------------------------------------------------
ARQ_QUEUE_KEY_TEMPLATE: str = "arq:queue:{track}"
ARQ_IN_PROGRESS_PREFIX: str = "arq:in-progress:"
ARQ_JOB_PREFIX: str = "arq:job:"
ARQ_RETRY_PREFIX: str = "arq:retry:"
ARQ_DEAD_LETTER_KEY_TEMPLATE: str = "arq:dead-letter:{track}"
TASK_PROGRESS_KEY_TEMPLATE: str = "task:{task_id}:progress"
SCAN_PROGRESS_KEY_TEMPLATE: str = "scan:{run_id}:progress"

# --- Numeric tuning (DEFAULTS -- runtime values come from ConfigRegistry) ---
# These are fallbacks when ConfigRegistry is unavailable (e.g. during tests).
# Production reads from PUT /config/platform/{key}.
HEARTBEAT_INTERVAL_S: int = 30
# Reaper thresholds:
# REAPER_ZOMBIE_THRESHOLD_S -- how long a job may run without ANY heartbeat
# before the reaper considers it a zombie. Set to 3300s (55 min) so the
# reaper never kills a job whose ARQ timeout (3600s) has not yet expired.
# REAPER_HEARTBEAT_THRESHOLD_S -- once heartbeat_at is being updated (see
# engine._commit_transition), a job is stale if no heartbeat for this many
# seconds. 86400s = 24 hours gives a wide window over the per-state typical
# advisory batch time. The reaper prefers heartbeat_at when present.
REAPER_ZOMBIE_THRESHOLD_S: int = 3300
REAPER_HEARTBEAT_THRESHOLD_S: int = 86400
ARQ_JOB_TIMEOUT_S: int = 3600      # 1 hour max per task
ARQ_KEEP_RESULT_S: int = 3600      # Keep job result in Redis for 1 hour
ARQ_MAX_TRIES: int = 3
# Phase 178: poison-pill detection. After this many unhandled exceptions in
# a row on the same task, the worker stops retrying and moves the task to
# status=dead_letter plus the arq:dead-letter:{track} sorted set.
POISON_PILL_THRESHOLD: int = 3
# Phase 178: worker is flagged UNHEALTHY (not just "stale") if its ARQ
# heartbeat is older than this threshold, because the frozen worker is
# actively blocking the queue.
WORKER_HEARTBEAT_UNHEALTHY_S: int = 60
XREAD_BLOCK_MS: int = 30000        # 30 seconds -- derived from heartbeat_interval_s * 1000
PROGRESS_STREAM_MAXLEN: int = 1000  # Max events per stream (XADD MAXLEN)

# --- Config registry keys --------------------------------------------------
CONFIG_NS_PLATFORM: str = "platform"
CONFIG_KEY_REDIS_URL: str = "redis_url"
