"""Central Prometheus metrics definitions for AILA.

Import individual metrics where needed -- all counters, histograms, and gauges
are defined here to avoid scattered metric registration.
"""
from __future__ import annotations

__all__ = [
    "REQUEST_COUNT",
    "REQUEST_LATENCY",
    "ACTIVE_SSE",
    "TASK_QUEUE_DEPTH",
    "LLM_CALL_TOTAL",
    "LLM_CALL_DURATION",
    "LLM_TOKENS_TOTAL",
    "LLM_COST_TOTAL",
    "SILENT_FAILURE_TOTAL",
    "VERIFICATION_TOTAL",
    "CONFIDENCE_DRIFT",
    "DRIFT_ALERTS",
    "APP_INFO",
    "AILA_API_ERROR_ENVELOPE_COUNTER",
    "API_ERROR_ENVELOPE_COUNTER_NAME",
    "TASK_ZOMBIES_REAPED_TOTAL",
    "TASK_DEAD_LETTER_TOTAL",
    "TASK_CHECKPOINT_CORRUPT_TOTAL",
    "TASK_ORPHANED_DEPENDENT_SWEPT_TOTAL",
    "TASK_CHECKPOINT_WRITES_TOTAL",
    "AUTOMATION_TICK_FAILURES_TOTAL",
    "SSE_WRITE_FAILURES_TOTAL",
]

from prometheus_client import Counter, Gauge, Histogram, Info

# ---------------------------------------------------------------------------
# HTTP request metrics (OBS-01)
# ---------------------------------------------------------------------------
REQUEST_COUNT = Counter(
    "aila_http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status_code"],
)
REQUEST_LATENCY = Histogram(
    "aila_http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "endpoint"],
    buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)
ACTIVE_SSE = Gauge(
    "aila_active_sse_connections",
    "Number of active SSE connections",
)
TASK_QUEUE_DEPTH = Gauge(
    "aila_task_queue_depth",
    "Number of tasks in queue by status",
    ["status"],
)

# ---------------------------------------------------------------------------
# LLM call metrics (OBS-02)
# ---------------------------------------------------------------------------
LLM_CALL_TOTAL = Counter(
    "aila_llm_calls_total",
    "Total LLM API calls",
    ["model", "method", "status"],
)
LLM_CALL_DURATION = Histogram(
    "aila_llm_call_duration_seconds",
    "LLM API call latency in seconds",
    ["model", "method"],
    buckets=(0.1, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0, 60.0, 120.0),
)
LLM_TOKENS_TOTAL = Counter(
    "aila_llm_tokens_total",
    "Total tokens consumed",
    ["model", "type"],
)
LLM_COST_TOTAL = Counter(
    "aila_llm_cost_dollars_total",
    "Estimated LLM cost in USD",
    ["model"],
)

# ---------------------------------------------------------------------------
# Silent failure metrics (OBS-06)
# ---------------------------------------------------------------------------
SILENT_FAILURE_TOTAL = Counter(
    "aila_silent_failures_total",
    "Count of silent failure fallbacks",
    ["component"],
)

# ---------------------------------------------------------------------------
# Second-model verification metrics (LLM-SEC-01)
# ---------------------------------------------------------------------------
VERIFICATION_TOTAL = Counter(
    "aila_verification_total",
    "Second-model verification attempts",
    ["task_type", "disposition"],
)

# ---------------------------------------------------------------------------
# Confidence drift metrics (LLM-SEC-04)
# ---------------------------------------------------------------------------
CONFIDENCE_DRIFT = Gauge(
    "aila_confidence_drift_score",
    "Confidence standard deviation for drift detection",
    ["target", "task_type"],
)
DRIFT_ALERTS = Counter(
    "aila_confidence_drift_alerts_total",
    "Confidence drift alerts fired",
    ["target", "task_type"],
)

# ---------------------------------------------------------------------------
# Application info
# ---------------------------------------------------------------------------
APP_INFO = Info("aila", "AILA platform metadata")

# ---------------------------------------------------------------------------
# API error envelope counter (Phase 176a, D-25)
# ---------------------------------------------------------------------------
# Labels locked per D-25: (code, status, module).
#   - code   -- the ErrorEnvelope.code (e.g. "MISSING_API_KEY", "INTERNAL_ERROR").
#   - status -- the HTTP status code as a string (e.g. "503", "422", "500").
#   - module -- the originating aila.* module bucket (e.g. "vulnerability",
#              "platform", "api"). Derived via _derive_module_label in handlers.
# Name "aila_api_error_total" verified free by preflight BE-C (no collision with
# any existing counter in src/aila/api/metrics.py as of 2026-04-12).
API_ERROR_ENVELOPE_COUNTER_NAME = "aila_api_error_total"
AILA_API_ERROR_ENVELOPE_COUNTER = Counter(
    API_ERROR_ENVELOPE_COUNTER_NAME,
    "Count of API error envelopes emitted, labeled by code, HTTP status, and source module",
    labelnames=("code", "status", "module"),
)

# ---------------------------------------------------------------------------
# Task queue failsafe metrics (Phase 178)
# ---------------------------------------------------------------------------
# Reaper outcomes: heartbeat_timeout means the DB record went stale;
# orphaned_arq_lock means an arq:in-progress:* lock outlived its DB record.
TASK_ZOMBIES_REAPED_TOTAL = Counter(
    "aila_task_zombies_reaped_total",
    "Number of zombie tasks reconciled by the reaper",
    labelnames=("reason",),
)
# Poison-pill outcomes: labelled by the Python exception class that tripped
# the threshold so operators can spot the dominant failure mode at a glance.
TASK_DEAD_LETTER_TOTAL = Counter(
    "aila_task_dead_letter_total",
    "Number of tasks moved to the dead-letter queue after repeated failures",
    labelnames=("exception_class",),
)
# Phase 178b: corrupt checkpoint recovery. Incremented when execute_task_job
# finds malformed JSON in TaskRecord.checkpoint_json and falls back to a
# fresh start instead of crashing. Labelled by stage hint so operators can
# trace which writer produced the bad payload.
TASK_CHECKPOINT_CORRUPT_TOTAL = Counter(
    "aila_task_checkpoint_corrupt_total",
    "Number of tasks that hit a corrupt checkpoint_json on resume",
    labelnames=("module",),
)
# Phase 178b: orphan dependent sweeper outcomes.
# outcome="enqueued" means a WAITING task whose parents all reached DONE was
# promoted to QUEUED; outcome="failed" means at least one parent was terminal
# non-DONE so the child could never run and was marked FAILED.
TASK_ORPHANED_DEPENDENT_SWEPT_TOTAL = Counter(
    "aila_task_orphaned_dependent_swept_total",
    "Number of WAITING tasks reconciled after their parents terminated",
    labelnames=("outcome",),
)
# Automation tick supervisor failures (#46), labelled by the exception type a
# supervised tick raised, so a persistently broken schedule row surfaces as a
# dominant label instead of a silent halt.
AUTOMATION_TICK_FAILURES_TOTAL = Counter(
    "aila_automation_tick_failures_total",
    "Automation tick loop failures, labelled by exception class",
    ["exception"],
)

# Phase 178b: checkpoint write volume. Useful for spotting stuck stages and
# confirms that in-flight tasks are actually persisting progress.
TASK_CHECKPOINT_WRITES_TOTAL = Counter(
    "aila_task_checkpoint_writes_total",
    "Number of successful checkpoint writes",
    labelnames=("module",),
)

# ---------------------------------------------------------------------------
# SSE progress write failure counter (RFC-07 first increment)
# ---------------------------------------------------------------------------
# Increments each time an SSE / progress-stream write is swallowed by a
# fail-safe except clause on the emitter or workflow-transition path.
# The swallow is deliberate (a progress-write failure must not kill the
# owning turn) but was previously silent; the counter surfaces the drop
# to operators without flipping the fail-safe posture.
# Labels:
#   source -- "emitter" for aila.platform.events.emitter destinations;
#             "workflow_log" for aila.platform.workflows.log XADD writes.
SSE_WRITE_FAILURES_TOTAL = Counter(
    "aila_sse_write_failures_total",
    "SSE / progress-stream write failures swallowed by fail-safe handlers",
    labelnames=("source",),
)
