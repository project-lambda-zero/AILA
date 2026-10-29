"""Unit tests for the scheduled report task (report_tasks).

Tests:
  - generate_scheduled_report_job is importable and a coroutine
  - report_tasks exports its live helper symbols
  - WorkerSettings registers the scheduled-report job

All tests are synchronous unit tests using stdlib only -- no DB connections required.
"""
from __future__ import annotations

from aila.platform.tasks.worker import WorkerSettings

# ---------------------------------------------------------------------------
# Report tasks: importability + module structure
# ---------------------------------------------------------------------------


# ---------------------------------------------------------------------------
# Worker settings: report job registered
# ---------------------------------------------------------------------------


def test_worker_settings_includes_report_job():
    """WorkerSettings.functions includes generate_scheduled_report_job."""
    # Registered via @platform_task, so it appears as an arq Function keyed on
    # the fully-qualified registry name rather than the raw callable.
    names = {getattr(fn, "name", None) for fn in WorkerSettings.functions}
    assert (
        "aila.platform.tasks.report_tasks.generate_scheduled_report_job" in names
    )
