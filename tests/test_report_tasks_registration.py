"""Unit tests for the scheduled report task (report_tasks).

Tests:
  - generate_scheduled_report_job is importable and a coroutine
  - report_tasks exports its live helper symbols
  - WorkerSettings registers the scheduled-report job

All tests are synchronous unit tests using stdlib only -- no DB connections required.
"""
from __future__ import annotations

import inspect

import aila.platform.tasks.report_tasks as report_tasks_mod
from aila.platform.tasks.report_tasks import generate_scheduled_report_job
from aila.platform.tasks.worker import WorkerSettings

# ---------------------------------------------------------------------------
# Report tasks: importability + module structure
# ---------------------------------------------------------------------------


def test_generate_scheduled_report_job_importable():
    """generate_scheduled_report_job is importable from report_tasks."""
    assert callable(generate_scheduled_report_job)
    assert inspect.iscoroutinefunction(generate_scheduled_report_job)


def test_report_tasks_module_structure():
    """report_tasks module exports expected symbols and imports cleanly."""
    assert hasattr(report_tasks_mod, "generate_scheduled_report_job")
    assert hasattr(report_tasks_mod, "_send_report_email")
    assert hasattr(report_tasks_mod, "_update_last_run_at")


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
