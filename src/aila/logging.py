"""Structured logging foundation for AILA.

Provides configure_logging(), RunIdFilter, human-readable and JSON formatters.
Only stdlib imports — this module is infrastructure used by everything else.

Two output modes are supported:
- Human-readable (default): HH:MM:SS level logger message
- JSON (json_output=True): single-line JSON with ISO 8601 timestamp (Phase 38 DEAD-05
  fix — the previous implementation used a human datefmt for JSON output, producing
  non-sortable timestamps; now uses datetime.utcfromtimestamp + strftime to produce
  unambiguous, sortable, locale-independent timestamps ending in "Z").

A single RunIdFilter instance (_run_id_filter) is shared across all
configure_logging() calls.  It injects the current run_id into every log record
so that structured log consumers can correlate all log lines for a workflow run.
"""

from __future__ import annotations

import json
import logging as _log
import sys
from datetime import datetime

# Note: `import logging as _log` is safe here — this module's fully-qualified
# name is `aila.logging`, so Python resolves `logging` to the stdlib package,
# not to this file. The importlib.import_module workaround is not needed.


class RunIdFilter(_log.Filter):
    """Injects run_id into every log record passing through the aila logger.

    Attached to the StreamHandler (not the logger) so it fires for records from
    all child loggers in the 'aila' hierarchy (e.g. 'aila.cli', 'aila.storage').
    The run_id field is read by _JsonFormatter and human formatters via
    %(run_id)s if included in the format string.

    Thread-safety: run_id is a plain string attribute.  set_run_id() is called
    once per workflow dispatch from the main thread before any worker threads start,
    so concurrent reads are safe in practice.
    """

    def __init__(self) -> None:
        super().__init__()
        self.run_id: str = ""

    def filter(self, record: _log.LogRecord) -> bool:
        """Attach the current run_id to the log record.  Always returns True."""
        record.run_id = self.run_id  # dynamic attribute injection — LogRecord allows extra fields
        return True

    def set_run_id(self, run_id: str) -> None:
        """Update the run_id injected into subsequent log records."""
        self.run_id = run_id


_HUMAN_FMT = "%(asctime)s %(levelname)-8s %(name)s  %(message)s"
_HUMAN_DATEFMT = "%H:%M:%S"


class _JsonFormatter(_log.Formatter):
    """Formats log records as single-line JSON with ISO 8601 timestamps and run_id.

    Output fields:
    - time: ISO 8601 UTC timestamp (e.g. "2026-04-02T14:30:00.123456Z").
      Produced via datetime.utcfromtimestamp + strftime — unambiguous, sortable,
      no locale dependency (Phase 38 DEAD-05 fix: previous implementation used
      the human datefmt "%H:%M:%S" for JSON output, producing non-machine-readable
      timestamps).
    - level: Log level name (e.g. "INFO", "ERROR").
    - logger: Logger name (e.g. "aila.storage.database").
    - message: Formatted log message.
    - run_id: Current workflow run ID for log correlation.  Empty string when not
      in a workflow context.

    Structured log consumers (log aggregators, SIEM) can use run_id to join all
    log lines for a single workflow run across multiple loggers.
    """

    def format(self, record: _log.LogRecord) -> str:
        return json.dumps(
            {
                "time": datetime.utcfromtimestamp(record.created).strftime("%Y-%m-%dT%H:%M:%S.%f") + "Z",
                "level": record.levelname,
                "logger": record.name,
                "message": record.getMessage(),
                "run_id": getattr(record, "run_id", ""),
            }
        )


# Module-level singleton filter — shared across all configure_logging calls.
_run_id_filter = RunIdFilter()


def configure_logging(*, run_id: str | None = None, json_output: bool = False) -> None:
    """Install a StreamHandler on the 'aila' logger.

    Idempotent: calling multiple times replaces the handler rather than
    stacking duplicates. The 'aila' hierarchy inherits from this logger.

    The RunIdFilter is added to the handler (not the logger) so that it
    applies to records from child loggers (e.g. 'aila.cli') passing
    through this handler.
    """
    logger = _log.getLogger("aila")

    # Remove any existing StreamHandler installed by a previous configure_logging
    # call (idempotency). We tag our handler with a sentinel attribute so we can
    # identify it without relying on stream identity (pytest replaces sys.stderr).
    for handler in list(logger.handlers):
        if getattr(handler, "_aila_managed", False):
            logger.removeHandler(handler)

    # Build new handler.
    handler = _log.StreamHandler(sys.stderr)
    handler.setLevel(_log.INFO)
    # Tag so the next configure_logging call can find and replace it.
    handler._aila_managed = True  # type: ignore[attr-defined]

    # Attach the run_id filter to the handler so it fires for all child loggers.
    handler.addFilter(_run_id_filter)

    if json_output:
        handler.setFormatter(_JsonFormatter())
    else:
        formatter = _log.Formatter(fmt=_HUMAN_FMT, datefmt=_HUMAN_DATEFMT)
        handler.setFormatter(formatter)

    logger.addHandler(handler)
    # Set logger level to DEBUG so handlers can control what they show.
    logger.setLevel(_log.DEBUG)

    # Always update run_id: provide the given value or reset to "" so each
    # configure_logging call starts with a clean state.
    _run_id_filter.set_run_id(run_id if run_id is not None else "")


def get_logger(name: str) -> _log.Logger:
    """Return a stdlib Logger bound to the 'aila' hierarchy for run_id correlation.

    The returned logger inherits from the 'aila' root logger and therefore
    receives the RunIdFilter that injects run_id into every record.  Use this
    instead of logging.getLogger() to ensure all AILA log lines are correlated.

    Args:
        name: Logger name, typically __name__ of the calling module
            (e.g. "aila.storage.database").

    Returns:
        A stdlib Logger instance in the 'aila' hierarchy.
    """
    return _log.getLogger(name)


def set_run_id(run_id: str) -> None:
    """Update the run_id injected into all subsequent 'aila' log records.

    Call this at the start of each workflow run so that all log lines emitted
    during the run carry the run_id for correlation.  Call with an empty string
    to clear the run_id after the run completes.
    """
    _run_id_filter.set_run_id(run_id)


__all__ = ["configure_logging", "get_logger", "set_run_id", "RunIdFilter"]
