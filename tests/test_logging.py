"""Tests for src/aila/logging.py — RunIdFilter, formatters, configure_logging."""

from __future__ import annotations

import json
import logging
import sys


def test_get_logger_returns_logger_in_aila_hierarchy():
    from aila.logging import get_logger

    logger = get_logger("aila.test_hierarchy")
    assert isinstance(logger, logging.Logger)
    assert logger.name == "aila.test_hierarchy"


def test_configure_logging_sets_stream_handler_on_aila_logger():
    from aila.logging import configure_logging

    configure_logging(run_id="test-setup", json_output=False)
    aila_logger = logging.getLogger("aila")
    stream_handlers = [h for h in aila_logger.handlers if isinstance(h, logging.StreamHandler)]
    assert len(stream_handlers) >= 1


def test_configure_logging_is_idempotent():
    from aila.logging import configure_logging

    configure_logging(run_id="idem-1", json_output=False)
    configure_logging(run_id="idem-2", json_output=False)
    aila_logger = logging.getLogger("aila")
    stream_handlers = [h for h in aila_logger.handlers if isinstance(h, logging.StreamHandler)]
    assert len(stream_handlers) == 1, f"Expected exactly 1 StreamHandler, got {len(stream_handlers)}"


def test_configure_logging_default_level_is_info():
    from aila.logging import configure_logging, get_logger

    configure_logging(run_id="level-test", json_output=False)
    logger = get_logger("aila.level_check")
    assert logger.getEffectiveLevel() <= logging.INFO


def test_run_id_filter_injects_run_id(capfd):
    from aila.logging import configure_logging, get_logger

    configure_logging(run_id="run-abc", json_output=False)
    logger = get_logger("aila.run_id_inject")
    logger.info("test message")
    captured = capfd.readouterr()
    assert "test message" in captured.err or "test message" in captured.out


def test_json_formatter_produces_valid_json(capfd):
    from aila.logging import configure_logging, get_logger

    configure_logging(run_id="json-test-001", json_output=True)
    logger = get_logger("aila.json_test")
    logger.info("structured entry")
    captured = capfd.readouterr()
    stderr_output = captured.err.strip()
    assert stderr_output, "Expected JSON output on stderr"
    # Find the JSON line emitted
    for line in stderr_output.splitlines():
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        # Found a valid JSON line — verify keys
        assert "time" in data
        assert "level" in data
        assert "logger" in data
        assert "message" in data
        assert "run_id" in data
        assert data["run_id"] == "json-test-001"
        assert data["message"] == "structured entry"
        return
    raise AssertionError(f"No valid JSON line found in stderr output: {stderr_output!r}")


def test_json_formatter_run_id_empty_when_not_set(capfd):
    from aila.logging import configure_logging, get_logger

    configure_logging(json_output=True)  # no run_id
    logger = get_logger("aila.no_run_id")
    logger.info("no run id test")
    captured = capfd.readouterr()
    for line in captured.err.strip().splitlines():
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if data.get("message") == "no run id test":
            assert data["run_id"] == ""
            return
    raise AssertionError("No matching JSON line found")


def test_set_run_id_updates_filter(capfd):
    from aila.logging import configure_logging, get_logger, set_run_id

    configure_logging(json_output=True)
    set_run_id("updated-run-id")
    logger = get_logger("aila.set_run_id_test")
    logger.info("after set_run_id")
    captured = capfd.readouterr()
    for line in captured.err.strip().splitlines():
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        if data.get("message") == "after set_run_id":
            assert data["run_id"] == "updated-run-id"
            return
    raise AssertionError("No matching JSON line found")


def test_run_id_filter_standalone():
    from aila.logging import RunIdFilter

    f = RunIdFilter()
    assert f.run_id == ""

    record = logging.LogRecord(
        name="aila.test", level=logging.INFO, pathname="", lineno=0,
        msg="hello", args=(), exc_info=None
    )
    result = f.filter(record)
    assert result is True
    assert record.run_id == ""

    f.set_run_id("xyz-456")
    f.filter(record)
    assert record.run_id == "xyz-456"


def test_all_exports():
    import aila.logging as log_module

    for name in ["configure_logging", "get_logger", "set_run_id", "RunIdFilter"]:
        assert name in log_module.__all__, f"{name!r} not in __all__"
        assert hasattr(log_module, name), f"{name!r} not exported"
