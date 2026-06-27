"""Structured logging configuration for AILA using structlog.

Per D-45: structlog on top of stdlib logging.
- JSON renderer in production (AILA_ENV != dev/development/local)
- ConsoleRenderer (pretty) in development
- Correlation IDs bound via CorrelationIdMiddleware using structlog contextvars

Call configure_logging() once at application startup (in lifespan).
"""
from __future__ import annotations

import logging
import os

import structlog

__all__ = ["configure_logging"]


def configure_logging() -> None:
    """Configure structlog for structured logging.

    Uses JSON renderer when AILA_ENV is production/staging/any non-dev value.
    Uses ConsoleRenderer (human-readable) when AILA_ENV is dev/development/local
    or when AILA_ENV is unset (developer default).

    Processors chain:
    1. merge_contextvars -- pull bound context (correlation_id, path, method)
    2. add_log_level -- add level name to event dict
    3. add_logger_name -- add logger name for traceability
    4. TimeStamper(fmt="iso") -- ISO 8601 timestamp
    5. renderer -- JSON or ConsoleRenderer based on environment
    """
    env = os.getenv("AILA_ENV", "development").lower()
    is_production = env not in ("dev", "development", "local", "test")

    renderer: structlog.types.Processor
    if is_production:
        renderer = structlog.processors.JSONRenderer()
    else:
        renderer = structlog.dev.ConsoleRenderer()

    structlog.configure(
        processors=[
            structlog.contextvars.merge_contextvars,
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.INFO),
        context_class=dict,
        logger_factory=structlog.WriteLoggerFactory(),
        cache_logger_on_first_use=True,
    )
