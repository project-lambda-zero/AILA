"""Template binding of the platform MCP call logger.

Mirrors :mod:`aila.modules.vr.services.mcp_call_logger`. Binds the
platform ``record_call`` to :class:`TemplateMcpCallLogRecord` via a
module-level ``functools.partial``. Callers use ``record_call``
unchanged; the #39 correlation join-keys are stamped by the platform
context manager on every write.
"""
from __future__ import annotations

from functools import partial

from aila.modules._template.db_models import TemplateMcpCallLogRecord
from aila.platform.mcp.call_logger import record_call as _platform_record_call

__all__ = ["record_call"]

record_call = partial(
    _platform_record_call,
    record_model=TemplateMcpCallLogRecord,
    log_prefix="template.mcp_call_log",
)
