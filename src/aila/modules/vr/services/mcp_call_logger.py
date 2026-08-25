"""VR binding of the platform MCP call logger.

Binds the platform ``record_call`` to the consolidated platform
:class:`McpCallLogRecord` via a module-level ``functools.partial`` and stamps
``module_scope="vr"`` on every write so the operator dashboard can slice the
platform audit trail by originating module. Callers use ``record_call``
unchanged.
"""
from __future__ import annotations

from functools import partial

from aila.platform.mcp.call_log_record import McpCallLogRecord
from aila.platform.mcp.call_logger import record_call as _platform_record_call

__all__ = ["record_call"]

record_call = partial(
    _platform_record_call,
    record_model=McpCallLogRecord,
    log_prefix="vr.mcp_call_log",
    module_scope="vr",
)
