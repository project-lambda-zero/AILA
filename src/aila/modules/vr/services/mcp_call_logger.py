"""VR binding of the platform MCP call logger.

Binds the platform ``record_call`` to the VR MCP call-log record via a
module-level ``functools.partial``. Callers use ``record_call`` unchanged.
"""
from __future__ import annotations

from functools import partial

from aila.modules.vr.db_models import VRMcpCallLogRecord
from aila.platform.mcp.call_logger import record_call as _platform_record_call

__all__ = ["record_call"]

record_call = partial(
    _platform_record_call,
    record_model=VRMcpCallLogRecord,
    log_prefix="vr.mcp_call_log",
)
