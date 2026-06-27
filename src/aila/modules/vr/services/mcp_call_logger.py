"""Helpers for writing one ``VRMcpCallLogRecord`` per MCP call.

Both ``AuditMcpBridgeTool.forward`` and ``IDABridgeTool.forward`` wrap
their HTTP call in :func:`record_call` so the operator-visible call log
captures every delegated action regardless of outcome.

This module is intentionally tiny -- no batching, no buffering, no
emission to events. Writes happen synchronously inline because the
operator wants to see the call in /vr/mcp/calls within the same second
it ran.
"""
from __future__ import annotations

import contextlib
import logging
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from aila.modules.vr.db_models import VRMcpCallLogRecord
from aila.platform.uow import UnitOfWork

__all__ = ["record_call"]

_log = logging.getLogger(__name__)

_ERROR_EXCERPT_MAX = 400


@asynccontextmanager
async def record_call(
    *,
    server_id: str,
    base_url: str,
    action: str,
) -> AsyncGenerator[dict[str, Any], None]:
    """Async context manager that writes one ``VRMcpCallLogRecord`` per call.

    Usage::

        async with record_call(server_id="audit_mcp", base_url=url, action=action) as ctx:
            resp = await client.post(...)
            ctx["http_status"] = resp.status_code
            ctx["status"] = "ready"  # or "error" / "pending"
            ctx["error_excerpt"] = ...  # optional

    The recorder always writes, even when the wrapped code raises. The
    ``status`` defaults to ``"error"`` and the exception's repr lands in
    ``error_excerpt`` so the UI shows ``what blew up``.
    """
    start = time.perf_counter()
    ctx: dict[str, Any] = {
        "http_status": None,
        "status": "error",
        "error_excerpt": None,
        "target_id": None,
        "team_id": None,
    }
    try:
        yield ctx
    except BaseException as exc:
        ctx["error_excerpt"] = repr(exc)[:_ERROR_EXCERPT_MAX]
        raise
    finally:
        latency_ms = int((time.perf_counter() - start) * 1000)
        await _write_record(
            server_id=server_id,
            base_url=base_url,
            action=action,
            latency_ms=latency_ms,
            **ctx,
        )


async def _write_record(
    *,
    server_id: str,
    base_url: str,
    action: str,
    latency_ms: int,
    http_status: int | None,
    status: str,
    error_excerpt: str | None,
    target_id: str | None,
    team_id: str | None,
) -> None:
    """Persist one log row. Swallowed errors only -- never crash the caller."""
    with contextlib.suppress(Exception):
        async with UnitOfWork() as uow:
            row = VRMcpCallLogRecord(
                server_id=server_id,
                base_url=base_url,
                action=action,
                latency_ms=latency_ms,
                http_status=http_status,
                status=status,
                error_excerpt=error_excerpt,
                target_id=target_id,
                team_id=team_id,
            )
            uow.session.add(row)
            await uow.session.commit()
            return
    # If we land here the write failed (DB unreachable, etc). Worker
    # logs still capture the call. Don't degrade the user-facing call.
    _log.warning(
        "vr.mcp_call_log write failed: server=%s action=%s latency_ms=%d status=%s",
        server_id, action, latency_ms, status,
    )
