"""Helpers for writing one MCP call-log row per delegated MCP call.

``AuditMcpBridgeTool.forward`` and ``IDABridgeTool.forward`` wrap their HTTP
call in :func:`record_call` so the operator-visible call log captures every
delegated action regardless of outcome. Writes happen synchronously inline so
the operator sees the call in ``/<module>/mcp/calls`` within the same second it
ran.

Generic over the module: the caller's module binds ``record_model`` (its MCP
call-log record) and ``log_prefix`` via a module-level ``functools.partial``;
this module never names a module. The correlation join-keys (#39) are stamped
from the ambient correlation ContextVar on every write.

Exception policy: only infra-transient failures are swallowed -- schema bugs
(TypeError / AttributeError / Pydantic ValidationError) propagate so drift
surfaces immediately rather than being silently dropped.
"""
from __future__ import annotations

import logging
import time
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any

from sqlalchemy.exc import SQLAlchemyError

from aila.platform.llm.correlation import current_join_keys
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
    record_model: type,
    log_prefix: str,
) -> AsyncGenerator[dict[str, Any], None]:
    """Async context manager that writes one MCP call-log row per call.

    Usage (through a module-bound partial that supplies ``record_model`` +
    ``log_prefix``)::

        async with record_call(server_id="audit_mcp", base_url=url, action=action) as ctx:
            resp = await client.post(...)
            ctx["http_status"] = resp.status_code
            ctx["status"] = "ready"  # or "error" / "pending"

    The recorder always writes, even when the wrapped code raises. The
    ``status`` defaults to ``"error"`` and the exception's repr lands in
    ``error_excerpt`` so the UI shows what blew up.
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
            record_model=record_model,
            log_prefix=log_prefix,
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
    record_model: type,
    log_prefix: str,
) -> None:
    """Persist one call-log row.

    Catches infra-transient failures only -- schema bugs propagate so drift
    surfaces immediately. Stamps the #39 correlation join-keys from the ambient
    ContextVar.
    """
    _inv, _branch, _turn = current_join_keys()
    try:
        async with UnitOfWork() as uow:
            row = record_model(
                server_id=server_id,
                base_url=base_url,
                action=action,
                latency_ms=latency_ms,
                http_status=http_status,
                status=status,
                error_excerpt=error_excerpt,
                target_id=target_id,
                team_id=team_id,
                investigation_id=_inv,
                branch_id=_branch,
                turn_number=_turn,
            )
            uow.session.add(row)
            await uow.session.commit()
            return
    except (SQLAlchemyError, OSError, RuntimeError, TimeoutError) as exc:
        _log.warning(
            "%s write failed: server=%s action=%s latency_ms=%d status=%s err=%s",
            log_prefix, server_id, action, latency_ms, status, exc,
        )
