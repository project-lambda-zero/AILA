"""Index-readiness probe for the VR investigation loop gate.

Operator-requested (2026): an investigation must never fire agent turns
against a half-built code index. Every audit-mcp read then fails on a
still-building index and the agent burns turns flailing (observed live on
the Apache Tomcat / OFBiz hunts -- ``read_function`` blocked, semantic
search returning ``semble still building``).

This probe resolves an investigation's bound audit-mcp index and reports
whether BOTH the graph (trailmark) index AND the semantic (semble) index
are ready. The platform loop gate (``investigation_loop_base``) calls it
through the ``index_readiness_fn`` binding; when it returns not-ready the
run is deferred (re-enqueued) with ZERO turns until the index is ready, so
the investigation simply sits on the queue.

Fail-open: any resolution / probe fault returns ``(True, ...)`` so a probe
defect never wedges an investigation -- the per-call tool guards still
apply. A missing index (target never analyzed) is treated as ready so the
run proceeds and the tool layer reports the real "not indexed" state
rather than the run waiting forever.
"""
from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING

from sqlalchemy.exc import SQLAlchemyError

if TYPE_CHECKING:
    from aila.platform.mcp.client import McpClient

__all__ = ["vr_index_readiness"]

_log = logging.getLogger(__name__)

# audit-mcp four-tier resolver inputs -- mirror server_specs.audit_mcp so
# an operator PATCH on the catalog row / config key is honoured here too.
_AUDIT_MCP_ENV_VAR = "AUDIT_MCP_URL"
_AUDIT_MCP_CONFIG_KEY = "audit_mcp_url"
_AUDIT_MCP_DEFAULT_URL = "http://127.0.0.1:18822"

# Operator escape hatch. Default True == gate on.
_GATE_CONFIG_KEY = "index_readiness_gate_enabled"

_PROBE_ERRORS = (OSError, TimeoutError, RuntimeError, ValueError, TypeError)


async def _gate_enabled() -> bool:
    """Resolve ``platform.index_readiness_gate_enabled`` (default True)."""
    from aila.storage.registry import ConfigRegistry

    try:
        raw = await ConfigRegistry().get("platform", _GATE_CONFIG_KEY)
    except (SQLAlchemyError, OSError, RuntimeError, ValueError, TypeError):
        return True
    if raw is None:
        return True
    if isinstance(raw, bool):
        return raw
    return str(raw).strip().lower() not in ("0", "false", "no", "off")


async def _resolve_index_id(investigation_id: str) -> str:
    """Resolve investigation -> primary target -> audit-mcp index id.

    Mirrors ``ToolExecutor._resolve_index_id``: a source_repo target
    stores the index under ``audit_mcp_index_id``; an android_apk target
    under ``audit_mcp_decompiled_index_id``. Returns ``""`` when no
    analyzed target / index exists.
    """
    from sqlmodel import select

    from aila.modules.vr.db_models import (
        VRInvestigationRecord,
        VRTargetRecord,
    )
    from aila.platform.uow import UnitOfWork

    async with UnitOfWork() as uow:
        inv = (await uow.session.exec(
            select(VRInvestigationRecord).where(
                VRInvestigationRecord.id == investigation_id,
            ),
        )).first()
        if inv is None or not inv.target_id:
            return ""
        target = (await uow.session.exec(
            select(VRTargetRecord).where(VRTargetRecord.id == inv.target_id),
        )).first()
        if target is None or not target.mcp_handles_json:
            return ""
        handles_json = target.mcp_handles_json
    try:
        handles = json.loads(handles_json or "{}")
    except (ValueError, TypeError) as exc:
        _log.debug(
            "vr_index_readiness: malformed mcp_handles_json for inv=%s: %s",
            investigation_id, exc,
        )
        return ""
    return str(
        handles.get("audit_mcp_index_id")
        or handles.get("audit_mcp_decompiled_index_id")
        or "",
    )


async def _audit_mcp_client() -> McpClient:
    """Build an :class:`McpClient` bound to the resolved audit-mcp URL."""
    from aila.platform.mcp.client import McpClient, resolve_instance

    resolved = await resolve_instance(
        module_scope="vr",
        server_name="audit_mcp",
        env_var=_AUDIT_MCP_ENV_VAR,
        config_key=_AUDIT_MCP_CONFIG_KEY,
        default_url=_AUDIT_MCP_DEFAULT_URL,
    )
    return McpClient(
        server_id="audit_mcp", base_url=resolved.url, timeout=30.0,
    )


async def vr_index_readiness(investigation_id: str) -> tuple[bool, str]:
    """Return ``(ready, detail)`` for the investigation's bound index.

    Ready == graph index ``status == 'ready'`` AND semantic index
    ``semble_status == 'ready'``. When the graph is ready but semble has
    not started (``pending`` / empty), a single ``semantic_search`` is
    fired to kick the lazy build so the next probe converges to ready. A
    missing index or any probe fault returns ``(True, ...)`` (fail-open).
    """
    if not await _gate_enabled():
        return True, "gate-disabled"
    try:
        index_id = await _resolve_index_id(investigation_id)
    except _PROBE_ERRORS as exc:
        return True, f"resolve-error:{type(exc).__name__}"
    if not index_id:
        return True, "no-bound-index"
    try:
        client = await _audit_mcp_client()
        resp = await client.post("poll_index", {"index_id": index_id})
    except _PROBE_ERRORS as exc:
        return True, f"poll-error:{type(exc).__name__}"
    data = resp.json() if hasattr(resp, "json") else resp
    if not isinstance(data, dict):
        return True, "poll-nonjson"
    status = str(data.get("status") or "")
    semble = str(data.get("semble_status") or "")
    if status == "ready" and semble == "ready":
        return True, f"ready (status={status}, semble={semble})"
    if status == "ready" and semble in ("", "pending"):
        # Graph is ready but nothing has triggered the semble build yet.
        # Kick it once so the next probe makes progress instead of
        # waiting on a build no caller ever started.
        try:
            await client.post(
                "semantic_search",
                {
                    "index_id": index_id,
                    "query": "index readiness warm",
                    "top_k": 1,
                },
            )
        except _PROBE_ERRORS:
            pass
    return False, f"building (status={status or '?'}, semble={semble or '?'})"
