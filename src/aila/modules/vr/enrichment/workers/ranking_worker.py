"""ARQ entrypoint for function ranking dispatch.

Wires ``IDABridgeTool`` + ``AuditMcpBridgeTool`` into the
``FunctionRankingDispatcher`` and exposes via ``@platform_task``.
Enqueued by:
  * api_router on operator-initiated /api/vr/targets/<id>/rank
  * M3.T-4 capability_profile_builder orchestrator (will land later)
"""
from __future__ import annotations

from typing import Any

from aila.modules.vr.enrichment.services import FunctionRankingDispatcher
from aila.modules.vr.services.mcp_call_logger import record_call
from aila.platform.mcp.bridges.audit_mcp import AuditMcpBridgeTool
from aila.platform.mcp.bridges.ida_headless import IDABridgeTool
from aila.platform.tasks.context import TaskContext
from aila.platform.tasks.template import platform_task

__all__ = ["run_function_ranking"]


@platform_task(
    track="vr",
    module_id="vr",
    max_tries=2,
    timeout_s=600.0,
)
async def run_function_ranking(
    ctx: TaskContext,
    target_id: str,
) -> dict[str, Any]:
    """Dispatch ranking for one target and return the report dict.

    The dispatcher routes by target kind:
      source target → audit-mcp ``fuzzing_targets`` (+ optional scan_and_correlate)
      binary target → IDA ``find_api_call_sites`` aggregation + ``assess_exploitability``

    Returns ``FunctionRanking.model_dump(mode='json')`` so the result is
    JSON-serializable for SSE push / audit trail.
    """
    dispatcher = FunctionRankingDispatcher(
        ida=IDABridgeTool(recorder=record_call),
        audit_mcp=AuditMcpBridgeTool(recorder=record_call),
    )
    ranking = await dispatcher.rank(target_id)
    return ranking.model_dump(mode="json")
