"""ARQ-wrapped entrypoint for mitigation analysis (M3.T-2).

Wraps :class:`MitigationAnalyzer` with the production checksec callable
(backed by ``IDABridgeTool``) and exposes it via ``@platform_task``.
Enqueued by:
  * api_router on target creation (eventually — M3.T-4 orchestrator),
  * operator-initiated re-enrichment endpoint,
  * downstream enrichment chains.

Per CLAUDE.md the function body is a thin wrapper: construction of the
dependency, call to the service, return its result. All durability /
retry / audit-trail concerns live in ``@platform_task``.
"""
from __future__ import annotations

from typing import Any

from aila.modules.vr.enrichment.contracts import MitigationSource
from aila.modules.vr.enrichment.services import MitigationAnalyzer
from aila.modules.vr.tools.ida_bridge import IDABridgeTool
from aila.platform.tasks.context import TaskContext
from aila.platform.tasks.template import platform_task

__all__ = ["run_mitigation_analysis"]


@platform_task(
    track="vr",
    module_id="vr",
    max_tries=2,
    timeout_s=180.0,
)
async def run_mitigation_analysis(
    ctx: TaskContext,
    target_id: str,
) -> dict[str, Any]:
    """Run mitigation analysis for one target and return the report dict.

    Args:
        target_id: vr_targets.id to analyze. The analyzer reads
            ``binary_id`` from ``vr_targets.descriptor_json`` and runs
            IDA-MCP ``checksec`` against it.

    Returns:
        ``MitigationReport.model_dump(mode='json')`` so the result is
        JSON-serializable for downstream consumers (task queue, audit
        trail, SSE push).
    """
    ida_bridge = IDABridgeTool()

    async def _checksec(bid: str) -> dict[str, Any]:
        return await ida_bridge.forward(action="checksec", binary_id=bid)

    analyzer = MitigationAnalyzer(
        checksec=_checksec,
        source=MitigationSource.IDA_CHECKSEC,
    )
    report = await analyzer.analyze(target_id)
    return report.model_dump(mode="json")
