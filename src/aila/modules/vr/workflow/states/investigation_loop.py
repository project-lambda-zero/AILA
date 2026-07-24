"""Investigation loop state (M3.R-7).

Drives ``HonestVulnResearcher.run_turn`` in a loop until one of:
  * A turn returns ``terminal=True`` (engine emitted submit; outcome
    already persisted)
  * Hits the per-loop max_turns cap
  * Investigation status changes from RUNNING (operator paused, cost
    budget exhausted, MCP failure)

On any exit reason the loop forwards the terminating turn's metadata to
the emit state for finalization. The loop itself does NOT mark the
investigation COMPLETED -- that's emit's job.
"""
from __future__ import annotations

import logging

from aila.modules.vr.agents import (
    HonestVulnResearcher,
    VulnResearcherError,
)
from aila.modules.vr.agents.tool_executor import ToolExecutor
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationRecord,
)
from aila.modules.vr.services.config_helpers import get_int
from aila.modules.vr.services.mcp_call_logger import record_call
from aila.platform.mcp.bridges.android_mcp import AndroidMcpBridgeTool
from aila.platform.mcp.bridges.audit_mcp import AuditMcpBridgeTool
from aila.platform.mcp.bridges.ida_headless import IDABridgeTool
from aila.platform.workflows.investigation_loop_base import (
    state_investigation_loop as _build_loop_state,
)
from aila.platform.workflows.investigation_setup_base import (
    InvestigationStateBindings,
    InvestigationStateHooks,
)

__all__ = ["state_investigation_loop"]

_log = logging.getLogger(__name__)

# Per-task turn budget. Loop returns on submit, status flip, researcher
# error, or when this cap hits -- at which point investigation_emit
# auto-re-enqueues another task (status stays RUNNING) until the
# overall branch.turn_count hits _OVERALL_TURN_CAP. Read at USE site
# via ConfigRegistry (namespace=vr, key=max_turns_per_task) so an
# operator running a deep variant chase can extend the budget via
# PUT /config without a worker restart.

# fix §286 -- module-level executor + bridges singleton, lazily built
# on first task wakeup of each worker process.
#
# Prior code constructed a fresh IDABridgeTool / AuditMcpBridgeTool /
# AndroidMcpBridgeTool / ToolExecutor on EVERY task. The bridges hold
# instance-level httpx clients with connection pools (W1 E12 fix); a
# new instance per task means a new pool every task, defeating the
# whole point of the pool. The executor carries an LRU
# investigation_id → audit_mcp index_id cache (fix §252) sized for
# 2048 concurrent investigations; throwing it away per task means
# every investigation pays the cold-cache resolve cost EVERY task,
# 70 turns wide.
#
# Caching at module scope ties the lifetime to the worker process,
# which is the right granularity:
#   * Restarting a worker bounces the pools (operator intent on
#     restart: re-check bridge config).
#   * Within a worker, tasks for the same investigation reuse the
#     warm index_id; tasks for different investigations share the
#     httpx pool but get independent LRU entries.
_EXECUTOR_SINGLETON: ToolExecutor | None = None


def _get_executor() -> ToolExecutor:
    """Return the per-worker-process ToolExecutor singleton.

    Constructed on first call; subsequent calls return the same
    instance so the bridge httpx pools + executor LRU index_id cache
    survive across investigations.
    """
    global _EXECUTOR_SINGLETON
    if _EXECUTOR_SINGLETON is None:
        _EXECUTOR_SINGLETON = ToolExecutor(
            ida=IDABridgeTool(recorder=record_call),
            audit_mcp=AuditMcpBridgeTool(recorder=record_call),
            android_mcp=AndroidMcpBridgeTool(recorder=record_call),
        )
    return _EXECUTOR_SINGLETON


_LOOP_BINDINGS = InvestigationStateBindings(
    inv_model=VRInvestigationRecord,
    branch_model=VRInvestigationBranchRecord,
    researcher_factory=lambda engine, iid, bid, cve, pat: HonestVulnResearcher(
        reasoning_engine=engine, investigation_id=iid, branch_id=bid,
        cve_intel=cve, applicable_patterns=pat,
    ),
    executor_factory=_get_executor,
    max_turns_reader=lambda: get_int("max_turns_per_task"),
    researcher_error=VulnResearcherError,
)

# The loop handler is the platform factory bound to VR's researcher.
state_investigation_loop = _build_loop_state(
    _LOOP_BINDINGS, InvestigationStateHooks(),
)
