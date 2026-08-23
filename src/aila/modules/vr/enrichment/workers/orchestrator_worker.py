"""ARQ orchestrator that sequences the two enrichment stages (M3.T-4).

Runs ``CapabilityProfileBuilder.build`` FIRST, then
``FunctionRankingDispatcher.rank``. The two stages used to fan out in
parallel from ``enqueue_downstream_target_stages``; they are now
serialised behind this orchestrator so ranking observes whatever the
profile build persisted (``capability_profile_json``) and the operator
gets a single enrichment run with one aggregated outcome per target.

Per-stage StageTracker semantics live inside each service exactly as
before -- the orchestrator does NOT open its own StageTracker and does
NOT double-transition CAPABILITY_PROFILE / FUNCTION_RANKING. It just
sequences the two service calls and folds their outputs / failures
into a single ``EnrichmentResult``.

Errors from one stage are captured as an ``EnrichmentError`` entry
rather than aborting the whole orchestrator, so a wedged audit-mcp
that blocks profile-build still lets ranking run (and vice-versa).
Enqueued by ``enqueue_downstream_target_stages`` (post-ingestion
fan-out) and by the operator-facing resume-analysis endpoint.
"""
from __future__ import annotations

import logging
from typing import Any

from aila.modules.vr.contracts.enrichment import (
    EnrichmentError,
    EnrichmentResult,
    TargetCapabilityProfile,
)
from aila.modules.vr.enrichment.services import (
    CapabilityProfileBuilder,
    FunctionRankerError,
    FunctionRankingDispatcher,
    ProfileBuilderError,
)
from aila.modules.vr.services.mcp_call_logger import record_call
from aila.modules.vr.services.stage_tracker import StageTrackerError
from aila.platform.contracts import utc_now
from aila.platform.mcp.factory import make_bridge
from aila.platform.tasks.context import TaskContext
from aila.platform.tasks.template import platform_task

__all__ = ["orchestrate_target_enrichment", "run_target_enrichment"]

_log = logging.getLogger(__name__)

# Exceptions the orchestrator captures per stage. Anything outside this
# tuple -- CancelledError, KeyboardInterrupt, SystemExit -- still
# propagates so worker shutdown / a wrapper timeout kill is honoured.
# The set covers:
#   - infra flap the services actually surface (MCP transport, DB, wall
#     clocks, mis-shaped MCP payloads):
#     OSError / ConnectionError / TimeoutError / RuntimeError / ValueError
#     / LookupError.
#   - the services' own domain exception classes
#     (ProfileBuilderError / FunctionRankerError, both Exception-direct
#     subclasses) and the tracker's StageTrackerError, which the
#     tracker's __aexit__ re-raises when the work body raised.
_STAGE_CAPTURED_ERRORS: tuple[type[BaseException], ...] = (
    OSError,
    TimeoutError,
    ConnectionError,
    RuntimeError,
    ValueError,
    LookupError,
    ProfileBuilderError,
    FunctionRankerError,
    StageTrackerError,
)


async def orchestrate_target_enrichment(
    target_id: str,
    *,
    builder: CapabilityProfileBuilder,
    dispatcher: FunctionRankingDispatcher,
) -> EnrichmentResult:
    """Run profile-build then ranking against ``target_id`` and aggregate.

    Split out from the ARQ entrypoint so tests can drive the orchestrator
    with fake ``builder`` / ``dispatcher`` doubles without spinning up
    the platform-task wrapper or a real MCP bridge.

    - Profile build runs first. Its return value populates
      ``EnrichmentResult.capability_profile`` (or ``None`` when the
      stage was skipped because it was already DONE / in flight).
    - Ranking runs second, unconditionally -- even if profile-build
      failed, so a healthy ranker doesn't get punished for an unrelated
      audit-mcp outage on the profile side. Its return value is not
      embedded in ``EnrichmentResult`` directly (the ranker persists
      it into ``capability_profile.function_ranking`` sidecar via
      StageTracker.record_output).
    - Any exception in ``_STAGE_CAPTURED_ERRORS`` from either stage is
      turned into an ``EnrichmentError`` entry (``step`` = the stage
      name, ``message`` = ``TypeName: str(exc)``). Domain-specific
      exceptions like ``ProfileBuilderError`` / ``FunctionRankerError``
      subclass ``Exception`` directly, and both fall through
      ``RuntimeError``-free -- they are captured explicitly by their
      concrete types being subclasses of ``Exception``; we widen to
      catch anything that is not a control-flow signal.
    """
    errors: list[EnrichmentError] = []
    profile: TargetCapabilityProfile | None = None

    try:
        profile = await builder.build(target_id)
    except _STAGE_CAPTURED_ERRORS as exc:
        _log.exception(
            "orchestrate_target_enrichment: capability_profile stage failed "
            "target_id=%s",
            target_id,
        )
        errors.append(EnrichmentError(
            step="capability_profile",
            message=f"{type(exc).__name__}: {exc}",
        ))

    try:
        await dispatcher.rank(target_id)
    except _STAGE_CAPTURED_ERRORS as exc:
        _log.exception(
            "orchestrate_target_enrichment: function_ranking stage failed "
            "target_id=%s",
            target_id,
        )
        errors.append(EnrichmentError(
            step="function_ranking",
            message=f"{type(exc).__name__}: {exc}",
        ))

    return EnrichmentResult(
        target_id=target_id,
        capability_profile=profile,
        completed_at=utc_now().isoformat(),
        errors=errors,
    )


@platform_task(
    track="vr",
    module_id="vr",
    max_tries=2,
    # ARQ hard cap on the enrichment worker slot. Sized to bound the sum
    # of both operator-tunable per-stage reaper caps
    # (``stage_capability_profile_timeout_s`` + ``stage_function_ranking_timeout_s``,
    # each defaulting to 7200s in ``vr/config_schema.py``) plus DB /
    # bridge overhead so large native binaries -- e.g. driver DLLs the
    # size of nvcuda.dll / nvapi64.dll -- don't get pre-empted mid-flight
    # by the ARQ job_timeout before the reaper has a chance to notice
    # (the historical 1800s cap tripped simultaneously with the stage
    # reaper's own 1800s cap and produced FAILED:timeout rows the
    # operator had to resume by hand). This is a wall-clock safety net,
    # not the operator's steering knob; that lives on the stage
    # timeouts in the VR config schema. 4h matches
    # ``ingestion_poll_timeout_s`` so the two enrichment stages get the
    # same operator envelope as the ingestion stage they follow.
    timeout_s=14400.0,
)
async def run_target_enrichment(
    ctx: TaskContext,
    target_id: str,
) -> dict[str, Any]:
    """Enqueued sequenced enrichment: capability_profile then ranking.

    See ``orchestrate_target_enrichment`` for the loop; this entrypoint
    just wires the two service constructors (with the VR MCP call
    recorder) and returns the JSON-serialised ``EnrichmentResult``.
    """
    del ctx
    ida = make_bridge("ida_headless", module_id="vr", recorder=record_call)
    audit_mcp = make_bridge("audit_mcp", module_id="vr", recorder=record_call)

    result = await orchestrate_target_enrichment(
        target_id,
        builder=CapabilityProfileBuilder(ida=ida, audit_mcp=audit_mcp),
        dispatcher=FunctionRankingDispatcher(ida=ida, audit_mcp=audit_mcp),
    )

    _log.info(
        "run_target_enrichment COMPLETE target_id=%s errors=%d has_profile=%s",
        target_id,
        len(result.errors),
        result.capability_profile is not None,
    )
    return result.model_dump(mode="json")
