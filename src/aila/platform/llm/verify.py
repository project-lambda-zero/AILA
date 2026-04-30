"""Second-model verification pipeline step.

Triggered when confidence is below a configurable threshold.  Sends the
SAME original prompt (blind -- no first model output) to a different model
and compares verdicts.  Both models' evidence and verdicts are stored in
VerificationRecord for full audit transparency.

The second model sees only the raw messages -- never the first model's
response.  This prevents anchoring bias in the verification assessment.

The verification step follows the same AsyncOpenAI client creation pattern
as gate.py's consensus retry: fresh client, bypass pipeline via call_fn.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Awaitable, TYPE_CHECKING

from openai import AsyncOpenAI

from .config import LLMConfigProvider, LLMRouting
from .gate import extract_confidence

if TYPE_CHECKING:
    from ..events.emitter import EventEmitter

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _confidence_to_level(score: float) -> str:
    """Map numeric score to confidence level string.

    Uses the same breakpoints as gate.py defaults: HIGH >= 0.8,
    MEDIUM >= 0.5, LOW >= 0.2, below that REJECT.
    """
    if score >= 0.8:
        return "HIGH"
    if score >= 0.5:
        return "MEDIUM"
    if score >= 0.2:
        return "LOW"
    return "REJECT"


# ---------------------------------------------------------------------------
# Audit event emission
# ---------------------------------------------------------------------------


def _emit_verify_event(
    ctx: dict[str, Any],
    routing: LLMRouting,
    disposition: str,
    agreement: bool,
    second_model_id: str,
    emitter: EventEmitter | None,
) -> None:
    """Emit llm_verification audit event."""
    if emitter is None:
        return

    from ..events.event import PlatformEvent

    emitter.emit(
        PlatformEvent(
            stage="llm_verification",
            action="verify",
            key=f"llm.verify.{ctx['task_type']}",
            message=f"Verification: {disposition} (agreement={agreement})",
            details={
                "task_type": ctx["task_type"],
                "first_model_id": routing.model_id,
                "second_model_id": second_model_id,
                "agreement": agreement,
                "disposition": disposition,
                "run_id": ctx.get("run_id", ""),
            },
        )
    )


# ---------------------------------------------------------------------------
# Factory: make_verify_step
# ---------------------------------------------------------------------------


def make_verify_step(
    config_provider: LLMConfigProvider,
    call_fn: Callable[..., Awaitable[Any]],
    emitter: EventEmitter | None = None,
) -> Any:
    """Create the verify pipeline step closure.

    The returned async callable matches the StepFn protocol:
    ``async def step(ctx, messages, routing) -> None``.

    The verify step is triggered when confidence is below a configurable
    threshold.  It calls a second model with the ORIGINAL messages (blind
    assessment) and compares verdicts.

    Args:
        config_provider: LLMConfigProvider for threshold/model config reads.
        call_fn: Async callable for raw LLM calls (bypasses pipeline).
        emitter: Optional EventEmitter for audit logging.

    Returns:
        Async step function for pipeline registration.
    """

    async def _verify_step(
        ctx: dict[str, Any],
        messages: list[dict[str, Any]],
        routing: LLMRouting,
    ) -> None:
        task_type = ctx.get("task_type", "")

        # Guard: no response to verify
        response = ctx.get("response")
        if response is None:
            return

        # Check if verify is enabled for this task_type
        if not await config_provider.is_step_enabled("verify", task_type):
            return

        # Read confidence from gate step's pipeline_metadata.
        # Gate stores score in ctx["pipeline_metadata"]["confidence_gating"]["confidence_score"].
        # Confidence level string is in ctx["confidence"].
        pipeline_meta = ctx.get("pipeline_metadata")
        confidence_score = 1.0
        if isinstance(pipeline_meta, dict):
            gating = pipeline_meta.get("confidence_gating")
            if isinstance(gating, dict):
                raw_score = gating.get("confidence_score")
                if isinstance(raw_score, (int, float)):
                    confidence_score = float(raw_score)

        # Read threshold from config
        threshold = await config_provider.resolve_verify_threshold(task_type)

        if confidence_score >= threshold:
            return  # Confidence high enough, skip verification

        logger.info(
            "Verification triggered for %s (confidence=%.2f < threshold=%.2f)",
            task_type,
            confidence_score,
            threshold,
        )

        # Resolve second model
        verify_model = await config_provider.resolve_verify_model(task_type)
        if not verify_model:
            logger.warning("No verification model configured for %s, skipping", task_type)
            return

        # First model results (from current pipeline run)
        first_model_id = routing.model_id
        first_response_content = response.content if response.content else ""
        first_confidence = confidence_score
        first_level = ctx.get("confidence", "UNKNOWN")

        # Call second model with ORIGINAL messages (blind -- no first model output)
        # Follow gate.py pattern: create fresh client, bypass pipeline via call_fn
        try:
            verify_routing = LLMRouting(
                model_id=verify_model,
                base_url=routing.base_url,
                api_key=routing.api_key,
                max_tokens=routing.max_tokens,
                temperature=0.0,  # Deterministic for verification
                max_tool_steps=0,
                task_type=task_type,
            )

            client = AsyncOpenAI(
                api_key=routing.api_key,
                base_url=routing.base_url,
                max_retries=0,
            )

            try:
                second_resp = await call_fn(
                    client=client,
                    routing=verify_routing,
                    messages=messages,  # Original messages -- blind assessment
                    response_format=None,
                    tools=None,
                    tool_executor=None,
                )
            finally:
                await client.close()

            second_content = second_resp.content if second_resp.content else ""
            second_finish = second_resp.finish_reason if second_resp.finish_reason else ""
            second_model_id = verify_model

            # Extract confidence from second model response
            second_confidence = extract_confidence(second_content, second_finish)
            second_level = _confidence_to_level(second_confidence)

            # Compare verdicts (confidence levels)
            agreement = first_level == second_level
            disposition = "verified" if agreement else "flagged_for_review"
            final_verdict = first_level if agreement else "REVIEW_REQUIRED"

            # Store verification record
            from ...storage.db_models import VerificationRecord
            from ...storage.database import async_session_scope

            async with async_session_scope() as session:
                record = VerificationRecord(
                    run_id=ctx.get("run_id", ""),
                    task_type=task_type,
                    first_model_id=first_model_id,
                    first_verdict=first_level,
                    first_confidence=first_confidence,
                    first_evidence=first_response_content[:2000],
                    second_model_id=second_model_id,
                    second_verdict=second_level,
                    second_confidence=second_confidence,
                    second_evidence=second_content[:2000],
                    agreement=agreement,
                    disposition=disposition,
                    final_verdict=final_verdict,
                )
                session.add(record)
                await session.commit()

            # Write verification results to ctx
            ctx["verification_status"] = disposition
            ctx["verification_agreement"] = agreement

            # Build pipeline_metadata entry
            verify_meta: dict[str, Any] = {
                "first_model_id": first_model_id,
                "first_verdict": first_level,
                "first_confidence": first_confidence,
                "second_model_id": second_model_id,
                "second_verdict": second_level,
                "second_confidence": second_confidence,
                "agreement": agreement,
                "disposition": disposition,
                "final_verdict": final_verdict,
            }

            existing_meta = ctx.get("pipeline_metadata")
            if existing_meta is not None:
                merged = dict(existing_meta)
                merged["verification"] = verify_meta
                ctx["pipeline_metadata"] = merged
            else:
                ctx["pipeline_metadata"] = {"verification": verify_meta}

            # Metrics
            from ...api.metrics import VERIFICATION_TOTAL

            VERIFICATION_TOTAL.labels(task_type=task_type, disposition=disposition).inc()

            # Emit audit event
            _emit_verify_event(ctx, routing, disposition, agreement, second_model_id, emitter)

            logger.info(
                "Verification complete: %s (agreement=%s, disposition=%s)",
                task_type,
                agreement,
                disposition,
            )

        except Exception:
            logger.exception(
                "Verification failed for %s, continuing without verification",
                task_type,
            )
            ctx["verification_status"] = "error"

    return _verify_step
