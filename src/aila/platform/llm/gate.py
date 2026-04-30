"""Confidence gating pipeline step.

Post-call step that extracts a confidence score from the LLM response,
maps it to HIGH/MEDIUM/LOW/REJECT, and routes accordingly: auto-accept
HIGH, flag MEDIUM, consensus-retry LOW, discard REJECT.

This is the only pipeline step that makes additional LLM calls (consensus)
and can replace ctx["response"].
"""

from __future__ import annotations

import json
import logging
from typing import Any, Callable, Awaitable, TYPE_CHECKING

import httpx
from openai import AsyncOpenAI

from .config import LLMConfigProvider, LLMRouting
from .errors import ConfidenceRejectedError
from ..exceptions import AILAError

if TYPE_CHECKING:
    from ..events.emitter import EventEmitter
    from .client import LLMResponse

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pure function: confidence extraction (D-01, D-02, D-03)
# ---------------------------------------------------------------------------


def extract_confidence(content: str, finish_reason: str) -> float:
    """Extract confidence score from LLM response content.

    Primary: parse JSON, look for confidence_score field (float 0.0-1.0).
    Fallback: heuristic based on finish_reason and content length.

    Args:
        content: The raw response content string.
        finish_reason: The finish_reason from the API response.

    Returns:
        Float between 0.0 and 1.0.
    """
    # Primary: JSON with confidence_score field
    try:
        data = json.loads(content)
        if isinstance(data, dict):
            score = data.get("confidence_score")
            if isinstance(score, (int, float)):
                score_f = float(score)
                if 0.0 <= score_f <= 1.0:
                    return score_f
    except (json.JSONDecodeError, ValueError, TypeError):
        pass

    # Fallback heuristic (D-02)
    if finish_reason == "length":
        return 0.4  # Likely truncated
    if content and len(content.strip()) > 50:
        return 0.7  # Normal completion
    return 0.1  # Empty or error-like


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _map_confidence_level(
    score: float,
    high: float,
    medium: float,
    reject: float,
) -> str:
    """Map numeric score to confidence level string.

    Args:
        score: Confidence score (0.0 - 1.0).
        high: Threshold for HIGH (score >= high -> HIGH).
        medium: Threshold for MEDIUM (score >= medium -> MEDIUM).
        reject: Threshold for REJECT (score < reject -> REJECT).

    Returns:
        One of "HIGH", "MEDIUM", "LOW", "REJECT".
    """
    if score >= high:
        return "HIGH"
    if score >= medium:
        return "MEDIUM"
    if score >= reject:
        return "LOW"
    return "REJECT"


async def _resolve_thresholds(
    config_provider: LLMConfigProvider,
    task_type: str,
) -> tuple[float, float, float]:
    """Read gate thresholds from ConfigRegistry.

    Returns (high, medium, reject) tuple with defaults (0.8, 0.5, 0.2).
    """
    registry = config_provider._registry

    async def _get_float(key: str, default: float) -> float:
        val = await registry.get("platform", f"llm_pipeline_gate_{key}_{task_type}")
        if val is not None:
            try:
                return float(val)
            except (ValueError, TypeError):
                pass
        return default

    return (
        await _get_float("high_threshold", 0.8),
        await _get_float("medium_threshold", 0.5),
        await _get_float("reject_threshold", 0.2),
    )


async def _resolve_consensus_config(
    config_provider: LLMConfigProvider,
    task_type: str,
) -> tuple[str, str, int]:
    """Read consensus config from ConfigRegistry.

    Returns (strategy, consensus_model, retries) tuple.
    """
    registry = config_provider._registry

    strategy_val = await registry.get(
        "platform",
        f"llm_pipeline_gate_consensus_strategy_{task_type}",
    )
    strategy = str(strategy_val) if strategy_val is not None else "same_model_high_temp"

    model_val = await registry.get(
        "platform",
        f"llm_pipeline_gate_consensus_model_{task_type}",
    )
    consensus_model = str(model_val) if model_val is not None else ""

    retries_val = await registry.get(
        "platform",
        f"llm_pipeline_gate_consensus_retries_{task_type}",
    )
    retries = 3
    if retries_val is not None:
        try:
            retries = int(retries_val)
        except (ValueError, TypeError):
            pass

    return strategy, consensus_model, retries


# ---------------------------------------------------------------------------
# Consensus runner (D-08, D-11, D-12, D-13, D-16)
# ---------------------------------------------------------------------------


async def _run_consensus(
    *,
    call_fn: Callable[..., Awaitable[Any]],
    config_provider: LLMConfigProvider,
    routing: LLMRouting,
    messages: list[dict[str, Any]],
    original_score: float,
    medium_threshold: float,
) -> tuple[Any, float] | None:
    """Run consensus retry calls and compute majority vote.

    Makes additional LLM calls (bypassing the pipeline to prevent recursion),
    collects confidence scores, and returns the winning response if majority
    vote passes.

    Args:
        call_fn: Async callable for raw LLM calls (_single_call).
        config_provider: For reading consensus config.
        routing: Original routing from the pipeline call.
        messages: Original message list.
        original_score: Confidence score of the original response.
        medium_threshold: Score threshold for "passing" in majority vote.

    Returns:
        Tuple of (winning_response, winning_score) if majority improves,
        or None if consensus fails.
    """
    strategy, consensus_model, retries = await _resolve_consensus_config(
        config_provider, routing.task_type
    )

    retry_results: list[tuple[Any, float]] = []

    for _ in range(retries):
        # Build consensus routing
        if strategy == "cross_model" and consensus_model:
            consensus_routing = LLMRouting(
                model_id=consensus_model,
                base_url=routing.base_url,
                api_key=routing.api_key,
                max_tokens=routing.max_tokens,
                temperature=1.0,
                max_tool_steps=0,
                task_type=routing.task_type,
            )
        else:
            # same_model_high_temp (default)
            consensus_routing = LLMRouting(
                model_id=routing.model_id,
                base_url=routing.base_url,
                api_key=routing.api_key,
                max_tokens=routing.max_tokens,
                temperature=1.0,
                max_tool_steps=0,
                task_type=routing.task_type,
            )

        # Create fresh client for consensus call
        client = AsyncOpenAI(
            api_key=routing.api_key,
            base_url=routing.base_url,
            max_retries=0,
        )

        try:
            resp = await call_fn(
                client=client,
                routing=consensus_routing,
                messages=messages,
                response_format=None,
                tools=None,
                tool_executor=None,
            )
            content = resp.content if resp.content else ""
            finish_reason = resp.finish_reason if resp.finish_reason else ""
            score = extract_confidence(content, finish_reason)
            retry_results.append((resp, score))
        except (AILAError, httpx.HTTPError):
            logger.warning("Consensus retry failed, skipping", exc_info=True)

    if not retry_results:
        return None

    # Majority vote: all_scores = [original] + retries
    all_scores = [original_score] + [s for _, s in retry_results]
    total_votes = len(all_scores)
    passing = sum(1 for s in all_scores if s >= medium_threshold)

    if passing > total_votes / 2:
        # Find highest-confidence response among retries only
        best_resp, best_score = max(retry_results, key=lambda x: x[1])
        # Only replace if the retry is actually better than original
        if best_score > original_score:
            return best_resp, best_score

    return None


# ---------------------------------------------------------------------------
# Factory: make_gate_step (D-14, D-15, D-17, D-18)
# ---------------------------------------------------------------------------


def make_gate_step(
    config_provider: LLMConfigProvider,
    call_fn: Callable[..., Awaitable[Any]],
    emitter: EventEmitter | None = None,
) -> Any:
    """Create the gate pipeline step closure.

    The returned async callable matches the StepFn protocol:
    ``async def step(ctx, messages, routing) -> None``.

    Args:
        config_provider: LLMConfigProvider for threshold/config reads.
        call_fn: Async callable for consensus retry calls (bypasses pipeline).
        emitter: Optional EventEmitter for audit logging.

    Returns:
        Async step function for pipeline registration.
    """

    async def _gate_step(
        ctx: dict[str, Any],
        messages: list[dict[str, Any]],
        routing: LLMRouting,
    ) -> None:
        # Guard: no response to gate
        response = ctx.get("response")
        if response is None:
            return

        content = response.content if response.content else ""
        finish_reason = response.finish_reason if response.finish_reason else ""

        # Extract confidence score
        score = extract_confidence(content, finish_reason)

        # Read thresholds from config
        high, medium, reject = await _resolve_thresholds(config_provider, routing.task_type)

        # Map to level
        level = _map_confidence_level(score, high, medium, reject)
        ctx["confidence"] = level

        # Route by level
        if level == "HIGH":
            pass  # Auto-accept, no extra work
        elif level == "MEDIUM":
            ctx["confidence_flagged"] = True
        elif level == "LOW":
            # Consensus retry
            ctx["consensus_attempted"] = True
            strategy, _, retries = await _resolve_consensus_config(
                config_provider, routing.task_type
            )
            ctx["consensus_retries"] = retries
            ctx["consensus_strategy"] = strategy

            result = await _run_consensus(
                call_fn=call_fn,
                config_provider=config_provider,
                routing=routing,
                messages=messages,
                original_score=score,
                medium_threshold=medium,
            )

            if result is not None:
                winner_resp, winner_score = result
                ctx["response"] = winner_resp
                new_level = _map_confidence_level(winner_score, high, medium, reject)
                ctx["confidence"] = new_level
                ctx["consensus_winner_score"] = winner_score
        elif level == "REJECT":
            # Emit audit event before raising
            _emit_gate_event(ctx, routing, score, level, emitter)
            raise ConfidenceRejectedError(
                f"Response rejected: confidence {score:.2f} below threshold {reject}"
            )

        # Build pipeline_metadata
        gate_meta: dict[str, Any] = {
            "confidence_score": score,
            "confidence_level": ctx["confidence"],
            "flagged": ctx.get("confidence_flagged", False),
            "consensus_attempted": ctx.get("consensus_attempted", False),
            "consensus_retries": ctx.get("consensus_retries", 0),
            "consensus_strategy": ctx.get("consensus_strategy", ""),
            "consensus_winner_score": ctx.get("consensus_winner_score"),
        }

        existing_meta = ctx.get("pipeline_metadata")
        if existing_meta is not None:
            merged = dict(existing_meta)
            merged["confidence_gating"] = gate_meta
            ctx["pipeline_metadata"] = merged
        else:
            ctx["pipeline_metadata"] = {"confidence_gating": gate_meta}

        # Emit audit event
        _emit_gate_event(ctx, routing, score, ctx["confidence"], emitter)

    return _gate_step


# ---------------------------------------------------------------------------
# Audit event emission (D-17, D-18)
# ---------------------------------------------------------------------------


def _emit_gate_event(
    ctx: dict[str, Any],
    routing: LLMRouting,
    score: float,
    level: str,
    emitter: EventEmitter | None,
) -> None:
    """Emit llm_confidence_gating audit event."""
    if emitter is None:
        return

    from ..events.event import PlatformEvent

    emitter.emit(
        PlatformEvent(
            stage="llm_confidence_gating",
            action="gate",
            key=f"llm.gate.{ctx['task_type']}",
            message=f"Confidence gating: {level} ({score:.2f})",
            details={
                "task_type": ctx["task_type"],
                "model_id": routing.model_id,
                "confidence_score": score,
                "confidence_level": level,
                "flagged": ctx.get("confidence_flagged", False),
                "consensus_attempted": ctx.get("consensus_attempted", False),
                "consensus_retries": ctx.get("consensus_retries", 0),
                "consensus_strategy": ctx.get("consensus_strategy", ""),
                "consensus_winner_score": ctx.get("consensus_winner_score"),
            },
        )
    )
