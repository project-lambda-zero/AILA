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
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any

import httpx

from ..exceptions import AILAError
from .config import LLMConfigProvider, LLMRouting
from .errors import ConfidenceRejectedError

if TYPE_CHECKING:
    from ..events.emitter import EventEmitter

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pure function: confidence extraction (D-01, D-02, D-03)
# ---------------------------------------------------------------------------


def extract_confidence(content: str, finish_reason: str) -> float:
    """Extract the model's self-reported confidence score.

    Primary: parse JSON, look for confidence_score field (float 0.0-1.0).
    Fallback: heuristic based on finish_reason and content length.

    Contract E2 note: the returned value is self-reported and MUST NOT
    alone drive auto-accept at the gate. The model has every incentive
    to inflate this number. The auto-accept branch in :func:`make_gate_step`
    now requires an independent, evidence-derived corroboration signal
    (see :func:`_has_corroboration`); self-report is discounted -- it
    can still be MEDIUM/LOW/REJECT-mapped and still feeds the calibrator,
    but on its own it cannot clear the HIGH auto-accept bar.

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


def _has_corroboration(ctx: dict[str, Any]) -> bool:
    """Return True when the gate sees an evidence-derived corroborating signal.

    Contract E1 seam: HIGH self-reported confidence alone MUST NOT
    auto-accept. This helper reports whether an independent, non-self-
    reported signal is available at gate time. The gate step consults
    it before honouring the ``level == "HIGH"`` auto-accept branch;
    when no corroboration is present, HIGH is downgraded to the flag
    path (Contract E1).

    Real signals available at gate time (post-call, post-validate step
    per :data:`aila.platform.llm.pipeline.POST_CALL_STEPS`):

    * ``ctx["evidence_validation"]`` -- the ``EvidenceValidationReport``
      dict written by :func:`aila.platform.llm.validate.make_validate_step`.
      Corroborates only when ``overall_pass`` is True, at least one
      citation was validated (``citations_valid >= 1``), and no citation
      was flagged as hallucinated. Empty reports (validators registered
      but nothing to check) and reports containing a hallucination are
      NOT corroboration.
    * ``ctx["corroboration_confirmed"]`` -- a boolean an upstream caller
      writes when the response is backed by a prior confirmed hypothesis
      or a verifier-confirmed verdict on the same claim (Contract C1/C2
      wiring on the caller side). The gate treats ``True`` as a real
      corroborating signal; any other value (missing, None, False) is
      not corroboration.
    """
    report = ctx.get("evidence_validation")
    if isinstance(report, dict):
        try:
            citations_valid = int(report.get("citations_valid") or 0)
            citations_hallucinated = int(
                report.get("citations_hallucinated") or 0
            )
        except (TypeError, ValueError):
            citations_valid = 0
            citations_hallucinated = 1
        if (
            bool(report.get("overall_pass"))
            and citations_valid >= 1
            and citations_hallucinated == 0
        ):
            return True
    if ctx.get("corroboration_confirmed") is True:
        return True
    return False


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


async def _apply_calibration(
    config_provider: LLMConfigProvider,
    task_type: str,
    raw_score: float,
) -> float:
    """Recalibrate ``raw_score`` via the active post-hoc calibrator.

    Contract C6 seam: sits between :func:`extract_confidence` and
    :func:`_resolve_thresholds` in the gate hot path. Applied
    unconditionally whenever an active
    :class:`CalibratorVersionRecord` exists for ``task_type``; when no
    active row is present the raw score is returned unchanged so the
    gate stays safe before any fit lands.

    Never raises: any DB / config lookup fault degrades to raw-
    passthrough (logged inside :func:`load_active_calibrator`). The
    length-heuristic fallback inside :func:`extract_confidence` is
    preserved; the calibrator sits AFTER it and reshapes the number the
    extractor already produced.
    """
    del config_provider
    from aila.platform.eval.calibrator import load_active_calibrator

    calibrator = await load_active_calibrator(task_type)
    if calibrator is None:
        return raw_score
    try:
        return float(calibrator.apply(raw_score))
    except (ValueError, TypeError, ArithmeticError) as exc:
        logger.warning(
            "_apply_calibration: apply failed for task_type=%s (%s); "
            "returning raw score",
            task_type, type(exc).__name__, exc_info=exc,
        )
        return raw_score


async def _resolve_thresholds(
    config_provider: LLMConfigProvider,
    task_type: str,
    outcome_kind: str | None = None,
) -> tuple[float, float, float]:
    """Read gate thresholds from ConfigRegistry.

    Returns (high, medium, reject) tuple with defaults (0.8, 0.5, 0.2).

    Calibration override: when a promoted
    :class:`aila.platform.eval.calibration.CalibrationProposalRecord`
    has written a live value into
    ``platform.calibration_threshold_{outcome_kind}`` (or, when the
    caller has no outcome_kind on hand, into
    ``platform.calibration_threshold_{task_type}``), that value
    replaces the per-task-type ``reject_threshold``. The write side is
    :func:`aila.api.routers.admin_eval.promote_calibration_proposal`,
    which stores ``proposal.after_threshold`` under
    ``platform.calibration_threshold_{proposal.outcome_kind}`` --
    identical key shape, so an operator whose proposal ``outcome_kind``
    matches either the current LLM ``task_type`` or a per-call
    ``outcome_kind`` supplied by the pipeline binds the promotion to
    the live reject/accept decision here. Absent the key the gate is
    byte-identical to the pre-calibration path.
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

    high = await _get_float("high_threshold", 0.8)
    medium = await _get_float("medium_threshold", 0.5)
    reject = await _get_float("reject_threshold", 0.2)

    # Live calibration threshold: prefer an explicit outcome_kind (the
    # per-call dimension the write side keys on) and fall back to
    # task_type so a gate call without an outcome_kind still resolves
    # against an operator-tuned override.
    calibration_val: Any = None
    if outcome_kind:
        calibration_val = await registry.get(
            "platform", f"calibration_threshold_{outcome_kind}",
        )
    if calibration_val is None:
        calibration_val = await registry.get(
            "platform", f"calibration_threshold_{task_type}",
        )
    if calibration_val is not None:
        try:
            override = float(calibration_val)
        except (ValueError, TypeError):
            override = None  # type: ignore[assignment]
        else:
            # Clamp into a sane range; keep medium >= override so the
            # LOW-band consensus path still has room to fire when the
            # operator has raised the reject floor above the default
            # medium threshold.
            if 0.0 <= override <= 1.0:
                reject = override
                if medium < reject:
                    medium = reject
                if high < medium:
                    high = medium

    return high, medium, reject


async def _resolve_bool_flag(
    config_provider: LLMConfigProvider,
    task_type: str,
    key_stem: str,
    *,
    default: bool,
) -> bool:
    """Read a ConfigRegistry boolean flag scoped by task_type.

    Reads ``platform.{key_stem}_{task_type}`` first, then
    ``platform.{key_stem}`` (unscoped fallback). Any registry outage
    or parse failure degrades to ``default`` so a config-plane fault
    can never flip a truth-safety knob silently.
    """
    registry = config_provider._registry
    for key in (f"{key_stem}_{task_type}", key_stem):
        try:
            raw = await registry.get("platform", key)
        except (OSError, RuntimeError, ValueError, TypeError, AttributeError):
            continue
        if raw is None:
            continue
        if isinstance(raw, bool):
            return raw
        if isinstance(raw, (int, float)):
            return bool(raw)
        if isinstance(raw, str):
            token = raw.strip().lower()
            if token in {"0", "false", "no", "off"}:
                return False
            if token in {"1", "true", "yes", "on"}:
                return True
    return default


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
    inner_call: Callable[..., Awaitable[Any]],
    config_provider: LLMConfigProvider,
    routing: LLMRouting,
    messages: list[dict[str, Any]],
    original_score: float,
    medium_threshold: float,
    run_id: str | None = None,
    team_id: str | None = None,
) -> tuple[Any, float] | None:
    """Run consensus retry calls and compute majority vote.

    §101: each retry routes through ``AilaLLMClient._inner_call`` so the
    consensus tokens land in the same cost ledger as the primary call.
    The inner_call bypasses the pipeline by design (no recursive gate).

    Args:
        inner_call: Async callable that issues a single LLM call WITHOUT
            triggering the pipeline. Wired to AilaLLMClient._inner_call.
        config_provider: For reading consensus config.
        routing: Original routing from the pipeline call.
        messages: Original message list.
        original_score: Confidence score of the original response.
        medium_threshold: Score threshold for "passing" in majority vote.
        run_id: Run identifier for cost accounting (carried through to
            ``persist_cost_record``).

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

        try:
            resp = await inner_call(
                routing=consensus_routing,
                messages=messages,
                response_format=None,
                tools=None,
                tool_executor=None,
                run_id=run_id,
                team_id=team_id,
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
    inner_call: Callable[..., Awaitable[Any]],
    emitter: EventEmitter | None = None,
) -> Any:
    """Create the gate pipeline step closure.

    The returned async callable matches the StepFn protocol:
    ``async def step(ctx, messages, routing) -> None``.

    Args:
        config_provider: LLMConfigProvider for threshold/config reads.
        inner_call: Async callable that issues a single LLM call WITHOUT
            triggering the pipeline. Wired to
            :meth:`AilaLLMClient._inner_call` so the consensus retries
            charge against the same cost ledger as the primary call
            (fix §101).
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

        # Extract confidence score (raw)
        raw_score = extract_confidence(content, finish_reason)

        # C6: post-hoc recalibration. Passes through when no active
        # calibrator exists for the task_type (safe before any fit
        # ships); applied unconditionally otherwise.
        score = await _apply_calibration(
            config_provider, routing.task_type, raw_score,
        )

        # Read thresholds from config. ``ctx["outcome_kind"]`` is the
        # per-call dimension that :func:`_resolve_thresholds` prefers
        # when resolving a promoted calibration threshold; callers that
        # know the outcome kind their call feeds set it upstream, and
        # every other caller falls back to the task-type key.
        ctx_outcome_kind = ctx.get("outcome_kind")
        outcome_kind_val = (
            str(ctx_outcome_kind) if ctx_outcome_kind else None
        )
        high, medium, reject = await _resolve_thresholds(
            config_provider, routing.task_type, outcome_kind_val,
        )

        # Map to level
        level = _map_confidence_level(score, high, medium, reject)

        # Contract E1: HIGH self-report alone MUST NOT auto-accept. When
        # no independent evidence-derived signal corroborates the response,
        # downgrade HIGH to the MEDIUM flag path so a reviewer sees it
        # instead of it slipping through as auto-accepted. See
        # :func:`_has_corroboration` for what counts as a real signal.
        corroborated = _has_corroboration(ctx)
        if level == "HIGH" and not corroborated:
            level = "MEDIUM"
            ctx["high_downgraded_no_corroboration"] = True
        ctx["confidence"] = level
        ctx["corroboration_present"] = corroborated

        # Issue .run/issues/26_uncertainty_stack.md /
        # .run/vr_truth_uncertainty_stack.md: the historical gate
        # re-sampled the HONEST tail (LOW self-report) and waved the
        # OVERCONFIDENT tail (uncorroborated HIGH) through untouched.
        # In a 75%-false-positive domain that inversion optimises for
        # false positives. Contract E1 (see :func:`_has_corroboration`)
        # already downgrades an uncorroborated HIGH to MEDIUM and marks
        # ``ctx["high_downgraded_no_corroboration"]``; the resample-
        # target inversion consumes that marker as the re-sample entry
        # point instead of the LOW branch alone.
        should_consensus_from_high_downgrade = (
            ctx.get("high_downgraded_no_corroboration") is True
            and await _resolve_bool_flag(
                config_provider, routing.task_type,
                "llm_pipeline_gate_resample_downgraded_high",
                default=True,
            )
        )

        async def _consensus_pass(reason: str) -> None:
            ctx["consensus_attempted"] = True
            ctx["consensus_reason"] = reason
            strategy, _, retries = await _resolve_consensus_config(
                config_provider, routing.task_type,
            )
            ctx["consensus_retries"] = retries
            ctx["consensus_strategy"] = strategy

            result = await _run_consensus(
                inner_call=inner_call,
                config_provider=config_provider,
                routing=routing,
                messages=messages,
                original_score=score,
                medium_threshold=medium,
                run_id=ctx.get("run_id") or None,
                team_id=ctx.get("team_id") or None,
            )
            if result is None:
                return
            winner_resp, winner_raw = result
            # C6: the consensus winner's raw score also flows through
            # the calibrator so downstream thresholding sees a
            # consistently-shaped number regardless of which branch
            # produced it.
            winner_score = await _apply_calibration(
                config_provider, routing.task_type, winner_raw,
            )
            ctx["response"] = winner_resp
            new_level = _map_confidence_level(
                winner_score, high, medium, reject,
            )
            # Contract E1 (centralized clamp): a consensus-driven HIGH is
            # still self-report -- multiple agreeing re-draws are not an
            # independent, evidence-derived signal (see
            # :func:`_has_corroboration`). Without corroboration the
            # ceiling stays MEDIUM regardless of which branch entered
            # consensus (a bare LOW self-report OR a downgraded,
            # uncorroborated HIGH), so the overconfident tail can never
            # auto-accept on self-report alone -- the false-positive path
            # #272 closes, now enforced for the LOW branch too.
            if new_level == "HIGH" and not _has_corroboration(ctx):
                new_level = "MEDIUM"
                ctx["consensus_high_capped_no_corroboration"] = True
            ctx["confidence"] = new_level
            ctx["consensus_winner_score"] = winner_score
            ctx["consensus_winner_raw_score"] = winner_raw

        # Route by level
        if level == "HIGH":
            pass  # Auto-accept, no extra work
        elif level == "MEDIUM":
            ctx["confidence_flagged"] = True
            # Inverted target: an uncorroborated HIGH (downgraded to
            # MEDIUM by the E1 gate above) is what the consensus loop
            # SHOULD re-draw -- the model reported high confidence and
            # produced no evidence to back it, exactly the tail the
            # spec's 75% false-positive base rate flags as most likely
            # wrong. Route it through the same retry machinery the LOW
            # branch uses.
            if should_consensus_from_high_downgrade:
                # E1 invariant is enforced centrally inside
                # ``_consensus_pass``: a re-sampled uncorroborated HIGH
                # may push DOWN but can never re-promote to auto-accept
                # HIGH on self-report alone. The same clamp now guards
                # the LOW branch below.
                await _consensus_pass(
                    reason="high_downgraded_no_corroboration",
                )
        elif level == "LOW":
            # Consensus retry -- honest low-confidence self-report.
            # Kept because a bare LOW with no better option still needs
            # sample-variance reduction, but the inversion above means
            # the LOW branch no longer carries the whole burden.
            await _consensus_pass(reason="low_self_report")
        elif level == "REJECT":
            # Emit audit event before raising
            _emit_gate_event(ctx, routing, score, level, emitter)
            raise ConfidenceRejectedError(
                f"Response rejected: confidence {score:.2f} below threshold {reject}"
            )

        # Build pipeline_metadata. ``raw_confidence_score`` is what
        # :func:`extract_confidence` produced pre-calibration;
        # ``confidence_score`` is what the gate acted on post-calibration.
        # The pair lets an audit reconstruct calibrator drift without
        # replaying the fit set.
        gate_meta: dict[str, Any] = {
            "raw_confidence_score": raw_score,
            "confidence_score": score,
            "confidence_level": ctx["confidence"],
            "flagged": ctx.get("confidence_flagged", False),
            "consensus_attempted": ctx.get("consensus_attempted", False),
            "consensus_retries": ctx.get("consensus_retries", 0),
            "consensus_strategy": ctx.get("consensus_strategy", ""),
            "consensus_reason": ctx.get("consensus_reason", ""),
            "consensus_winner_score": ctx.get("consensus_winner_score"),
            "consensus_winner_raw_score": ctx.get("consensus_winner_raw_score"),
            "corroboration_present": ctx.get("corroboration_present", False),
            "high_downgraded_no_corroboration": ctx.get(
                "high_downgraded_no_corroboration", False
            ),
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
