"""Per-run LLM cost tracking via RunMemory (Phase 122).

Accumulates prompt_tokens and completion_tokens per run_id using the
platform's RunMemory key-value store.  Budget enforcement reads the
ceiling from ConfigRegistry at check time (zero caching) and raises
BudgetExceededError when the run's total tokens exceed the limit.

Standalone calls (run_id=None) are recorded under a ``_no_run`` sentinel
and are never budget-checked.

Phase 175 additions (D-02, D-04a, D-05):
  calculate_cost_usd  -- dollar amount from ConfigRegistry operator pricing
  persist_cost_record -- durable LLMCostRecord write (fire-and-forget)
  emit_missing_pricing_notification -- one-time operator warning per model
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

import sqlalchemy.exc

from .errors import BudgetExceededError
from .run_memory import RunMemory

if TYPE_CHECKING:
    from ...storage.registry import ConfigRegistry

_log = logging.getLogger(__name__)

_KEY_PROMPT = "_cost_prompt_tokens"
_KEY_COMPLETION = "_cost_completion_tokens"
_NO_RUN = "_no_run"


class CostTracker:
    """Accumulates per-run token usage and enforces budget ceilings.

    Args:
        run_memory: RunMemory instance for per-run storage.
        registry: ConfigRegistry instance for budget ceiling reads.
    """

    def __init__(self, run_memory: RunMemory, registry: ConfigRegistry) -> None:
        self._mem = run_memory
        self._registry = registry

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record(self, run_id: str | None, usage: dict[str, int]) -> None:
        """Add token counts from one LLM call to the run's accumulator.

        Args:
            run_id: The run identifier, or None for standalone calls.
            usage: Dict with optional ``prompt_tokens`` and ``completion_tokens``.
        """
        rid = run_id or _NO_RUN
        prompt = usage.get("prompt_tokens", 0)
        completion = usage.get("completion_tokens", 0)

        current_prompt: int = self._mem.get(rid, _KEY_PROMPT, 0)
        current_completion: int = self._mem.get(rid, _KEY_COMPLETION, 0)

        self._mem.put(rid, _KEY_PROMPT, current_prompt + prompt)
        self._mem.put(rid, _KEY_COMPLETION, current_completion + completion)

    # ------------------------------------------------------------------
    # Reading
    # ------------------------------------------------------------------

    def get_usage(self, run_id: str | None) -> dict[str, int]:
        """Return accumulated token counts for a run.

        Args:
            run_id: The run identifier, or None for standalone calls.

        Returns:
            Dict with ``prompt_tokens``, ``completion_tokens``, ``total_tokens``.
        """
        rid = run_id or _NO_RUN
        prompt: int = self._mem.get(rid, _KEY_PROMPT, 0)
        completion: int = self._mem.get(rid, _KEY_COMPLETION, 0)
        return {
            "prompt_tokens": prompt,
            "completion_tokens": completion,
            "total_tokens": prompt + completion,
        }

    # ------------------------------------------------------------------
    # Budget enforcement
    # ------------------------------------------------------------------

    def check_budget(self, run_id: str | None, task_type: str) -> None:
        """Raise BudgetExceededError if the run's token usage exceeds ceiling.

        Skips enforcement for standalone calls (``_no_run``).
        Skips enforcement when ceiling is 0 (unlimited).

        Args:
            run_id: The run identifier, or None for standalone calls.
            task_type: Used to resolve per-task-type ceiling from config.

        Raises:
            BudgetExceededError: When accumulated total_tokens >= ceiling.
        """
        rid = run_id or _NO_RUN
        if rid == _NO_RUN:
            return

        ceiling = self._resolve_ceiling(task_type)
        if ceiling <= 0:
            return

        usage = self.get_usage(run_id)
        total = usage["total_tokens"]
        if total >= ceiling:
            raise BudgetExceededError(
                f"LLM budget exceeded for run {rid}: "
                f"{total}/{ceiling} tokens used. Partial results preserved."
            )

    def _resolve_ceiling(self, task_type: str) -> int:
        """Read budget ceiling from ConfigRegistry.

        Looks up ``llm_budget_max_total_tokens_{task_type}`` in the
        ``platform`` namespace.  Returns 0 (unlimited) if the key is
        missing or cannot be converted to int.
        """
        raw = self._registry.get("platform", f"llm_budget_max_total_tokens_{task_type}")
        if raw is None:
            return 0
        try:
            return int(raw)
        except (ValueError, TypeError):
            return 0


# ---------------------------------------------------------------------------
# Phase 175: Dollar calculation + durable persistence + pricing notification
# ---------------------------------------------------------------------------


async def calculate_cost_usd(
    model_id: str,
    prompt_tokens: int,
    completion_tokens: int,
    registry: ConfigRegistry,
) -> tuple[float, bool]:
    """Calculate LLM call cost in USD from operator-configured pricing.

    Looks up ``llm_cost_per_1k_prompt_{model_id}`` and
    ``llm_cost_per_1k_completion_{model_id}`` from ConfigRegistry
    (namespace "platform").  ConfigRegistry.get() is async -- MUST await.

    Args:
        model_id: The model identifier (e.g. "gpt-4o").
        prompt_tokens: Number of prompt/input tokens used.
        completion_tokens: Number of completion/output tokens used.
        registry: ConfigRegistry instance for pricing key lookups.

    Returns:
        Tuple of (cost_usd, pricing_configured):
          - cost_usd: Dollar amount, or 0.0 when pricing is unconfigured.
          - pricing_configured: True when both keys were found and valid;
            False when either key was missing, non-numeric, or negative
            (T-175-01 mitigation -- reject negative prices).
    """
    prompt_key = f"llm_cost_per_1k_prompt_{model_id}"
    completion_key = f"llm_cost_per_1k_completion_{model_id}"

    try:
        prompt_price_raw = await registry.get("platform", prompt_key)
        completion_price_raw = await registry.get("platform", completion_key)
    except sqlalchemy.exc.SQLAlchemyError:
        return (0.0, False)

    if prompt_price_raw is None or completion_price_raw is None:
        return (0.0, False)

    try:
        prompt_price = float(prompt_price_raw)
        completion_price = float(completion_price_raw)
    except (ValueError, TypeError):
        return (0.0, False)

    # T-175-01: reject negative prices (operator config tampering guard)
    if prompt_price < 0 or completion_price < 0:
        return (0.0, False)

    cost = (prompt_tokens / 1000.0) * prompt_price + (completion_tokens / 1000.0) * completion_price
    return (cost, True)


def _make_preview(text: str | None, limit: int = 200) -> str | None:
    """Truncate a prompt/response string for the admin interaction log.

    Returns None when the source is None or empty so the column stays NULL
    instead of storing the empty string -- keeps the UI honest about what
    was actually captured.
    """
    if text is None:
        return None
    stripped = text.strip()
    if not stripped:
        return None
    if len(stripped) <= limit:
        return stripped
    return stripped[:limit] + "…"


async def persist_cost_record(
    *,
    run_id: str | None,
    model_id: str,
    task_type: str,
    team_id: str | None,
    prompt_tokens: int,
    completion_tokens: int,
    cost_usd: float,
    registry: ConfigRegistry | None = None,
    prompt_preview: str | None = None,
    response_preview: str | None = None,
    duration_ms: int | None = None,
    status: str = "ok",
) -> None:
    """Write a durable LLMCostRecord to PostgreSQL, then trigger budget check.

    Fire-and-forget: DB failures are logged as warnings and never re-raised
    (T-175-03 mitigation -- DB write failure must not block the LLM call).

    After successfully writing the cost record, calls check_monthly_budget for
    the team (Phase 175 / D-03).  The budget check is also fire-and-forget --
    its own exceptions are swallowed inside check_monthly_budget.

    When registry is None (backward-compatible callers), the budget check is
    skipped entirely.

    Args:
        run_id: Run identifier; defaults to "_no_run" when None.
        model_id: The model identifier used for the call.
        task_type: The task_type routing key (e.g. "scoring").
        team_id: Team identifier for RLS scoping; may be None for admin calls.
        prompt_tokens: Prompt token count from LLM response usage.
        completion_tokens: Completion token count from LLM response usage.
        cost_usd: Dollar cost computed by calculate_cost_usd (0.0 if unconfigured).
        registry: Optional ConfigRegistry for monthly budget ceiling lookups.
            When provided and team_id is not None, triggers check_monthly_budget
            after the cost record is committed.
    """
    try:
        from aila.platform.llm.cost_record import LLMCostRecord
        from aila.storage.database import async_session_scope

        record = LLMCostRecord(
            run_id=run_id or "_no_run",
            model_id=model_id,
            task_type=task_type or "",
            team_id=team_id,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            cost_usd=cost_usd,
            prompt_preview=_make_preview(prompt_preview),
            response_preview=_make_preview(response_preview),
            duration_ms=duration_ms,
            status=status or "ok",
        )

        async with async_session_scope() as session:
            session.add(record)
            await session.commit()

        # Budget check runs after successful commit (D-03).
        # check_monthly_budget is fire-and-forget -- handles its own exceptions.
        if team_id is not None and registry is not None:
            from aila.platform.llm.budget_alert import check_monthly_budget
            await check_monthly_budget(team_id, registry)
    except sqlalchemy.exc.SQLAlchemyError:
        _log.warning(
            "persist_cost_record_failed",
            extra={
                "run_id": run_id,
                "model_id": model_id,
                "task_type": task_type,
            },
        )


async def emit_missing_pricing_notification(model_id: str) -> None:
    """Emit a one-time operator warning when pricing is not configured for a model.

    Deduplication: uses source_entity_id = "pricing_missing:{model_id}" so
    only one notification is created per model regardless of how many calls
    are made (D-04a).

    user_id="__system__" because NotificationRecord.user_id is required and
    non-nullable; no __team__ pattern exists in the codebase (per plan research).

    Failures are swallowed -- missing pricing warning must never block an LLM call.

    Args:
        model_id: The model identifier that is missing pricing config.
    """
    try:
        from sqlmodel import select

        from aila.storage.database import async_session_scope
        from aila.storage.db_models import NotificationRecord

        source_entity_id = f"pricing_missing:{model_id}"

        async with async_session_scope() as session:
            existing = (
                await session.exec(
                    select(NotificationRecord).where(
                        NotificationRecord.source_entity_id == source_entity_id
                    )
                )
            ).first()

            if existing is not None:
                return

            notification = NotificationRecord(
                user_id="__system__",
                title=f"Configure LLM pricing for {model_id}",
                body=(
                    f"No pricing configuration found for model '{model_id}'. "
                    f"LLM calls will record $0.00 cost until pricing is configured. "
                    f"Set 'llm_cost_per_1k_prompt_{model_id}' and "
                    f"'llm_cost_per_1k_completion_{model_id}' in platform config "
                    f"to enable accurate cost tracking."
                ),
                category="warning",
                source_module="llm_cost",
                source_entity_id=source_entity_id,
            )
            session.add(notification)
            await session.commit()
    except sqlalchemy.exc.SQLAlchemyError:
        _log.warning(
            "emit_missing_pricing_notification_failed",
            extra={"model_id": model_id},
        )
