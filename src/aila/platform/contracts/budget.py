from __future__ import annotations

import logging

from pydantic import BaseModel, ConfigDict, Field

__all__ = [
    "BudgetConfig",
    "BudgetState",
]

_log = logging.getLogger(__name__)

# Divergence factor above/below which BudgetState.reconcile_actual_cost logs
# an operator warning that ``cost_per_turn_usd`` is stale relative to what the
# LLM cost ledger has actually charged. Both directions are surfaced so an
# operator can tune the prior toward the observed spend.
_COST_DIVERGENCE_FACTOR = 2.0


class BudgetConfig(BaseModel):
    """Dual budget configuration: turn count + cumulative tool time.

    Reusable by any module running multi-turn LLM loops with expensive tool
    calls. The turn budget bounds reasoning depth; the tool-time budget bounds
    wall-clock work spent in long-running tools (decompilation, symbolic
    execution, scans). Extensions add fixed increments to both ceilings.
    """

    model_config = ConfigDict(extra="forbid")

    max_turns: int = 30
    max_tool_time_seconds: float = 14400.0  # 4 hours
    auto_waive_recommended_at: float = 0.8  # waive RECOMMENDED obligations at 80% turns
    extension_turns: int = 15
    extension_tool_time_seconds: float = 7200.0  # 2 hours
    # A-priori estimate: dollars per turn used before any measured cost has
    # landed. Once ``BudgetState.actual_cost_usd`` becomes positive (via
    # ``record_cost`` or ``reconcile_actual_cost``), ``estimated_cost_usd``
    # prefers the measured value and this prior is used only as a fallback.
    # 0.0 keeps the pre-measurement estimate silent instead of misleading.
    cost_per_turn_usd: float = 0.0


class BudgetState(BaseModel):
    """Mutable dual-budget tracker.

    Records consumption and grants extensions. Pure value type -- persistence
    is the caller's responsibility via `to_json` / `from_json`. Concurrent
    mutation is the caller's responsibility (typically owned by a single
    workflow run).
    """

    model_config = ConfigDict(extra="forbid")

    config: BudgetConfig = Field(default_factory=BudgetConfig)
    turns_used: int = 0
    tool_time_used_seconds: float = 0.0
    extensions_granted: int = 0
    # Measured USD spend accumulated by ``record_cost`` (per-call) and by
    # ``reconcile_actual_cost`` (durable-ledger sync). Grows monotonically so
    # a stale/partial ledger read can never clobber in-flight per-call
    # charges. Fixes issue #38: the turn-based budget and the token-based
    # cost tracker now reconcile through this field.
    actual_cost_usd: float = 0.0

    @property
    def _max_turns(self) -> int:
        return self.config.max_turns + self.extensions_granted * self.config.extension_turns

    @property
    def _max_tool_time_seconds(self) -> float:
        return (
            self.config.max_tool_time_seconds
            + self.extensions_granted * self.config.extension_tool_time_seconds
        )

    @property
    def turns_remaining(self) -> int:
        return max(0, self._max_turns - self.turns_used)

    @property
    def tool_time_remaining_seconds(self) -> float:
        return max(0.0, self._max_tool_time_seconds - self.tool_time_used_seconds)

    @property
    def turn_fraction(self) -> float:
        """0.0 to 1.0+ -- how much of the turn budget is consumed."""
        max_turns = self._max_turns
        if max_turns <= 0:
            return 1.0
        return self.turns_used / max_turns

    @property
    def exhausted(self) -> bool:
        """True if either budget is fully consumed."""
        return self.turns_remaining <= 0 or self.tool_time_remaining_seconds <= 0.0

    @property
    def should_waive_recommended(self) -> bool:
        """True when turn fraction >= auto-waive threshold."""
        return self.turn_fraction >= self.config.auto_waive_recommended_at

    def record_turn(self) -> None:
        """Charge one turn against the turn budget."""
        self.turns_used += 1

    def record_tool_time(self, seconds: float) -> None:
        """Charge tool wall-clock time against the tool-time budget."""
        if seconds < 0.0:
            raise ValueError("tool time delta must be non-negative")
        self.tool_time_used_seconds += seconds

    def grant_extension(self) -> None:
        """Grant one extension -- bumps both ceilings, leaves consumption alone."""
        self.extensions_granted += 1

    def record_cost(self, usd: float) -> None:
        """Charge a measured LLM call cost against the actual-spend accumulator.

        Callers that already computed a per-call dollar amount (typically via
        ``aila.platform.llm.cost.calculate_cost_usd``) forward it here so
        ``estimated_cost_usd`` and ``effective_cost_per_turn_usd`` surface
        real spend instead of the pre-measurement prior. Non-negative;
        a zero (pricing-not-configured) charge is a no-op accumulator hit.
        """
        if usd < 0.0:
            raise ValueError("cost delta must be non-negative")
        self.actual_cost_usd += usd

    def reconcile_actual_cost(self, ledger_total_usd: float) -> None:
        """Reconcile the actual-cost accumulator against a durable-ledger sum.

        Monotonic: only raises ``actual_cost_usd``, so a stale or partial
        LLM cost ledger read cannot lower a total that per-call
        :meth:`record_cost` calls have already grown past.

        When the configured prior ``cost_per_turn_usd`` diverges from the
        measured per-turn rate by more than :data:`_COST_DIVERGENCE_FACTOR`
        in either direction, logs a warning so an operator can retune the
        prior toward observed spend. The warning fires only once the ledger
        has both a positive total and at least one recorded turn.
        """
        if ledger_total_usd < 0.0:
            return
        if ledger_total_usd > self.actual_cost_usd:
            self.actual_cost_usd = ledger_total_usd

        prior = self.config.cost_per_turn_usd
        if prior > 0.0 and self.turns_used > 0 and self.actual_cost_usd > 0.0:
            observed_per_turn = self.actual_cost_usd / self.turns_used
            ratio = observed_per_turn / prior
            if ratio >= _COST_DIVERGENCE_FACTOR or ratio <= 1.0 / _COST_DIVERGENCE_FACTOR:
                _log.warning(
                    "budget_state.cost_per_turn_usd_diverged prior=%.6f observed=%.6f ratio=%.2f turns=%d",
                    prior, observed_per_turn, ratio, self.turns_used,
                )

    @property
    def effective_cost_per_turn_usd(self) -> float:
        """Real average USD-per-turn from measured spend, or the prior fallback.

        Returns the ledger-derived rate once at least one turn has been
        charged AND a measured cost has landed; otherwise falls back to
        ``config.cost_per_turn_usd`` so callers reading this before the
        first LLM call completes still get the pre-measurement estimate.
        """
        if self.turns_used > 0 and self.actual_cost_usd > 0.0:
            return self.actual_cost_usd / self.turns_used
        return self.config.cost_per_turn_usd

    @property
    def estimated_cost_usd(self) -> float:
        """Best-known run cost in USD.

        Prefers measured ``actual_cost_usd`` (grown by ``record_cost`` /
        ``reconcile_actual_cost``); falls back to ``turns_used *
        cost_per_turn_usd`` when no measurement has landed yet.
        """
        if self.actual_cost_usd > 0.0:
            return self.actual_cost_usd
        return self.turns_used * self.config.cost_per_turn_usd

    def summary_for_prompt(self) -> str:
        """One-line status for the LLM system prompt.

        Examples:
          'Turn 7/30. Tool time: 2h14m remaining. Cost: $1.40.'  # measured
          'Turn 7/30. Tool time: 2h14m remaining. Est. cost: $1.40.'  # prior
        """
        base = (
            f"Turn {self.turns_used}/{self._max_turns}. "
            f"Tool time: {_format_duration(self.tool_time_remaining_seconds)} remaining."
        )
        cost = self.estimated_cost_usd
        if cost > 0.0:
            label = "Cost" if self.actual_cost_usd > 0.0 else "Est. cost"
            base += f" {label}: ${cost:.2f}."
        return base

    def to_json(self) -> dict:
        """JSON-serializable snapshot for workflow state persistence."""
        return self.model_dump(mode="json")

    @classmethod
    def from_json(cls, data: dict) -> BudgetState:
        """Reconstruct from a persisted snapshot."""
        return cls.model_validate(data)


def _format_duration(seconds: float) -> str:
    """Render seconds as compact 'XhYm' / 'Ym' for prompt display."""
    total = int(max(0.0, seconds))
    hours, rem = divmod(total, 3600)
    minutes = rem // 60
    if hours:
        return f"{hours}h{minutes}m"
    return f"{minutes}m"
