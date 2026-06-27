from __future__ import annotations

from pydantic import BaseModel, Field

__all__ = [
    "BudgetConfig",
    "BudgetState",
]


class BudgetConfig(BaseModel):
    """Dual budget configuration: turn count + cumulative tool time.

    Reusable by any module running multi-turn LLM loops with expensive tool
    calls. The turn budget bounds reasoning depth; the tool-time budget bounds
    wall-clock work spent in long-running tools (decompilation, symbolic
    execution, scans). Extensions add fixed increments to both ceilings.
    """

    max_turns: int = 30
    max_tool_time_seconds: float = 14400.0  # 4 hours
    auto_waive_recommended_at: float = 0.8  # waive RECOMMENDED obligations at 80% turns
    extension_turns: int = 15
    extension_tool_time_seconds: float = 7200.0  # 2 hours
    cost_per_turn_usd: float = 0.0  # 0 = cost tracking disabled


class BudgetState(BaseModel):
    """Mutable dual-budget tracker.

    Records consumption and grants extensions. Pure value type -- persistence
    is the caller's responsibility via `to_json` / `from_json`. Concurrent
    mutation is the caller's responsibility (typically owned by a single
    workflow run).
    """

    config: BudgetConfig = Field(default_factory=BudgetConfig)
    turns_used: int = 0
    tool_time_used_seconds: float = 0.0
    extensions_granted: int = 0

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

    @property
    def estimated_cost_usd(self) -> float:
        """Estimated cost based on turns consumed multiplied by cost_per_turn_usd."""
        return self.turns_used * self.config.cost_per_turn_usd

    def summary_for_prompt(self) -> str:
        """One-line status for the LLM system prompt.

        Example: 'Turn 7/30. Tool time: 2h14m remaining. Est. cost: $1.40.'
        """
        base = (
            f"Turn {self.turns_used}/{self._max_turns}. "
            f"Tool time: {_format_duration(self.tool_time_remaining_seconds)} remaining."
        )
        if self.config.cost_per_turn_usd > 0:
            base += f" Est. cost: ${self.estimated_cost_usd:.2f}."
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
