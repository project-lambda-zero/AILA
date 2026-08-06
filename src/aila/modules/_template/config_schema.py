"""Typed configuration schema for the template module.

Every module publishes its operator-tunable knobs through a Pydantic
model registered with the shared :class:`aila.storage.registry.ConfigRegistry`
under the module's own namespace. Subclassing
:class:`aila.platform.config_base.ModuleConfigBase` bakes in
``extra='forbid'`` so an undeclared or misspelled key fails closed at
construction instead of silently passing through -- the drift class of
failure RFC-04 closed for ``vulnerability`` and codified as honesty
audit rule 37 (``module_config_schema_base``).

Copiers replace the example fields below with the real knobs the new
module needs (rate limits, cache TTLs, external URLs, feature flags).
The registration wiring in :mod:`module.py` picks the schema up without
further platform edits.

The residue keys below back the investigation engine wiring the
template scaffold ships:

* ``max_turns_per_task`` -- per-loop-task turn cap (investigation_loop_base).
* ``overall_turn_cap`` -- cumulative branch turn ceiling (investigation_emit_base
  auto-continue guard).
* ``investigation_turn_cap`` / ``investigation_message_cap`` /
  ``investigation_wall_clock_hours`` / ``wall_clock_idle_grace_s`` --
  investigation-level cap enforcement in the emit state.
* ``tool_executor_hard_block_repeat`` -- refuse-repeat cap in the tool
  executor (fires HARD-BLOCK after N identical failing tool calls on
  the same branch).
* ``claim_verifier_auto_promote_floor`` -- confidence floor gating the
  claim verifier's auto-promote path.
"""
from __future__ import annotations

from pydantic import Field

from aila.platform.config_base import ModuleConfigBase

__all__ = ["TemplateConfigSchema"]


class TemplateConfigSchema(ModuleConfigBase):
    """Config keys the template investigation engine residue reads.

    Each annotated attribute becomes one typed key in the module's
    config namespace. ``extra='forbid'`` is inherited from
    :class:`ModuleConfigBase` so an operator ``PUT /config`` with an
    undeclared key raises at construction rather than silently succeeding.
    """

    # --- Example knobs (kept from the pre-agents scaffold) --------------
    example_timeout_seconds: float = Field(
        default=30.0,
        ge=0.0,
        description="Placeholder timeout knob; replace with a real setting.",
    )
    example_max_retries: int = Field(
        default=3,
        ge=0,
        description="Placeholder retry ceiling; replace with a real setting.",
    )

    # --- Investigation loop caps ---------------------------------------
    max_turns_per_task: int = Field(
        default=25,
        ge=1,
        description=(
            "Per-loop-task turn cap. investigation_loop exits when the "
            "researcher runs this many turns without a terminal submit; "
            "investigation_emit re-enqueues another task until "
            "overall_turn_cap trips."
        ),
    )
    overall_turn_cap: int = Field(
        default=200,
        ge=1,
        description=(
            "Cumulative per-branch turn ceiling. investigation_emit "
            "stops auto-continuing once the branch reaches this count."
        ),
    )

    # --- Investigation-level cap enforcement ---------------------------
    investigation_turn_cap: int = Field(
        default=1000,
        ge=1,
        description=(
            "Sum of live-branch turns above which investigation_emit "
            "halts every active branch + flips the investigation to "
            "COMPLETED with reason=investigation_turn_cap."
        ),
    )
    investigation_message_cap: int = Field(
        default=5000,
        ge=1,
        description=(
            "Total live-branch message count above which "
            "investigation_emit halts every active branch."
        ),
    )
    investigation_wall_clock_hours: float = Field(
        default=48.0,
        gt=0.0,
        description=(
            "Wall-clock ceiling (hours) since started_at above which "
            "investigation_emit halts every active branch, subject to "
            "the idle-grace escape hatch below."
        ),
    )
    wall_clock_idle_grace_s: float = Field(
        default=900.0,
        ge=0.0,
        description=(
            "Idle-grace window (seconds). A branch that updated within "
            "this window bypasses the wall-clock cap so a live audit "
            "is not killed mid-tool-call."
        ),
    )

    # --- Tool executor breaker -----------------------------------------
    tool_executor_hard_block_repeat: int = Field(
        default=3,
        ge=1,
        description=(
            "The tool executor refuses to re-dispatch an identical "
            "failing tool call once the same call has failed this many "
            "times on the same branch; sends the agent a HARD-BLOCK "
            "message telling it to change tool or args."
        ),
    )

    # --- Claim verifier auto-promote gate ------------------------------
    claim_verifier_auto_promote_floor: float = Field(
        default=0.9,
        ge=0.0,
        le=1.0,
        description=(
            "Confidence floor below which the claim verifier will NOT "
            "auto-promote an assessment report to a direct finding."
        ),
    )
