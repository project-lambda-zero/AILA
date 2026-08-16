"""Configuration schema for the forensics module.

Registered with ConfigRegistry under the ``forensics`` namespace.
Operators can tune these values via PUT /config without code changes.

NOTE: These defaults are used as fallbacks. The API-layer ``max_attempts``
parameter on InvestigationRequest takes priority when explicitly set.
The timeout values here define the upper bounds for SSH and collection
operations -- the workflow states in definitions.py reference these same
defaults. Changing config at runtime does NOT hot-reload into running
workflows, only new workflow runs pick up updated values.
"""
from __future__ import annotations

from pydantic import Field

from aila.platform.config_base import ModuleConfigBase

__all__ = ["ForensicsConfigSchema", "FORENSICS_DEFAULTS"]


class ForensicsConfigSchema(ModuleConfigBase):
    """Operator-tunable settings for the forensics module.

    ``llm_model`` is inherited from :class:`ModuleConfigBase` -- the
    forensics module's historical default matched the platform default
    (``PlatformConfigSchema.llm_default_model``), so no per-module
    override is needed.
    """

    freeflow_max_attempts: int = Field(
        default=10,
        ge=1,
        le=50,
        description="Maximum script execution attempts per free-flow investigation.",
    )
    ssh_command_timeout_seconds: float = Field(
        default=300.0,
        ge=10.0,
        description="Timeout for individual SSH commands on the analyzer machine.",
    )
    script_execution_timeout_seconds: float = Field(
        default=600.0,
        ge=30.0,
        description="Timeout for agent-generated script execution.",
    )
    collection_timeout_seconds: float = Field(
        default=3600.0,
        ge=60.0,
        description="Timeout for the full artifact collection pipeline.",
    )
    # RFC-04 C11e -- previously read from raw
    # ``AILA_FORENSICS_RETRIEVE_MAX_BYTES`` env at every call and ignored
    # PUT /config overrides. Routed through ConfigRegistry so operator
    # overrides land on the next call without a worker restart. Env form
    # is standardised to ``AILA_FORENSICS_RETRIEVE_MAX_BYTES`` (unchanged
    # spelling -- the layered lookup already accepts it).
    retrieve_max_bytes: int = Field(
        default=500 * 1024 * 1024,  # 500 MiB
        ge=1024,
        description=(
            "Per-retrieval byte cap the file_retriever service enforces "
            "on the analyzer-side script and on the SFTP pull back to the "
            "API host. Bodies past this cap fail retrieval so a huge "
            "malicious archive cannot OOM the worker."
        ),
    )
    freeflow_max_cost_usd: float = Field(
        default=25.0,
        ge=0.0,
        description=(
            "Hard per-investigation LLM spend ceiling in USD. When the sum "
            "of ``LLMCostRecord.cost_usd`` rows for ``run_id == "
            "investigation_id`` reaches this value the freeflow loop "
            "terminates cleanly with status ``exhausted`` and a "
            "``<budget_exhausted>`` final_answer marker. A value of 0.0 "
            "disables the ceiling (only the ``_HARD_TURN_CAP`` safety net "
            "remains). Freeflow_max_attempts and this ceiling are ANDed: "
            "whichever fires first halts the run."
        ),
    )


    # --- Reasoning closure pressure (issue #175 parity) -----------------
    unresolved_hyp_reject_cap: int = Field(
        default=3,
        ge=0,
        le=20,
        description=(
            "Cap on consecutive submit rejections by the unresolved-"
            "hypothesis gate on the same investigation. When the agent "
            "emits a terminal answer while live hypotheses remain "
            "unresolved, the gate converts the submit to a reasoning "
            "turn and injects a steering directive so the agent must "
            "explicitly reject each live hypothesis or fold it into the "
            "answer. After this many consecutive rejections the submit "
            "is forced through with an "
            "``unresolved_hypotheses_at_submit_advisory`` marker on the "
            "answer provenance so the operator can audit. A value of 0 "
            "disables the gate. Mirrors ``vr/unresolved_hyp_reject_cap``."
        ),
    )

    # --- RFC-07 #31 stuck-investigation healer ---------------------------
    stuck_healer_idle_grace_s: int = Field(
        default=600,
        ge=30,
        description=(
            "Idle grace before an investigation stuck at ``running`` is a "
            "candidate for the RFC-07 stuck-investigation healer, in "
            "seconds. Rows whose ``created_at`` is fresher than this are "
            "never touched so a slow turn is not mistaken for a stall. "
            "Env: AILA_FORENSICS_STUCK_HEALER_IDLE_GRACE_S."
        ),
    )
    stuck_healer_max_heals_per_tick: int = Field(
        default=5,
        ge=1,
        le=50,
        description=(
            "Per-tick cap on stuck-investigation re-enqueues so a mass "
            "backlog cannot saturate the task queue in one sweep. "
            "Env: AILA_FORENSICS_STUCK_HEALER_MAX_HEALS_PER_TICK."
        ),
    )


FORENSICS_DEFAULTS = ForensicsConfigSchema()
