"""Service implementations for the template module.

Domain services -- anything that owns records this module writes -- live
here. A copier renames each ``Template`` / ``template`` binding to the
new module's identifier and prunes services the module does not need.

The platform ships parameterized generics for every investigation-shape
support service so a new module composes them rather than copying a peer
module's implementation (RFC-04). Every primitive below is generic over
the caller's record models, enums, and configuration namespace; each
binding file in this package hands the template's residue to the
platform generic at wiring time. The barrel re-export makes the bound
symbols importable off ``aila.modules._template.services`` (mirrors the
vr / malware surface).

Config surface: subclass
:class:`aila.platform.config_base.ModuleConfigBase` in ``config_schema.py``
so ``extra='forbid'`` is inherited (rule 37, ``module_config_schema_base``).
Typed reads route through :class:`aila.platform.config_base.ModuleConfigReader`
bound to the ``"template"`` namespace at each caller module (per RFC-04:
the old ``services/config_helpers.py`` shim was deleted and replaced by
a module-level reader instance inside each consuming file).

The honesty audit's ``service_copy_of_platform`` rule (38) treats a
module service file whose normalized content mirrors a platform service
file as a finding; import the platform generic, do not copy it.
"""
from __future__ import annotations

from .branch_cleanup import close_orphan_branches_on_terminal
from .branch_reaper import sweep_orphan_active_branches
from .investigation_finalizers import (
    abandon_stale_branches,
    abandon_stale_branches_impl,
    close_rejected_for_investigation,
    close_rejected_outcomes,
    synthesize_no_finding_for_investigation,
    synthesize_no_finding_outcomes,
)
from .investigation_reaper import (
    evaluate_cap_for_investigation,
    sweep_cap_exceeded_investigations,
)
from .machine_readiness import (
    MachineReadinessService,
    ReadinessResult,
    ToolCheckResult,
)
from .mcp_call_logger import record_call
from .mcp_registry import (
    MCP_SERVERS,
    MODULE_CAPABILITIES,
    SERVER_CAPABILITY_DEFAULTS,
    McpRegistryService,
    get_descriptors,
)
from .multi_target import MultiTargetService, MultiTargetServiceError
from .outcome_review import (
    OUTCOME_STATE_APPROVED,
    OUTCOME_STATE_DISPATCHED,
    OUTCOME_STATE_DRAFT,
    OUTCOME_STATE_REJECTED,
    VOTE_ABSTAIN,
    VOTE_APPROVE,
    VOTE_NOT_READY,
    VOTE_REJECT,
    VOTE_REQUEST_EDIT,
    compute_quorum,
    evaluate_quorum,
    post_draft_review_request,
    set_outcome_state,
    summarize_outcome_for_review,
    upsert_review,
)
from .pattern_store import PatternRetrievalResult, PatternStore, PatternStoreError
from .stage_tracker import (
    StageAlreadyDoneError,
    StageInFlightError,
    StageTracker,
    StageTrackerError,
    load_target_stages,
    parse_stages,
    reap_stuck_stages,
    save_target_stages,
)
from .stall_recovery import (
    StallRecoveryResult,
    SubmitFn,
    sweep_stalled_investigations,
)

__all__ = [
    "MCP_SERVERS",
    "MODULE_CAPABILITIES",
    "MachineReadinessService",
    "McpRegistryService",
    "MultiTargetService",
    "MultiTargetServiceError",
    "OUTCOME_STATE_APPROVED",
    "OUTCOME_STATE_DISPATCHED",
    "OUTCOME_STATE_DRAFT",
    "OUTCOME_STATE_REJECTED",
    "PatternRetrievalResult",
    "PatternStore",
    "PatternStoreError",
    "ReadinessResult",
    "SERVER_CAPABILITY_DEFAULTS",
    "StageAlreadyDoneError",
    "StageInFlightError",
    "StageTracker",
    "StageTrackerError",
    "StallRecoveryResult",
    "SubmitFn",
    "ToolCheckResult",
    "VOTE_ABSTAIN",
    "VOTE_APPROVE",
    "VOTE_NOT_READY",
    "VOTE_REJECT",
    "VOTE_REQUEST_EDIT",
    "abandon_stale_branches",
    "abandon_stale_branches_impl",
    "close_orphan_branches_on_terminal",
    "close_rejected_for_investigation",
    "close_rejected_outcomes",
    "compute_quorum",
    "evaluate_cap_for_investigation",
    "evaluate_quorum",
    "get_descriptors",
    "load_target_stages",
    "parse_stages",
    "post_draft_review_request",
    "reap_stuck_stages",
    "record_call",
    "save_target_stages",
    "set_outcome_state",
    "summarize_outcome_for_review",
    "sweep_cap_exceeded_investigations",
    "sweep_orphan_active_branches",
    "sweep_stalled_investigations",
    "synthesize_no_finding_for_investigation",
    "synthesize_no_finding_outcomes",
    "upsert_review",
]
