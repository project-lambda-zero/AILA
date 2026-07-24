"""VR binding of the platform draft outcome review service.

Binds the platform generic vote/quorum kernel to the VR record models via
module-level ``functools.partial``. The exported callables retain stable
identity across re-imports and preserve the module's historical public surface:

* the four ``OUTCOME_STATE_*`` constants + the four ``VOTE_*`` constants,
* :func:`compute_quorum` (pure, no model dependency),
* :func:`set_outcome_state`, :func:`upsert_review`, :func:`evaluate_quorum`,
  :func:`post_draft_review_request` -- all pre-bound to
  :class:`VRInvestigationOutcomeRecord`, :class:`VRInvestigationBranchRecord`,
  :class:`VRInvestigationOutcomeReviewRecord`,
  :class:`VRInvestigationMessageRecord`, and to VR's historical
  ``veto_k=1`` (single reject vetoes) + ``audit_stage="vr.outcome"``.

VR does not expose the direct ``edit_outcome`` action; the malware module's
binding does. See :mod:`aila.platform.services.outcome_review` for the
generic kernel and the full lifecycle documentation.
"""
from __future__ import annotations

from functools import partial

from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationMessageRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationOutcomeReviewRecord,
)
from aila.platform.services.outcome_review import (
    OUTCOME_STATE_APPROVED,
    OUTCOME_STATE_DISPATCHED,
    OUTCOME_STATE_DRAFT,
    OUTCOME_STATE_REJECTED,
    VOTE_ABSTAIN,
    VOTE_APPROVE,
    VOTE_REJECT,
    VOTE_REQUEST_EDIT,
    QuorumOutcome,
    compute_quorum,
)
from aila.platform.services.outcome_review import (
    evaluate_quorum as _platform_evaluate_quorum,
)
from aila.platform.services.outcome_review import (
    post_draft_review_request as _platform_post_draft_review_request,
)
from aila.platform.services.outcome_review import (
    set_outcome_state as _platform_set_outcome_state,
)
from aila.platform.services.outcome_review import (
    upsert_review as _platform_upsert_review,
)

__all__ = [
    "OUTCOME_STATE_APPROVED",
    "OUTCOME_STATE_DISPATCHED",
    "OUTCOME_STATE_DRAFT",
    "OUTCOME_STATE_REJECTED",
    "VOTE_ABSTAIN",
    "VOTE_APPROVE",
    "VOTE_REJECT",
    "VOTE_REQUEST_EDIT",
    "compute_quorum",
    "evaluate_quorum",
    "post_draft_review_request",
    "set_outcome_state",
    "upsert_review",
]

# Module-scoped audit stage label + veto threshold. VR historically used
# a single-reject veto (``veto_k=1``): one sibling reject flips the
# outcome to REJECTED. The audit_stage lands on every AuditEventRecord
# row emitted by this module's outcome path so an operator querying by
# stage sees only VR rows.
_AUDIT_STAGE = "vr.outcome"
_VETO_K = 1

set_outcome_state = partial(
    _platform_set_outcome_state,
    audit_stage=_AUDIT_STAGE,
)

upsert_review = partial(
    _platform_upsert_review,
    outcome_model=VRInvestigationOutcomeRecord,
    branch_model=VRInvestigationBranchRecord,
    outcome_review_model=VRInvestigationOutcomeReviewRecord,
)

evaluate_quorum = partial(
    _platform_evaluate_quorum,
    outcome_model=VRInvestigationOutcomeRecord,
    branch_model=VRInvestigationBranchRecord,
    outcome_review_model=VRInvestigationOutcomeReviewRecord,
    veto_k=_VETO_K,
    audit_stage=_AUDIT_STAGE,
)

post_draft_review_request = partial(
    _platform_post_draft_review_request,
    message_model=VRInvestigationMessageRecord,
)

# QuorumOutcome is imported from the platform above so it stays importable
# off this module for legacy callers, matching the pre-Phase-1 surface. It
# is intentionally kept out of __all__.
