"""Template draft-outcome review binding.

Mirrors :mod:`aila.modules.vr.services.outcome_review`: partial-binds the
platform vote/quorum kernel to the template's record models and to the
template's audit-stage label. Callers keep the ``set_outcome_state`` /
``upsert_review`` / ``evaluate_quorum`` / ``post_draft_review_request``
surface unchanged; the platform generic owns the transition body.
"""
from __future__ import annotations

from functools import partial

from aila.modules._template.db_models import (
    TemplateInvestigationBranchRecord,
    TemplateInvestigationMessageRecord,
    TemplateInvestigationOutcomeRecord,
    TemplateInvestigationOutcomeReviewRecord,
)
from aila.platform.services.outcome_review import (
    OUTCOME_STATE_APPROVED,
    OUTCOME_STATE_DISPATCHED,
    OUTCOME_STATE_DRAFT,
    OUTCOME_STATE_REJECTED,
    VOTE_ABSTAIN,
    VOTE_APPROVE,
    VOTE_NOT_READY,
    VOTE_REJECT,
    VOTE_REQUEST_EDIT,
    QuorumOutcome,
    compute_quorum,
    summarize_outcome_for_review,
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
    "VOTE_NOT_READY",
    "VOTE_REJECT",
    "VOTE_REQUEST_EDIT",
    "compute_quorum",
    "evaluate_quorum",
    "post_draft_review_request",
    "set_outcome_state",
    "summarize_outcome_for_review",
    "upsert_review",
]

_AUDIT_STAGE = "template.outcome"
# Single-reject veto -- match vr's historical default. A copier tunes
# this when the module wants a chorus of rejects before vetoing.
_VETO_K = 1

set_outcome_state = partial(
    _platform_set_outcome_state,
    audit_stage=_AUDIT_STAGE,
)

upsert_review = partial(
    _platform_upsert_review,
    outcome_model=TemplateInvestigationOutcomeRecord,
    branch_model=TemplateInvestigationBranchRecord,
    outcome_review_model=TemplateInvestigationOutcomeReviewRecord,
)

evaluate_quorum = partial(
    _platform_evaluate_quorum,
    outcome_model=TemplateInvestigationOutcomeRecord,
    branch_model=TemplateInvestigationBranchRecord,
    outcome_review_model=TemplateInvestigationOutcomeReviewRecord,
    veto_k=_VETO_K,
    audit_stage=_AUDIT_STAGE,
)

post_draft_review_request = partial(
    _platform_post_draft_review_request,
    message_model=TemplateInvestigationMessageRecord,
)

# ``QuorumOutcome`` is imported for module-local callers only; not
# re-exported to mirror the vr surface.
_ = QuorumOutcome
