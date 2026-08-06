"""Forensics binding of the platform draft-outcome review service (#18).

Binds the platform generic vote/quorum kernel (RFC-04) to the forensics
panel record models via module-level :func:`functools.partial`. The
exported callables retain stable identity across re-imports and mirror
the shape VR + malware use.

Introduced in #18 alongside the panel + sibling-review-quorum spine. The
forensics module previously ran a single Think-Act-Observe agent with no
per-role branching or vote gating; this binding wires the platform quorum
kernel so a submitted finding must clear a sibling review before it can
dispatch.

See :mod:`aila.platform.services.outcome_review` for the generic kernel
and the full draft outcome lifecycle documentation.
"""
from __future__ import annotations

from functools import partial

from aila.modules.forensics.db_models import (
    ForensicsInvestigationBranchRecord,
    ForensicsInvestigationMessageRecord,
    ForensicsInvestigationOutcomeRecord,
    ForensicsInvestigationOutcomeReviewRecord,
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
    "VOTE_REJECT",
    "VOTE_REQUEST_EDIT",
    "compute_quorum",
    "evaluate_quorum",
    "post_draft_review_request",
    "set_outcome_state",
    "summarize_outcome_for_review",
    "upsert_review",
]

# Module-scoped audit stage label + veto threshold.
#
# ``veto_k=1`` matches VR's historical single-reject veto: one sibling
# reject flips the outcome to REJECTED. Forensic findings share the same
# "kill fast on a single well-argued objection" bar -- a single sibling
# who says "the evidence chain is broken" or "this isn't the smoking gun
# the branch claims" is enough to send the draft back.
#
# The audit stage lands on every AuditEventRecord row emitted by this
# module's outcome path so an operator querying by stage sees only
# forensics rows.
_AUDIT_STAGE = "forensics.outcome"
_VETO_K = 1

set_outcome_state = partial(
    _platform_set_outcome_state,
    audit_stage=_AUDIT_STAGE,
)

upsert_review = partial(
    _platform_upsert_review,
    outcome_model=ForensicsInvestigationOutcomeRecord,
    branch_model=ForensicsInvestigationBranchRecord,
    outcome_review_model=ForensicsInvestigationOutcomeReviewRecord,
)

evaluate_quorum = partial(
    _platform_evaluate_quorum,
    outcome_model=ForensicsInvestigationOutcomeRecord,
    branch_model=ForensicsInvestigationBranchRecord,
    outcome_review_model=ForensicsInvestigationOutcomeReviewRecord,
    veto_k=_VETO_K,
    audit_stage=_AUDIT_STAGE,
)

post_draft_review_request = partial(
    _platform_post_draft_review_request,
    message_model=ForensicsInvestigationMessageRecord,
)

# QuorumOutcome is imported from the platform above so it stays importable
# off this module for legacy callers, matching the pre-Phase-1 surface. It
# is intentionally kept out of __all__.
