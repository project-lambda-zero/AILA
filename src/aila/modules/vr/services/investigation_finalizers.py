"""VR binding of the platform investigation finalizers.

Binds the platform generic finalizers to the VR ORM record models,
raw table names, ``audit_memo`` outcome kind, and the VR-shaped
no-finding payload via module-level :func:`functools.partial`
bindings. Callers keep the same import site and call-signature they
have today (``synthesize_no_finding_for_investigation(inv_id)``,
``_synthesize_no_finding_outcomes(uow)``, etc.); each partial is a
stable object across re-imports so any downstream identity-keyed
registration (task registration, sweep-step reference) does not
churn.

The VR no-finding outcome is written as ``audit_memo`` with a
payload shape carrying ``verdict='no_finding'``, a per-branch trace
of persona / turns / closed_reason, and the standard
synthesized_by / synthesized_at / rule provenance fields.
"""
from __future__ import annotations

from functools import partial
from typing import Any

from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
)
from aila.modules.vr.db_models.outcome_review import (
    VRInvestigationOutcomeReviewRecord,
)
from aila.modules.vr.services.config_helpers import get_int as _vr_get_int
from aila.platform.services.investigation_finalizers import (
    abandon_stale_branches as _platform_abandon_stale_branches,
)
from aila.platform.services.investigation_finalizers import (
    abandon_stale_branches_impl as _platform_abandon_stale_branches_impl,
)
from aila.platform.services.investigation_finalizers import (
    close_rejected_for_investigation as _platform_close_rejected_for_investigation,
)
from aila.platform.services.investigation_finalizers import (
    close_rejected_outcomes as _platform_close_rejected_outcomes,
)
from aila.platform.services.investigation_finalizers import (
    synthesize_no_finding_for_investigation as _platform_synthesize_no_finding_for_investigation,
)
from aila.platform.services.investigation_finalizers import (
    synthesize_no_finding_outcomes as _platform_synthesize_no_finding_outcomes,
)

__all__ = [
    "abandon_stale_branches",
    "abandon_stale_branches_impl",
    "close_rejected_for_investigation",
    "close_rejected_outcomes",
    "synthesize_no_finding_for_investigation",
    "synthesize_no_finding_outcomes",
]


_VR_BRANCH_TABLE = "vr_investigation_branches"
_VR_OUTCOME_TABLE = "vr_investigation_outcomes"
_VR_NO_FINDING_OUTCOME_KIND = "audit_memo"


def _build_vr_no_finding_payload(
    *,
    summary_text: str,
    per_branch: list[dict[str, Any]],
    total_turns: int,
    now_iso: str,
) -> dict[str, Any]:
    """Build the VR ``audit_memo`` payload for an orphan-close outcome.

    ``total_turns`` is intentionally unused in the VR payload shape
    (the per-branch turn breakdown already lives under ``branches``).
    The parameter is part of the platform builder contract so both
    modules see the same context.
    """
    del total_turns
    return {
        "verdict": "no_finding",
        "summary": summary_text,
        "branches": per_branch,
        "synthesized_by": "investigation_finalizers.synthesize_no_finding_outcomes",
        "synthesized_at": now_iso,
        "rule": "every_investigation_has_outcome",
    }


synthesize_no_finding_outcomes = partial(
    _platform_synthesize_no_finding_outcomes,
    investigation_model=VRInvestigationRecord,
    branch_model=VRInvestigationBranchRecord,
    branch_table=_VR_BRANCH_TABLE,
    outcome_table=_VR_OUTCOME_TABLE,
    no_finding_outcome_kind=_VR_NO_FINDING_OUTCOME_KIND,
    build_no_finding_payload=_build_vr_no_finding_payload,
)

close_rejected_outcomes = partial(
    _platform_close_rejected_outcomes,
    investigation_model=VRInvestigationRecord,
    branch_model=VRInvestigationBranchRecord,
    outcome_model=VRInvestigationOutcomeRecord,
    outcome_review_model=VRInvestigationOutcomeReviewRecord,
)

abandon_stale_branches_impl = partial(
    _platform_abandon_stale_branches_impl,
    branch_model=VRInvestigationBranchRecord,
    get_int=_vr_get_int,
)

close_rejected_for_investigation = partial(
    _platform_close_rejected_for_investigation,
    investigation_model=VRInvestigationRecord,
    branch_model=VRInvestigationBranchRecord,
    outcome_model=VRInvestigationOutcomeRecord,
    outcome_review_model=VRInvestigationOutcomeReviewRecord,
)

synthesize_no_finding_for_investigation = partial(
    _platform_synthesize_no_finding_for_investigation,
    investigation_model=VRInvestigationRecord,
    branch_model=VRInvestigationBranchRecord,
    branch_table=_VR_BRANCH_TABLE,
    outcome_table=_VR_OUTCOME_TABLE,
    no_finding_outcome_kind=_VR_NO_FINDING_OUTCOME_KIND,
    build_no_finding_payload=_build_vr_no_finding_payload,
)

abandon_stale_branches = partial(
    _platform_abandon_stale_branches,
    branch_model=VRInvestigationBranchRecord,
    get_int=_vr_get_int,
)
