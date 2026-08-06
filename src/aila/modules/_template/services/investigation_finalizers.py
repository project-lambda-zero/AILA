"""Template binding of the platform investigation finalizers.

Mirrors :mod:`aila.modules.vr.services.investigation_finalizers`. Binds
the platform generic finalizers to the template ORM record models, raw
table names, ``assessment_report`` outcome kind, and a template-shaped
no-finding payload via module-level :func:`functools.partial` bindings.
Callers keep the same call surface across modules
(``synthesize_no_finding_for_investigation(inv_id)`` etc.); each partial
is a stable object across re-imports so any downstream identity-keyed
registration (task registration, sweep-step reference) does not churn.

Config reads route through :class:`ModuleConfigReader` bound to the
``template`` namespace -- the ``stale_branch_frozen_min`` and
``stale_branch_halted_min`` keys resolve through the layered lookup
(``AILA_TEMPLATE_<KEY>`` env -> DB -> schema default).
"""
from __future__ import annotations

from functools import partial
from typing import Any

from aila.modules._template.db_models import (
    TemplateInvestigationBranchRecord,
    TemplateInvestigationOutcomeRecord,
    TemplateInvestigationOutcomeReviewRecord,
    TemplateInvestigationRecord,
)
from aila.platform.config_base import ModuleConfigReader
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


_TEMPLATE_BRANCH_TABLE = "template_investigation_branches"
_TEMPLATE_OUTCOME_TABLE = "template_investigation_outcomes"
# Copier picks the module's real terminal-narrative outcome kind. The
# template ships a single ``assessment_report`` shape so orphan-close
# rows adopt that kind by default.
_TEMPLATE_NO_FINDING_OUTCOME_KIND = "assessment_report"

# Module-level shared reader for the platform finalizer's stale-branch
# threshold reads. Keeping one instance per module avoids scattering
# the ``"template"`` namespace string across the binding surface.
_config_reader = ModuleConfigReader("template")


def _build_template_no_finding_payload(
    *,
    summary_text: str,
    per_branch: list[dict[str, Any]],
    total_turns: int,
    now_iso: str,
) -> dict[str, Any]:
    """Build the template no-finding payload for an orphan-close outcome.

    ``total_turns`` is intentionally unused in this payload shape (the
    per-branch turn breakdown already lives under ``branches``). The
    parameter is part of the platform builder contract so every module
    sees the same context.
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
    investigation_model=TemplateInvestigationRecord,
    branch_model=TemplateInvestigationBranchRecord,
    branch_table=_TEMPLATE_BRANCH_TABLE,
    outcome_table=_TEMPLATE_OUTCOME_TABLE,
    no_finding_outcome_kind=_TEMPLATE_NO_FINDING_OUTCOME_KIND,
    build_no_finding_payload=_build_template_no_finding_payload,
)

close_rejected_outcomes = partial(
    _platform_close_rejected_outcomes,
    investigation_model=TemplateInvestigationRecord,
    branch_model=TemplateInvestigationBranchRecord,
    outcome_model=TemplateInvestigationOutcomeRecord,
    outcome_review_model=TemplateInvestigationOutcomeReviewRecord,
)

abandon_stale_branches_impl = partial(
    _platform_abandon_stale_branches_impl,
    branch_model=TemplateInvestigationBranchRecord,
    get_int=_config_reader.get_int,
)

close_rejected_for_investigation = partial(
    _platform_close_rejected_for_investigation,
    investigation_model=TemplateInvestigationRecord,
    branch_model=TemplateInvestigationBranchRecord,
    outcome_model=TemplateInvestigationOutcomeRecord,
    outcome_review_model=TemplateInvestigationOutcomeReviewRecord,
)

synthesize_no_finding_for_investigation = partial(
    _platform_synthesize_no_finding_for_investigation,
    investigation_model=TemplateInvestigationRecord,
    branch_model=TemplateInvestigationBranchRecord,
    branch_table=_TEMPLATE_BRANCH_TABLE,
    outcome_table=_TEMPLATE_OUTCOME_TABLE,
    no_finding_outcome_kind=_TEMPLATE_NO_FINDING_OUTCOME_KIND,
    build_no_finding_payload=_build_template_no_finding_payload,
)

abandon_stale_branches = partial(
    _platform_abandon_stale_branches,
    branch_model=TemplateInvestigationBranchRecord,
    get_int=_config_reader.get_int,
)
