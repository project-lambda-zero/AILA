"""Template outcome dispatcher -- thin subclass of the platform base.

Routes an approved :class:`TemplateInvestigationOutcomeRecord` to its
downstream artifact. The template ships a single outcome kind
(``ASSESSMENT_REPORT``), which is terminal-no-downstream: the
dispatcher records SKIPPED with a stable reason so the platform emit
path stamps the outcome row cleanly.

A copier adds one branch per new outcome kind in :meth:`_handle_kind`
and (typically) an ``_persist_dispatch_status`` override that cascades
sibling-branch halt + investigation status flip + ARQ purge -- the vr
module is the reference for that richer shape.
"""
from __future__ import annotations

import logging
from typing import Any

from aila.modules._template.contracts.outcome import TemplateOutcomeKind
from aila.modules._template.db_models import TemplateInvestigationOutcomeRecord
from aila.modules._template.services.outcome_review import (
    OUTCOME_STATE_APPROVED,
    OUTCOME_STATE_DISPATCHED,
    OUTCOME_STATE_DRAFT,
    OUTCOME_STATE_REJECTED,
)
from aila.platform.agents.outcome_dispatcher import (
    OutcomeDispatcherBase,
    OutcomeDispatcherError,
    OutcomeDispatchResult,
)
from aila.platform.contracts.enums import OutcomeDispatchStatus
from aila.platform.services.knowledge import KnowledgeService

__all__ = [
    "OutcomeDispatchResult",
    "OutcomeDispatcher",
    "OutcomeDispatcherError",
]

_log = logging.getLogger(__name__)


class OutcomeDispatcher(OutcomeDispatcherBase):
    """Template-side outcome dispatcher scaffold."""

    _outcome_model = TemplateInvestigationOutcomeRecord
    _outcome_kind_cls = TemplateOutcomeKind
    _default_error_kind = TemplateOutcomeKind.ASSESSMENT_REPORT
    # Fold handler exceptions into a FAILED result so the platform base
    # emits a clean terminal row rather than re-raising to ARQ. Copy
    # this to ``False`` when the module wants a bad payload to force a
    # worker-level retry (the vr shape).
    _catch_handler_errors = True

    def __init__(self, knowledge: KnowledgeService | Any) -> None:
        self._knowledge = knowledge

    def _dispatch_state_guard(
        self, outcome: TemplateInvestigationOutcomeRecord,
    ) -> str | None:
        """Refuse dispatch of any outcome whose state is not approved."""
        state = outcome.state
        if state is None:
            raise OutcomeDispatcherError(
                f"outcome.state is NULL outcome_id={outcome.id}",
            )
        if state == OUTCOME_STATE_DRAFT:
            return "draft_awaiting_sibling_quorum"
        if state == OUTCOME_STATE_REJECTED:
            return "rejected_by_sibling_review"
        if state == OUTCOME_STATE_DISPATCHED:
            return "already_dispatched"
        if state != OUTCOME_STATE_APPROVED:
            raise OutcomeDispatcherError(
                f"unknown outcome state outcome_id={outcome.id} state={state!r}",
            )
        return None

    async def _handle_kind(
        self,
        *,
        outcome_kind: TemplateOutcomeKind,
        outcome_id: str,
        investigation_id: str,
        payload: dict[str, Any],
        outcome_row: TemplateInvestigationOutcomeRecord | None,
    ) -> OutcomeDispatchResult:
        """Route the winning claim -- template scaffold ships one kind."""
        del investigation_id, payload, outcome_row
        if outcome_kind is TemplateOutcomeKind.ASSESSMENT_REPORT:
            return OutcomeDispatchResult(
                outcome_id=outcome_id,
                outcome_kind=outcome_kind,
                dispatch_status=OutcomeDispatchStatus.SKIPPED,
                dispatch_target=None,
                reason="assessment_reports_are_terminal_no_downstream",
            )
        # A future kind added to the enum without a matching branch
        # here would silently return an empty SKIPPED. Raise so the
        # missing wiring surfaces on the first dispatch instead.
        raise OutcomeDispatcherError(
            f"unhandled outcome_kind={outcome_kind.value!r}; extend "
            "TemplateOutcomeDispatcher._handle_kind with a branch for it",
        )
