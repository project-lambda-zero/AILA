"""Template claim verifier -- thin subclass of the platform base.

The three-stage adversarial pipeline (extractor LLM -> parallel audit-
mcp probes -> verdict LLM) plus the negative-claim guard, verifier-
report persist, and auto-promote/revert live on
:class:`aila.platform.agents.claim_verifier.ClaimVerifierAgentBase`.
This module supplies the template-scoped task-type keys, negative
phrase tables (initially empty), record models, config binding, and
the flat ``payload["answer"]`` claim-text accessor.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from aila.modules._template.agents.outcome_dispatcher import OutcomeDispatcher
from aila.modules._template.contracts.outcome import TemplateOutcomeKind
from aila.modules._template.db_models import (
    TemplateInvestigationOutcomeRecord,
    TemplateInvestigationRecord,
    TemplateTargetRecord,
)
from aila.modules._template.services.config_helpers import get_float
from aila.modules._template.services.outcome_review import OUTCOME_STATE_APPROVED
from aila.platform.agents.claim_verifier import ClaimVerifierAgentBase
from aila.platform.contracts.enums import OutcomeDispatchStatus

__all__ = ["ClaimVerifierAgent"]

_log = logging.getLogger(__name__)

# The template ships empty phrase tables so no answer prefix is
# treated as a negative finding by default. A copier populates these
# alongside the module's real outcome semantics (see vr's
# ``_NEGATIVE_ANSWER_PREFIXES`` / ``_NEGATIVE_ANSWER_SUBSTRINGS`` for
# the shape).
_NEGATIVE_ANSWER_PREFIXES: tuple[str, ...] = ()
_NEGATIVE_ANSWER_SUBSTRINGS: tuple[str, ...] = ()


def _template_record_call(*_args: Any, **_kwargs: Any) -> None:
    """No-op MCP call recorder for the template scaffold.

    A real module wires its ``services.mcp_call_logger.record_call`` so
    verifier probe traffic is attributed to the module dashboard.
    """


class ClaimVerifierAgent(ClaimVerifierAgentBase):
    """Template-scoped adversarial claim verifier."""

    _EXTRACTOR_TASK_TYPE = "template.verifier_extractor"
    _VERDICT_TASK_TYPE = "template.verifier_verdict"

    _NEGATIVE_ANSWER_PREFIXES = _NEGATIVE_ANSWER_PREFIXES
    _NEGATIVE_ANSWER_SUBSTRINGS = _NEGATIVE_ANSWER_SUBSTRINGS

    _investigation_model = TemplateInvestigationRecord
    _outcome_model = TemplateInvestigationOutcomeRecord
    _target_model = TemplateTargetRecord
    _outcome_dispatcher_cls = OutcomeDispatcher

    # The template ships a single terminal-narrative outcome kind, so
    # promotion is a no-op source -> target on the same kind; the
    # platform base still records the audit trail even though nothing
    # rewrites the row's ``outcome_kind`` value.
    _promote_source_kind = TemplateOutcomeKind.ASSESSMENT_REPORT.value
    _promote_target_kind = TemplateOutcomeKind.ASSESSMENT_REPORT.value
    _promote_wrong_kind_reason = "outcome_kind_not_promotable"
    _promote_negative_skip_reason = "answer_starts_negative_no_bug_to_promote"
    _dispatch_status_pending = OutcomeDispatchStatus.PENDING.value
    _dispatch_status_skipped = OutcomeDispatchStatus.SKIPPED.value
    _outcome_state_approved = OUTCOME_STATE_APPROVED

    async def _read_auto_promote_floor(self) -> float:
        """Read ``claim_verifier_auto_promote_floor`` via ConfigRegistry."""
        return await get_float("claim_verifier_auto_promote_floor")

    def _bridge_recorder(self) -> Callable[..., Any]:
        return _template_record_call

    def _extract_claim_text(
        self, canonical_kind: str, canonical_payload: dict[str, Any],
    ) -> str:
        """Template payload shape is flat ``{"answer": "..."}``."""
        del canonical_kind
        return str(canonical_payload.get("answer") or "")

    def _promote_negative_claim_text(
        self, orig_payload: dict[str, Any],
    ) -> str:
        return str(orig_payload.get("answer") or "")
