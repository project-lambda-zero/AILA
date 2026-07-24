"""VR ClaimVerifierAgent -- adversarial verification of canonical-outcome claims.

Thin subclass of :class:`aila.platform.agents.claim_verifier.ClaimVerifierAgentBase`.
The three-stage pipeline (extractor LLM -> parallel audit-mcp probes ->
verdict LLM), the negative-claim guard, the verifier-report persist,
and the auto-promote + revert live on the platform base. This module
supplies the vr wiring:

* task-type routing keys for the extractor and verdict stages,
* the vr negative-finding phrase tables (kept module-local so
  cross-module reuse is opt-in on the platform side),
* the vr SQLModel record classes and the vr ``OutcomeDispatcher``,
* the auto-promote gate constants (ASSESSMENT_REPORT -> DIRECT_FINDING),
* the extractor's ``payload["answer"]`` claim-text extraction and the
  auto-promote negative-claim source (also ``payload["answer"]``),
* the vr ``ConfigRegistry`` binding for
  ``claim_verifier_auto_promote_floor`` and the vr mcp call recorder.

Idempotency: skips when ``verifier_report`` is already present in the
canonical outcome's payload. Triggered post-synthesis from
``investigation_emit._maybe_trigger_synthesis``.
"""
from __future__ import annotations

import logging
from collections.abc import Callable
from typing import Any

from aila.modules.vr.agents.outcome_dispatcher import OutcomeDispatcher
from aila.modules.vr.contracts import OutcomeDispatchStatus, OutcomeKind
from aila.modules.vr.db_models import (
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
    VRTargetRecord,
)
from aila.modules.vr.services.config_helpers import get_float
from aila.modules.vr.services.mcp_call_logger import record_call
from aila.modules.vr.services.outcome_review import OUTCOME_STATE_APPROVED
from aila.platform.agents.claim_verifier import (
    ClaimVerifierAgentBase,
)
from aila.platform.agents.claim_verifier import (
    is_negative_finding_claim as _platform_is_negative_finding_claim,
)

__all__ = ["ClaimVerifierAgent", "is_negative_finding_claim"]

_log = logging.getLogger(__name__)

# VR-domain negative-claim vocabulary. Kept module-local so the platform
# base's phrase-table hook is passed the right set for vr and no other
# module inherits vr's exact vocabulary by accident. Malware carries its
# own superset in ``modules/malware/agents/claim_verifier.py``.
_NEGATIVE_ANSWER_PREFIXES: tuple[str, ...] = (
    "NEGATIVE",
    "NOT VULNERABLE",
    "NO BUG",
    "NO VULNERABILITY",
    "NO FINDING",
    "PATCH PRESENT",
    "PATCH IS IN PLACE",
    "VARIANT DEAD",
    "VARIANT IS DEAD",
    "NO VARIANTS",
    "VULNERABILITY DOES NOT APPLY",
    "NOT EXPLOITABLE IN PRACTICE",
    "THE ISSUE IS MITIGATED",
)

# Substring matchers for descriptive negative claims that don't always
# start at character 0 (see platform base for the head-window rules).
_NEGATIVE_ANSWER_SUBSTRINGS: tuple[str, ...] = (
    "NO EXPLOITABLE CONDITION REACHES HERE",
    "THE ISSUE IS MITIGATED",
    "VULNERABILITY DOES NOT APPLY",
    "NOT EXPLOITABLE IN PRACTICE",
    "PATCH IS IN PLACE",
)


def is_negative_finding_claim(answer: str) -> bool:
    """VR-scoped negative-claim gate.

    Thin wrapper over the platform helper: passes the vr phrase tables
    through. Kept as a module-level function so existing import sites
    (``from aila.modules.vr.agents.claim_verifier import is_negative_finding_claim``)
    keep working after the platform lift.
    """
    return _platform_is_negative_finding_claim(
        answer,
        prefixes=_NEGATIVE_ANSWER_PREFIXES,
        substrings=_NEGATIVE_ANSWER_SUBSTRINGS,
    )


class ClaimVerifierAgent(ClaimVerifierAgentBase):
    """Three-stage adversarial verifier for the vr module."""

    # Task-type diversity: each stage gets its own task_type so operators
    # can route them to a different model via ConfigRegistry keys
    # ``llm_model_vulnerability_research.verifier_extractor`` and
    # ``llm_model_vulnerability_research.verifier_verdict``. Until those
    # keys are populated they fall back to ``llm_default_model``;
    # routing the verdict stage to a different model is the meaningful
    # follow-up.
    _EXTRACTOR_TASK_TYPE = "vulnerability_research.verifier_extractor"
    _VERDICT_TASK_TYPE = "vulnerability_research.verifier_verdict"

    _NEGATIVE_ANSWER_PREFIXES = _NEGATIVE_ANSWER_PREFIXES
    _NEGATIVE_ANSWER_SUBSTRINGS = _NEGATIVE_ANSWER_SUBSTRINGS

    _investigation_model = VRInvestigationRecord
    _outcome_model = VRInvestigationOutcomeRecord
    _target_model = VRTargetRecord
    _outcome_dispatcher_cls = OutcomeDispatcher

    _promote_source_kind = OutcomeKind.ASSESSMENT_REPORT.value
    _promote_target_kind = OutcomeKind.DIRECT_FINDING.value
    _promote_wrong_kind_reason = "outcome_kind_not_assessment"
    _promote_negative_skip_reason = "answer_starts_negative_no_bug_to_promote"
    _dispatch_status_pending = OutcomeDispatchStatus.PENDING.value
    _dispatch_status_skipped = OutcomeDispatchStatus.SKIPPED.value
    _outcome_state_approved = OUTCOME_STATE_APPROVED

    async def _read_auto_promote_floor(self) -> float:
        """Read the vr-namespaced auto-promote floor via ConfigRegistry."""
        return await get_float("claim_verifier_auto_promote_floor")

    def _bridge_recorder(self) -> Callable[..., Any]:
        """The vr mcp call recorder -- probe traffic attributed to vr."""
        return record_call

    def _extract_claim_text(
        self, canonical_kind: str, canonical_payload: dict[str, Any],
    ) -> str:
        """VR reads the free-form ``answer`` field directly.

        The vr outcome payload is a flat ``{"answer": "..."}`` shape
        across every outcome kind, so the kind argument does not gate
        which field is read.
        """
        del canonical_kind
        return str(canonical_payload.get("answer") or "")

    def _promote_negative_claim_text(
        self, orig_payload: dict[str, Any],
    ) -> str:
        """The auto-promote negative-claim gate reads ``payload["answer"]``."""
        return str(orig_payload.get("answer") or "")
