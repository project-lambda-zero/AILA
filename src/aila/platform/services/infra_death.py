"""Infra-death classifier for multi-turn investigation finalization.

Problem this closes (RFC-07, first increment):

The synthesize_no_finding_outcomes finalizer already skips synthesis
when the LLM is currently unhealthy AND already downgrades a zero-turn
investigation to FAILED (retryable) instead of writing a hollow
no-finding outcome. Neither guard catches the following live shape:

  * The investigation ran real turns (turn_count > 0).
  * Its trailing N turns died to an infra failure -- LLM timeout,
    rate-limit exhaustion, provider connection reset, or a stale-branch
    abandonment triggered by a bounded LLM outage window.
  * The LLM endpoint recovered BEFORE the finalizer tick fires.
  * The outer is_llm_recently_unhealthy() gate therefore reads healthy,
    the branches look "terminal" via abandoned closed_reason, and the
    finalizer writes a clean no-finding outcome that reads to the
    operator as "we audited and found nothing" instead of "the tail
    of the run died to infrastructure".

The classifier is intentionally PURE so the caller stays responsible
for gathering signals (branch turn totals, trailing error classes,
current llm-health snapshot). This keeps the finalizer control flow
transparent and the classifier trivially testable without a DB.

Return contract:
    "infra_death" -- caller must NOT synthesize a clean no-finding
                     outcome; instead mark the investigation FAILED
                     (retryable) with a distinct closed_reason so the
                     operator can reopen / re-enqueue.
    "terminal"    -- caller may proceed with the existing no-finding
                     synthesis path.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Literal

__all__ = [
    "InfraDeathClassifier",
    "InfraDeathVerdict",
    "RETRYABLE_INFRA_CLASSES",
]


# Error-class strings the classifier treats as infra failures. Sources:
#   * openai / provider client exception names surfaced through
#     WorkflowStateTransition.error_class ("APIConnectionError",
#     "APITimeoutError", "RateLimitError"). Provider-network transports
#     the aila LLM retry loop already treats as retryable per
#     aila.platform.llm.client._is_retryable.
#   * "LLMError" -- the platform wrapper raised with retryable=True
#     after the in-call retry budget is exhausted.
#   * "TimeoutError", "OSError", "ConnectionError" -- generic transport
#     and socket failures that surface identically for a wedged Redis
#     or Postgres session as for the LLM endpoint.
#   * "WorkflowConflictError" -- optimistic-lock loss during a turn is
#     the cursor engine's retryable signal (the whole task retries).
#   * "stale_no_progress" -- pseudo-class the finalizer feeds when a
#     branch's closed_reason starts with "stale_no_progress_"; the
#     stale-branch abandonment fires when a branch went dark, which
#     in practice means an LLM outage or a dispatcher failure earlier
#     in the run.
#
# The set is frozen at module load so callers cannot silently widen it.
RETRYABLE_INFRA_CLASSES: frozenset[str] = frozenset(
    {
        "APIConnectionError",
        "APITimeoutError",
        "ConnectionError",
        "LLMError",
        "OSError",
        "RateLimitError",
        "TimeoutError",
        "WorkflowConflictError",
        "stale_no_progress",
    }
)


InfraDeathVerdict = Literal["infra_death", "terminal"]


class InfraDeathClassifier:
    """Pure classifier: turn signals into a finalizer verdict.

    Constructed once per finalizer sweep tick; classify() is called per
    orphan-candidate investigation. Holds no state -- kept as a class
    so callers pin a stable object identity through their DI wiring
    and so a future increment (per-module tuning of the infra class
    set) has an obvious extension point.
    """

    def classify(
        self,
        *,
        branch_turn_count: int,
        recent_turn_errors: Sequence[str],
        llm_unhealthy_at_close: bool,
    ) -> InfraDeathVerdict:
        """Return "infra_death" when the tail of the run died to infra.

        branch_turn_count:
            Total reasoning turns the investigation actually completed
            (summed across its branches). The zero-turn case is owned
            by the finalizer's existing zero-turn guard -- treat 0 as
            "terminal" here so a caller that forgets the outer guard
            still degrades to the pre-classifier behaviour rather than
            silently masking every zero-turn run as infra_death.
        recent_turn_errors:
            Small ordered sequence of error-class strings observed on
            the tail turns / branch closed_reasons. Any string that
            appears in RETRYABLE_INFRA_CLASSES flips the verdict to
            infra_death.
        llm_unhealthy_at_close:
            The is_llm_recently_unhealthy() snapshot at the moment the
            finalizer is about to synthesize this specific outcome. The
            outer sweep also gates on this, so it is typically False by
            the time we reach here; when True (per-id path, race, or
            future callers that bypass the sweep gate) it is a hard
            infra_death signal.
        """
        # Zero-turn: the finalizer's existing zero-turn guard handles
        # this via a distinct FAILED close reason; if we somehow reach
        # here for a zero-turn candidate the safe default is to let the
        # caller's outer branch decide, not to relabel it infra_death.
        if branch_turn_count <= 0:
            return "terminal"

        if llm_unhealthy_at_close:
            return "infra_death"

        for err_class in recent_turn_errors:
            if err_class and err_class in RETRYABLE_INFRA_CLASSES:
                return "infra_death"

        return "terminal"
