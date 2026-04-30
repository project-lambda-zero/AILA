"""LLM subsystem error types.

LLMError is the base for all LLM-related failures.
LLMDisabledError signals the kill switch is active -- callers receive this
when ConfigRegistry has llm_kill_switch=True.  It is NOT raised as an
exception; the client returns it as a structured error response (per D-08).
"""

from __future__ import annotations


class LLMError(Exception):
    """Base exception for LLM subsystem failures.

    Attributes:
        message: Human-readable error description.
        retryable: True if the caller should retry (transient failure).
    """

    def __init__(self, message: str, *, retryable: bool = False) -> None:
        super().__init__(message)
        self.message = message
        self.retryable = retryable


class LLMDisabledError(LLMError):
    """Kill switch is active -- all LLM calls are disabled by operator.

    This error carries a standard message and is never retryable.
    """

    def __init__(self) -> None:
        super().__init__("LLM disabled by operator", retryable=False)


class ClassificationBlockedError(LLMError):
    """RESTRICTED data detected and fail-closed behavior is configured.

    This error is ALWAYS re-raised by the pipeline regardless of fail_mode.
    It represents an intentional block, not an unexpected failure.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message, retryable=False)


class ConfidenceRejectedError(LLMError):
    """Response confidence below reject threshold -- intentional discard.

    Always propagated by the pipeline regardless of fail_mode setting,
    same as ClassificationBlockedError.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message, retryable=False)


class BudgetExceededError(LLMError):
    """Budget ceiling exceeded for a scan run -- intentional hard stop.

    NOT retryable.  The agent/module receiving this error should catch it
    and preserve partial results.
    """

    def __init__(self, message: str) -> None:
        super().__init__(message, retryable=False)


class LLMTransientError(LLMError):
    """Retriable LLM client failure (rate limit with retry-after, 503, 504).

    Matched by ``StateSpec.retriable_on`` for routing, operation_selection,
    scoring, and report states in the Phase 180 vulnerability workflow so the
    durable workflow engine replays the handler instead of transitioning to
    ``__failed__``.  Callers translate provider-specific transient exceptions
    (e.g. ``anthropic.RateLimitError`` carrying ``retry-after``) into this
    typed wrapper so the engine's retry policy is uniform across providers.
    """

    def __init__(
        self,
        message: str = "",
        *,
        retry_after_s: float | None = None,
    ) -> None:
        super().__init__(message, retryable=True)
        self.retry_after_s = retry_after_s
