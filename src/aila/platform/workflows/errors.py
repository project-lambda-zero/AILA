"""Exception types for the durable workflows engine.

Design notes:
  - `WorkflowConflictError` is NOT in any `retriable_on` set (D-32). It propagates
    past the engine to ARQ, which treats it as a bare exception and retries the
    whole job. The next attempt reloads the cursor and discovers the new version,
    so there is no split-brain between competing workers.
  - `ServiceBuildError` wraps the original exception raised by
    `WorkflowServices.build()` (D-45). The engine catches service-build failures
    and transitions to `spec.on_failure` (or the reserved `__crashed__` state).
  - `UnknownNextStateError` is raised when a handler returns a `StateResult`
    whose `next_state` is neither in `definition.states` nor a reserved terminal
    (T-178-07). Treated by the engine as non-retriable.
"""
from __future__ import annotations


class WorkflowConflictError(Exception):
    """Raised by cursor save when 0 rows updated (stale version).

    NOT in any retriable_on set -- propagates to ARQ as a bare exception;
    ARQ retries the job; next attempt reloads the cursor and discovers the
    new version (no split-brain). See CONTEXT D-32.

    Message carries no sensitive data (Phase 178 security fix): the engine
    raises it with the generic string ``"Concurrent workflow modification
    detected"`` and logs ``run_id`` / ``loaded_version`` via structlog at
    warning level. Callers that need correlation data should read the log.
    """


class WorkflowStepLimitExceeded(Exception):
    """Raised when a single ``execute`` call performs too many state
    transitions in one ARQ job (``MAX_STEPS_PER_JOB``).

    Protects against a malformed definition whose handlers loop forever
    (e.g., A -> B -> A) without reaching a terminal state. Treated as
    non-retriable: the engine transitions to ``__crashed__`` with a
    typed origin.
    """


class WorkflowSafeMessage(Exception):
    """Marker base class for exceptions whose ``str(exc)`` is safe to
    persist in the audit log verbatim (Phase 178 security fix).

    By default the engine records ``type(exc).__name__`` in audit rows to
    avoid leaking PII / secrets through handler exception messages.
    Handler authors who want the full message preserved must raise an
    exception that inherits from ``WorkflowSafeMessage``. Inheritance is
    opt-in and explicit so the default path is safe.
    """


class ServiceBuildError(Exception):
    """Raised by the engine when `WorkflowServices.build()` fails (D-45).

    Wraps the original exception. The engine uses this class name so the
    audit log row carries a distinct `error_class="ServiceBuildError"`.
    Treated as non-retriable: transition goes straight to `on_failure`.
    """


class UnknownNextStateError(ValueError):
    """Raised when a handler returns a StateResult with an unknown `next_state`.

    Covers T-178-07: handler escape via crafted StateResult. The engine
    treats this as a non-retriable exception and transitions to
    `spec.on_failure` (or `__crashed__`).
    """
