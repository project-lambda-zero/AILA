"""Cancellation primitives for the LLM retry loop and tool bridges.

Phase B.5 of the cutover (operator-elective). The hard problem is
cancelling a single in-flight HTTP call mid-stream -- that requires
plumbing ``httpx.AsyncClient`` aclose() through every retry loop +
every tool bridge. The PARTIAL solution shipped here covers the 80%
case: cancellation at the retry boundary.

Mechanism:

* :class:`CancellationToken` holds a single ``asyncio.Event``.
  Cheap to check; safe across cancel-while-not-cancelled races.
* :func:`get_cancellation_token` returns a per-investigation token
  from a process-local registry. The pause task (Phase B) flips
  the token to ``cancelled`` when ``workflow_state_cursor.current_state``
  transitions to ``__paused__``. The LLM retry loop checks
  ``token.is_cancelled()`` between retries; on True it raises
  :class:`LLMCancelledError` which the engine's state handler
  treats as a clean exit (no retry, no FAILED transition).

Mid-call cancellation is deferred to Phase B.6 (separate engineering
pass -- requires aclose() threading + tool bridge cancel_scope hooks).
Today's behavior: in-flight LLM calls finish their current HTTP
request, but the NEXT retry attempt or NEXT tool dispatch aborts
immediately. Practical impact: pause → 30-60s for the current call
to finish → cancellation kicks in.

Token lifecycle:

  - Created lazily when ``get_cancellation_token(investigation_id)``
    is first called.
  - Cancelled by ``cancel_for_investigation(investigation_id)`` (the
    Phase B pause path calls this after committing the cursor flip).
  - Cleared by ``clear_for_investigation(investigation_id)`` (the
    Phase B resume path calls this so a subsequent pause produces
    a fresh token).
  - Process-local registry; ARQ workers and FastAPI processes each
    maintain their own. The cursor is the cross-process SSOT.
"""
from __future__ import annotations

import asyncio
import logging

__all__ = [
    "CancellationToken",
    "LLMCancelledError",
    "cancel_for_investigation",
    "clear_for_investigation",
    "get_cancellation_token",
    "token_registry_snapshot",
]

_log = logging.getLogger(__name__)


class LLMCancelledError(Exception):
    """Raised when the LLM retry loop observes a cancelled token.

    Engine-state-handler-friendly: callers should catch this exactly
    (not via broad ``except Exception``) and exit clean without
    transitioning to FAILED. The cursor SSOT records the pause; this
    exception just unwinds the current call stack.
    """


class CancellationToken:
    """Single-flag cancellation primitive.

    Backed by an :class:`asyncio.Event` so callers can both
    poll (``is_cancelled()``) and ``await wait_cancelled()`` if they
    want to race the call with cancellation directly. Phase B.5 uses
    polling only.

    Thread-safe within a single asyncio event loop. Across loops the
    process-local registry is the safe sharing surface.
    """

    __slots__ = ("_event", "_id")

    def __init__(self, token_id: str) -> None:
        self._id = token_id
        self._event = asyncio.Event()

    @property
    def id(self) -> str:
        return self._id

    def is_cancelled(self) -> bool:
        """Cheap O(1) check. Safe to call from any context."""
        return self._event.is_set()

    def cancel(self) -> None:
        """Mark the token as cancelled. Idempotent."""
        if not self._event.is_set():
            self._event.set()
            _log.info("CancellationToken cancelled id=%s", self._id)

    async def wait_cancelled(self) -> None:
        """Await until cancelled. Used by callers that want to
        ``asyncio.wait`` against this + their primary work to race
        the call.
        """
        await self._event.wait()

    def raise_if_cancelled(self) -> None:
        """Raise :class:`LLMCancelledError` if cancelled, else no-op.

        Convenience for retry-loop sites: ``token.raise_if_cancelled()``
        is one line and the exception type is exactly the one the
        engine state handler catches.
        """
        if self._event.is_set():
            raise LLMCancelledError(f"Cancellation token {self._id!r} flipped")


# ─────────────────────────────────────────────────────────────────
# Process-local registry
# ─────────────────────────────────────────────────────────────────


_TOKENS: dict[str, CancellationToken] = {}


def get_cancellation_token(investigation_id: str) -> CancellationToken:
    """Return the (lazy-created) token for ``investigation_id``.

    Multiple callers in the same process share the same token instance.
    Each call from a different process gets its own (the registry is
    process-local). The cursor SSOT in
    ``workflow_state_cursor.current_state`` is what synchronizes
    cancellation across processes.
    """
    token = _TOKENS.get(investigation_id)
    if token is None:
        token = CancellationToken(investigation_id)
        _TOKENS[investigation_id] = token
    return token


def cancel_for_investigation(investigation_id: str) -> bool:
    """Flip the token for ``investigation_id`` to cancelled.

    Returns True if a token existed and was flipped (or was already
    cancelled). Returns False if no token existed for that id -- the
    pause path doesn't need to fabricate one because the cursor SSOT
    is already in ``__paused__`` and the next ``get_cancellation_token``
    call will read the cursor first.
    """
    token = _TOKENS.get(investigation_id)
    if token is None:
        return False
    token.cancel()
    return True


def clear_for_investigation(investigation_id: str) -> None:
    """Drop the token for ``investigation_id`` from the registry.

    Phase B resume calls this so the next pause produces a fresh
    (non-cancelled) token. Calling on a missing id is a no-op.
    """
    _TOKENS.pop(investigation_id, None)


def token_registry_snapshot() -> dict[str, bool]:
    """Return ``{investigation_id: is_cancelled}`` for diagnostics.

    Used by operator dashboards and tests; do not poll in hot paths.
    """
    return {tid: t.is_cancelled() for tid, t in _TOKENS.items()}
