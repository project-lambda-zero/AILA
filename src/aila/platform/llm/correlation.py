"""Ambient investigation/branch/turn correlation for observability records (#39).

The agent turn loop sets the current correlation before it drives the LLM and
MCP calls; the platform cost-record writer and the module MCP-call logger read
it so every record can be joined back to the investigation, branch, and turn
that produced it. Threading it as a ContextVar avoids passing the ids through
every call signature (AilaLLMClient, tool executors, bridges), and it
propagates across ``await`` within the same task, so a value set around a
turn reaches the awaited cost-record and MCP-log writes.
"""
from __future__ import annotations

import contextlib
from collections.abc import Iterator
from contextvars import ContextVar
from dataclasses import dataclass

__all__ = [
    "CorrelationContext",
    "bind_user_id",
    "correlation_scope",
    "current_canary_key",
    "current_join_keys",
    "current_prompt_content_hash",
    "current_prompt_version",
    "current_user_id",
    "user_id_scope",
]


@dataclass(frozen=True, slots=True)
class CorrelationContext:
    """The investigation/branch/turn a run of work belongs to."""

    investigation_id: str | None = None
    branch_id: str | None = None
    turn_number: int | None = None
    prompt_content_hash: str | None = None
    prompt_version: str | None = None
    canary_key: str | None = None


_correlation: ContextVar[CorrelationContext | None] = ContextVar(
    "aila_llm_correlation", default=None,
)


# #124 user attribution ContextVar. Independent lifecycle from
# ``_correlation`` (which is per-turn): user_id is per-request, set once
# by the API auth dependency and inherited by every LLM cost write that
# happens under that request task. Kept as its own ContextVar so nested
# ``correlation_scope`` blocks (which replace ``_correlation`` wholesale
# with turn-scoped values) do not accidentally wipe the request-level
# user attribution.
_user_id: ContextVar[str | None] = ContextVar(
    "aila_llm_user_id", default=None,
)


def current_join_keys() -> tuple[str | None, str | None, int | None]:
    """Return ``(investigation_id, branch_id, turn_number)`` for the current context.

    All three are None when no correlation is set (a call outside an agent
    turn). Returning the unpacked triple keeps the None-guard in one place
    instead of repeating it at every record-write site.
    """
    corr = _correlation.get()
    if corr is None:
        return (None, None, None)
    return (corr.investigation_id, corr.branch_id, corr.turn_number)


def current_prompt_content_hash() -> str | None:
    """Return the sha256 of the resolved system prompt for the current turn.

    None when no correlation is set or the caller did not tag a prompt hash.
    Read by the cost-record writer so each LLM call is attributable to the
    exact prompt template that produced it (RFC-09).
    """
    corr = _correlation.get()
    if corr is None:
        return None
    return corr.prompt_content_hash


def current_canary_key() -> str | None:
    """Return the lifecycle key of the canary prompt this turn is running, or None.

    Set only when the investigation's cohort bucket landed inside an active
    canary for the resolved prompt key (RFC-10). Read by the seal step to
    feed the turn's drift + cost into the canary hold gate for that key.
    None on every non-canary turn, so the seal step's signal feed is a
    no-op outside a live canary rollout.
    """
    corr = _correlation.get()
    if corr is None:
        return None
    return corr.canary_key


def current_prompt_version() -> str | None:
    """Return the resolved prompt version for the current turn, or None.

    None when no correlation is set or the prompt came from an inline
    literal with no version-store entry. Read by the cost-record and seal
    writers so each LLM call is attributable to the exact prompt version
    that produced it (RFC-09).
    """
    corr = _correlation.get()
    if corr is None:
        return None
    return corr.prompt_version


@contextlib.contextmanager
def correlation_scope(
    *,
    investigation_id: str | None = None,
    branch_id: str | None = None,
    turn_number: int | None = None,
    prompt_content_hash: str | None = None,
    prompt_version: str | None = None,
    canary_key: str | None = None,
) -> Iterator[None]:
    """Set the ambient correlation for the duration of the block.

    Restores the prior value on exit so a following turn (or unrelated work
    on the same task) does not inherit stale ids.
    """
    token = _correlation.set(
        CorrelationContext(
            investigation_id=investigation_id,
            branch_id=branch_id,
            turn_number=turn_number,
            prompt_content_hash=prompt_content_hash,
            prompt_version=prompt_version,
            canary_key=canary_key,
        ),
    )
    try:
        yield
    finally:
        _correlation.reset(token)


def current_user_id() -> str | None:
    """Return the user id attributed to the current async task, or None.

    Read by :func:`persist_cost_record` so every LLM cost row records the
    user whose auth context drove the call (#124). Set by
    :func:`bind_user_id` (fire-and-forget request-lifetime bind used by
    the FastAPI auth dependency) or by :func:`user_id_scope` (contextlib
    scope used by tests and callers that manage their own lifetime).
    None when no user attribution is available -- worker-triggered LLM
    calls (agent turns, background scans) run outside a user session.

    Normalises the empty string to ``None`` so a caller that hands the
    dependency a blank subject id (a misconfigured token, a placeholder
    left in a test double) yields "no attribution" downstream instead
    of a bogus filter key that would silently match every row a future
    ``LEFT JOIN`` treats as unattributed.
    """
    uid = _user_id.get()
    if not uid:
        return None
    return uid


def bind_user_id(user_id: str | None) -> None:
    """Set the ambient user id for the current async task.

    Fire-and-forget: no reset. Intended for FastAPI dependencies where
    the request task's lifetime naturally bounds the ContextVar's
    visibility (each request runs in its own asyncio.Task with its own
    private context copy). Tests and callers with a bounded block
    should use :func:`user_id_scope` instead.
    """
    _user_id.set(user_id)


@contextlib.contextmanager
def user_id_scope(user_id: str | None) -> Iterator[None]:
    """Set the ambient user id for the duration of the block.

    Restores the prior value on exit so a following unit of work does
    not inherit stale attribution. Preferred over :func:`bind_user_id`
    when the caller can bound the lifetime explicitly (tests, opt-in
    attribution around a specific worker task).
    """
    token = _user_id.set(user_id)
    try:
        yield
    finally:
        _user_id.reset(token)
