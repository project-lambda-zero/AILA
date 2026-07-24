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
    "correlation_scope",
    "current_join_keys",
    "current_prompt_content_hash",
    "current_prompt_version",
]


@dataclass(frozen=True, slots=True)
class CorrelationContext:
    """The investigation/branch/turn a run of work belongs to."""

    investigation_id: str | None = None
    branch_id: str | None = None
    turn_number: int | None = None
    prompt_content_hash: str | None = None
    prompt_version: str | None = None


_correlation: ContextVar[CorrelationContext | None] = ContextVar(
    "aila_llm_correlation", default=None,
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
        ),
    )
    try:
        yield
    finally:
        _correlation.reset(token)
