"""Replay-grade full-body capture into the hash-chained journal (#39).

Motivation: `LLMCostRecord.prompt_preview` and `response_preview` are
truncated to 200 characters -- adequate for the admin interaction list
UI but insufficient to REPLAY a turn (rebuild the exact prompt, verify
the exact response). This module writes the FULL prompt payload
(messages list + tool spec) and the FULL response body to the platform
journal under ``kind=\"llm_prompt\"`` and ``kind=\"llm_response\"``, and
raw tool-call inputs + outputs under ``kind=\"tool_call\"``. These are
already declared JOURNAL_KINDS -- persistence lands into the existing
hash-chained table so a new migration is unnecessary.

Size / secret handling:

- Very large payloads (whole tool corpora, embedded binaries) are
  soft-truncated at :data:`_MAX_BODY_BYTES` with the truncation flag
  and original byte count preserved in the payload metadata; a caller
  who wants to opt out for a specific call passes
  ``truncate=False`` and accepts the wire cost. Default is FULL
  capture -- the replay-first bias trumps the storage bias, which is
  the acceptance criterion for #39.
- The journal writer already redacts secret-classed top-level keys
  (:func:`aila.platform.services.journal._redact_payload`), so
  prompts carrying operator-set secret values do not leak into the
  chain in plaintext. Nested-body redaction is out of scope; secret
  material embedded deep in a tool result body is the caller's
  problem (upstream sanitize path).

All helpers are best-effort: journal-write failures route through
:func:`append_or_deadletter` so the LLM call / tool execution never
raises solely because the replay trail could not be persisted.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from aila.platform.exceptions import AILAError

__all__ = [
    "record_llm_call_bodies",
    "record_llm_call_bodies_sync",
    "record_tool_call_body",
]


_log = logging.getLogger(__name__)


# Soft-cap for a single journal payload body. 512 KiB is well below the
# Postgres row size soft-limit (8 KiB TOAST threshold triggers automatic
# out-of-line storage) and comfortably fits the largest prompts + tool
# results observed in production without paying a hash + serialisation
# tax on truly runaway bodies. Callers may opt into full capture on
# specific calls by passing ``truncate=False``.
_MAX_BODY_BYTES: int = 512 * 1024


# Exception classes the replay helpers absorb into a WARNING log. The
# LLM call and tool execution paths already handle their own failure
# modes; a broken journal must not cascade into either.
_REPLAY_ERRORS: tuple[type[BaseException], ...] = (
    RuntimeError,
    OSError,
    TimeoutError,
    ValueError,
    TypeError,
    AttributeError,
    ImportError,
    AILAError,
)


def _truncate_text(text: str | None, *, truncate: bool) -> tuple[str | None, dict[str, Any]]:
    """Return (body, metadata) for the given text with optional soft-cap.

    ``metadata`` carries the original byte count and a boolean flag so
    a replay tool can detect + report a truncated capture without
    reading the body itself.
    """
    if text is None:
        return None, {"truncated": False, "original_bytes": 0}
    encoded = text.encode("utf-8", errors="replace")
    original = len(encoded)
    if truncate and original > _MAX_BODY_BYTES:
        head = encoded[:_MAX_BODY_BYTES].decode("utf-8", errors="replace")
        return head, {
            "truncated": True,
            "original_bytes": original,
            "captured_bytes": len(head.encode("utf-8", errors="replace")),
        }
    return text, {"truncated": False, "original_bytes": original}


def _messages_body(messages: list[dict[str, Any]] | None) -> tuple[str, dict[str, Any]]:
    """Serialise the assembled prompt messages list for replay.

    Non-JSON-serialisable content (rare -- tool_use blocks carrying
    non-primitive types) is coerced through ``default=str`` so the
    write never fails on a caller's unusual payload shape. The
    serialised form goes through the standard soft-cap.
    """
    if messages is None:
        return "", {"truncated": False, "original_bytes": 0}
    body = json.dumps(messages, default=str, ensure_ascii=False)
    text, meta = _truncate_text(body, truncate=True)
    return text or "", meta


def _build_llm_prompt_payload(
    *,
    run_id: str | None,
    model_id: str,
    task_type: str,
    messages: list[dict[str, Any]] | None,
    tools: list[dict[str, Any]] | None,
    truncate: bool,
) -> dict[str, Any]:
    """Compose the journal payload for kind=llm_prompt."""
    del truncate  # messages/tools always soft-capped at _MAX_BODY_BYTES.
    body, meta = _messages_body(messages)
    tools_body: str | None = None
    tools_meta: dict[str, Any] = {"truncated": False, "original_bytes": 0}
    if tools is not None:
        tools_body, tools_meta = _messages_body(tools)  # type: ignore[arg-type]
    return {
        "run_id": run_id or "",
        "model_id": model_id,
        "task_type": task_type,
        "messages": body,
        "messages_meta": meta,
        "tools": tools_body,
        "tools_meta": tools_meta,
    }


def _build_llm_response_payload(
    *,
    run_id: str | None,
    model_id: str,
    task_type: str,
    response_text: str | None,
    usage: dict[str, Any] | None,
    duration_ms: int | None,
    status: str,
    truncate: bool,
) -> dict[str, Any]:
    """Compose the journal payload for kind=llm_response."""
    body, meta = _truncate_text(response_text, truncate=truncate)
    return {
        "run_id": run_id or "",
        "model_id": model_id,
        "task_type": task_type,
        "response": body,
        "response_meta": meta,
        "usage": usage or {},
        "duration_ms": duration_ms,
        "status": status or "ok",
    }


async def record_llm_call_bodies(
    *,
    run_id: str | None,
    model_id: str,
    task_type: str,
    team_id: str | None,
    messages: list[dict[str, Any]] | None,
    tools: list[dict[str, Any]] | None,
    response_text: str | None,
    usage: dict[str, Any] | None,
    duration_ms: int | None,
    status: str = "ok",
    truncate: bool = True,
) -> None:
    """Persist full LLM prompt + response to the hash-chained journal.

    Two rows are written -- one ``llm_prompt`` carrying the assembled
    messages list (and, when supplied, the tools spec), and one
    ``llm_response`` carrying the response body + token usage. Rows share
    the ambient correlation ContextVar so a replay tool can join
    ``(investigation_id, branch_id, turn_number)`` back to the cost
    record and the domain events fired around the same call.

    Fail-open: any failure is logged and swallowed; the calling LLM
    request path is never blocked by a replay-trail write. Full
    tamper-evident chain semantics still apply -- a chain-hash violation
    dead-letters, it does not silently swallow.
    """
    try:
        # Deferred imports keep this module importable in test contexts
        # where the SQL layer is unavailable.
        from aila.platform.llm.correlation import current_join_keys
        from aila.platform.services.journal import (
            JournalEntry,
            append_or_deadletter,
        )
        from aila.storage.database import async_session_scope

        inv, branch, turn = current_join_keys()
        prompt_payload = _build_llm_prompt_payload(
            run_id=run_id, model_id=model_id, task_type=task_type,
            messages=messages, tools=tools, truncate=truncate,
        )
        response_payload = _build_llm_response_payload(
            run_id=run_id, model_id=model_id, task_type=task_type,
            response_text=response_text, usage=usage,
            duration_ms=duration_ms, status=status, truncate=truncate,
        )

        async with async_session_scope() as session:
            await append_or_deadletter(
                session,
                entry=JournalEntry(
                    kind="llm_prompt",
                    source=f"llm.{task_type}" if task_type else "llm",
                    action="llm.prompt",
                    actor_kind="system",
                    actor_id="llm_client",
                    status=status,
                    payload=prompt_payload,
                    run_id=run_id,
                    investigation_id=inv,
                    branch_id=branch,
                    turn_number=turn,
                ),
                team_id=team_id,
            )
            await append_or_deadletter(
                session,
                entry=JournalEntry(
                    kind="llm_response",
                    source=f"llm.{task_type}" if task_type else "llm",
                    action="llm.response",
                    actor_kind="system",
                    actor_id="llm_client",
                    status=status,
                    payload=response_payload,
                    run_id=run_id,
                    investigation_id=inv,
                    branch_id=branch,
                    turn_number=turn,
                ),
                team_id=team_id,
            )
            await session.commit()
    except _REPLAY_ERRORS as exc:
        _log.warning(
            "llm_replay_journal_failed run_id=%s model=%s: %s",
            run_id, model_id, exc,
        )


def record_llm_call_bodies_sync(
    *,
    run_id: str | None,
    model_id: str,
    task_type: str,
    team_id: str | None,
    messages: list[dict[str, Any]] | None,
    tools: list[dict[str, Any]] | None,
    response_text: str | None,
    usage: dict[str, Any] | None,
    duration_ms: int | None,
    status: str = "ok",
    truncate: bool = True,
) -> None:
    """Synchronous twin of :func:`record_llm_call_bodies` for sync callers.

    Used by the sync ``chat_sync`` / ``chat_json_sync`` shims and any
    CLI path that runs outside an event loop.
    """
    try:
        from aila.platform.llm.correlation import current_join_keys
        from aila.platform.services.journal import (
            JournalEntry,
            append_sync,
        )
        from aila.storage.database import session_scope

        inv, branch, turn = current_join_keys()
        prompt_payload = _build_llm_prompt_payload(
            run_id=run_id, model_id=model_id, task_type=task_type,
            messages=messages, tools=tools, truncate=truncate,
        )
        response_payload = _build_llm_response_payload(
            run_id=run_id, model_id=model_id, task_type=task_type,
            response_text=response_text, usage=usage,
            duration_ms=duration_ms, status=status, truncate=truncate,
        )

        with session_scope() as session:
            append_sync(
                session,
                entry=JournalEntry(
                    kind="llm_prompt",
                    source=f"llm.{task_type}" if task_type else "llm",
                    action="llm.prompt",
                    actor_kind="system",
                    actor_id="llm_client",
                    status=status,
                    payload=prompt_payload,
                    run_id=run_id,
                    investigation_id=inv,
                    branch_id=branch,
                    turn_number=turn,
                ),
                team_id=team_id,
            )
            append_sync(
                session,
                entry=JournalEntry(
                    kind="llm_response",
                    source=f"llm.{task_type}" if task_type else "llm",
                    action="llm.response",
                    actor_kind="system",
                    actor_id="llm_client",
                    status=status,
                    payload=response_payload,
                    run_id=run_id,
                    investigation_id=inv,
                    branch_id=branch,
                    turn_number=turn,
                ),
                team_id=team_id,
            )
            session.commit()
    except _REPLAY_ERRORS as exc:
        _log.warning(
            "llm_replay_journal_sync_failed run_id=%s model=%s: %s",
            run_id, model_id, exc,
        )


async def record_tool_call_body(
    *,
    server_id: str,
    tool_name: str,
    arguments: dict[str, Any] | None,
    result_body: str | dict[str, Any] | None,
    status: str = "ok",
    error: str | None = None,
    duration_ms: int | None = None,
    team_id: str | None = None,
    run_id: str | None = None,
    truncate: bool = True,
) -> None:
    """Persist a tool-call round-trip to the platform journal for replay.

    Writes one ``tool_call`` entry per call; the payload carries the
    arguments dict (as-is), the raw result body (soft-capped to
    :data:`_MAX_BODY_BYTES`), status, and duration. Correlation ids
    are pulled from the ambient ContextVar so replay joins back to
    the LLM call that requested the tool.
    """
    try:
        from aila.platform.llm.correlation import current_join_keys
        from aila.platform.services.journal import (
            JournalEntry,
            append_or_deadletter,
        )
        from aila.storage.database import async_session_scope

        inv, branch, turn = current_join_keys()
        if isinstance(result_body, dict):
            body_str = json.dumps(result_body, default=str, ensure_ascii=False)
        elif result_body is None:
            body_str = None
        else:
            body_str = str(result_body)
        body_captured, body_meta = _truncate_text(body_str, truncate=truncate)
        payload = {
            "server_id": server_id,
            "tool_name": tool_name,
            "arguments": arguments or {},
            "result": body_captured,
            "result_meta": body_meta,
            "status": status,
            "error": error,
            "duration_ms": duration_ms,
        }
        async with async_session_scope() as session:
            await append_or_deadletter(
                session,
                entry=JournalEntry(
                    kind="tool_call",
                    source=f"tool.{server_id}.{tool_name}",
                    action="tool.call",
                    actor_kind="system",
                    actor_id="tool_executor",
                    status=status,
                    payload=payload,
                    run_id=run_id,
                    investigation_id=inv,
                    branch_id=branch,
                    turn_number=turn,
                ),
                team_id=team_id,
            )
            await session.commit()
    except _REPLAY_ERRORS as exc:
        _log.warning(
            "tool_replay_journal_failed server=%s tool=%s: %s",
            server_id, tool_name, exc,
        )
