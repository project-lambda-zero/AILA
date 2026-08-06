"""Idempotent LLM call wrapper (RFC-03 Phase 2).

Retry-safe front door for the module agent LLM calls that were bypassing
the idempotency cache (claim verifier, pattern extractor, synthesis,
narrative). Each was a direct ``llm_client.chat`` / ``chat_json`` /
``chat_structured`` call, so a worker crash plus ARQ redelivery paid the
model API a second time for the same request.

All three client methods return :class:`LLMResponse` (``chat_structured``
returns the JSON in ``.content`` for the caller to re-parse), so one
wrapper covers them via a small method dispatch. The response is keyed by
(investigation_id, branch_id, turn_number, method, task_type, messages
[, schema / model name]); keying on the full messages makes a stale hit
impossible -- any change to the request yields a different key. A retried
worker recomputes the same key and reads the stored response instead of
calling the model. Disabled (kill-switch) responses are never cached.
"""
from __future__ import annotations

import hashlib
import logging
from typing import Any

from pydantic import BaseModel

from aila.platform.llm.client import LLMResponse
from aila.platform.llm.correlation import (
    correlation_scope,
    current_prompt_content_hash,
    current_prompt_version,
)
from aila.platform.llm.idempotency_cache import (
    lookup_cached_response,
    make_request_key,
    store_response,
)
from aila.platform.uow import UnitOfWork

__all__ = ["idempotent_llm_call"]

_log = logging.getLogger(__name__)


def _system_prompt_hash(messages: list[dict[str, Any]]) -> str | None:
    """sha256 of the first system message, or None when there is none.

    Lets every call route its resolved prompt into the cost/seal records
    (RFC-09) even when the caller did not open an outer correlation scope.
    """
    for msg in messages:
        if msg.get("role") == "system":
            content = msg.get("content") or ""
            if content:
                return hashlib.sha256(content.encode("utf-8")).hexdigest()
    return None


async def idempotent_llm_call(
    llm_client: Any,
    *,
    method: str,
    task_type: str,
    messages: list[dict[str, Any]],
    investigation_id: str,
    branch_id: str | None = None,
    turn_number: int | None = None,
    schema: dict[str, Any] | None = None,
    model_class: type[BaseModel] | None = None,
    run_id: str | None = None,
    team_id: str | None = None,
    prompt_content_hash: str | None = None,
    prompt_version: str | None = None,
    ttl_days: int = 7,
) -> tuple[LLMResponse, bool]:
    """Call ``llm_client.<method>`` behind the idempotency cache.

    *method* is one of ``"chat"``, ``"chat_json"``, ``"chat_structured"``.
    ``chat_json`` requires *schema*; ``chat_structured`` requires
    *model_class*. Returns ``(response, cache_hit)``. On a cache hit the
    model is not called; on a miss the response is stored (unless the
    kill switch disabled it) so a later retry replays it.
    """
    key_extra: Any = ""
    if schema is not None:
        key_extra = schema
    elif model_class is not None:
        key_extra = model_class.__name__
    request_key = make_request_key(
        investigation_id, branch_id, turn_number,
        method, task_type, messages, key_extra,
    )

    async with UnitOfWork() as uow:
        cached = await lookup_cached_response(uow.session, request_key)
    if cached is not None:
        _log.info(
            "idempotent_llm_call cache HIT method=%s task=%s inv=%s branch=%s",
            method, task_type, investigation_id, branch_id,
        )
        replay = LLMResponse(
            content=cached.get("content", ""),
            model=cached.get("model", ""),
            usage=dict(cached.get("usage") or {}),
            disabled=False,
            finish_reason=cached.get("finish_reason", ""),
        )
        return replay, True

    # Set-if-unset: prefer an explicit arg, then an outer correlation scope
    # (the researcher turn sets one), then derive from the system prompt so
    # every agent LLM call lands a content_hash on its cost + seal records.
    _phash = (
        prompt_content_hash
        or current_prompt_content_hash()
        or _system_prompt_hash(messages)
    )
    _pver = prompt_version or current_prompt_version()
    with correlation_scope(
        investigation_id=investigation_id,
        branch_id=branch_id,
        turn_number=turn_number,
        prompt_content_hash=_phash,
        prompt_version=_pver,
    ):
        if method == "chat":
            resp = await llm_client.chat(
                task_type, messages, run_id=run_id, team_id=team_id,
            )
        elif method == "chat_json":
            if schema is None:
                raise ValueError("idempotent_llm_call: chat_json requires schema")
            resp = await llm_client.chat_json(
                task_type, messages, schema, run_id=run_id, team_id=team_id,
            )
        elif method == "chat_structured":
            if model_class is None:
                raise ValueError(
                    "idempotent_llm_call: chat_structured requires model_class",
                )
            resp = await llm_client.chat_structured(
                task_type, messages, model_class, run_id=run_id, team_id=team_id,
            )
        else:
            raise ValueError(f"idempotent_llm_call: unknown method {method!r}")

    if not resp.disabled:
        usage = dict(resp.usage or {})
        async with UnitOfWork() as uow:
            await store_response(
                uow.session,
                request_key=request_key,
                investigation_id=investigation_id,
                branch_id=branch_id,
                turn_number=turn_number,
                response={
                    "content": resp.content,
                    "model": resp.model,
                    "usage": usage,
                    "finish_reason": resp.finish_reason,
                },
                prompt_tokens=usage.get("prompt_tokens", 0),
                completion_tokens=usage.get("completion_tokens", 0),
                ttl_days=ttl_days,
            )
    return resp, False
