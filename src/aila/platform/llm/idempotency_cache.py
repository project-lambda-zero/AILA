"""LLM idempotency cache — request-key keyed cache for retry-safe LLM calls.

Sits between the LLM client and the upstream API. Callers pass a
``request_key`` derived from (investigation_id, branch_id, turn_number,
prompt_hash, case_state_hash). On cache HIT the cached response replays
without a network round-trip; on MISS the upstream is called and the
response persisted under the key.

The cache table is created by migration ``061_llm_idempotency_cache``.

Design notes:

* Key derivation is the CALLER'S responsibility — this module makes no
  assumption about what the input shape is. ``make_request_key`` is a
  convenience helper that's also explicitly defensive (sha256, no
  partial hashes).

* Best-effort writes. If the DB write fails, the LLM call still
  succeeded for the caller — we log and continue. The next retry will
  just call the API again.

* TTL is 7 days by default (migration server_default). The /reset
  endpoint should cascade-delete by investigation_id; a periodic
  scheduler should prune expired rows. Neither is wired here.

* Costs (prompt_tokens / completion_tokens / cost_usd) are stored on
  the cache row so a HIT can record the COSTS THAT WERE SAVED — useful
  for ROI dashboards and detecting whether the cache is doing anything.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime
from typing import Any

from sqlalchemy import DateTime, Index
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlmodel import Field, SQLModel, select

from aila.platform.contracts._common import utc_now

__all__ = [
    "LLMIdempotencyCache",
    "lookup_cached_response",
    "store_response",
    "make_request_key",
]

_log = logging.getLogger(__name__)


class LLMIdempotencyCache(SQLModel, table=True):
    """Cached LLM response keyed by deterministic request_key."""

    __tablename__ = "llm_idempotency_cache"
    __table_args__ = (
        Index("ix_llm_idempotency_inv_created", "investigation_id", "created_at"),
        Index("ix_llm_idempotency_expires", "expires_at"),
    )

    request_key: str = Field(primary_key=True, max_length=64)
    investigation_id: str = Field(max_length=36, index=False)
    branch_id: str | None = Field(default=None, max_length=36)
    turn_number: int | None = Field(default=None)
    response_json: str = Field()
    prompt_tokens: int = Field(default=0)
    completion_tokens: int = Field(default=0)
    cost_usd: float = Field(default=0.0)
    created_at: datetime = Field(
        default_factory=utc_now,
        sa_type=DateTime(timezone=True),
    )
    expires_at: datetime = Field(sa_type=DateTime(timezone=True))


def make_request_key(*parts: Any) -> str:
    """Stable sha256 of the joined parts. Caller decides what's in."""
    h = hashlib.sha256()
    for p in parts:
        if isinstance(p, (dict, list)):
            h.update(json.dumps(p, sort_keys=True, default=str).encode())
        else:
            h.update(str(p).encode())
        h.update(b"\x00")  # separator
    return h.hexdigest()


async def lookup_cached_response(
    session: Any,
    request_key: str,
) -> dict[str, Any] | None:
    """Return the cached response dict for ``request_key``, or None on miss.

    Skips expired rows. Returns the FULL response dict ({content, model,
    usage, finish_reason, ...}) for the caller to substitute for an
    upstream call.
    """
    if not request_key:
        return None
    try:
        row = (await session.exec(
            select(LLMIdempotencyCache).where(
                LLMIdempotencyCache.request_key == request_key,
            )
        )).first()
    except Exception as exc:  # noqa: BLE001 — cache lookup is best-effort
        _log.debug("idempotency cache lookup failed: %s", exc)
        return None
    if row is None:
        return None
    if row.expires_at < utc_now():
        return None
    try:
        return json.loads(row.response_json)
    except (ValueError, TypeError):
        return None


async def store_response(
    session: Any,
    *,
    request_key: str,
    investigation_id: str,
    branch_id: str | None,
    turn_number: int | None,
    response: dict[str, Any],
    prompt_tokens: int = 0,
    completion_tokens: int = 0,
    cost_usd: float = 0.0,
    ttl_days: int = 7,
) -> None:
    """Persist response under ``request_key``. INSERT-or-UPDATE on key
    collision (safe replay if two retries race). Best-effort: any DB
    error is logged and swallowed so the LLM caller's success path
    is never derailed by cache write failures.
    """
    if not request_key:
        return
    from datetime import timedelta

    now = utc_now()
    expires = now + timedelta(days=ttl_days)
    payload = json.dumps(response, default=str)
    try:
        # PostgreSQL native upsert. The LLMIdempotencyCache table's
        # sole primary key is request_key, so ON CONFLICT (request_key)
        # DO UPDATE is the safe race-resolution for two retries that
        # both compute the same key.
        stmt = pg_insert(LLMIdempotencyCache.__table__).values(
            request_key=request_key,
            investigation_id=investigation_id,
            branch_id=branch_id,
            turn_number=turn_number,
            response_json=payload,
            prompt_tokens=prompt_tokens,
            completion_tokens=completion_tokens,
            cost_usd=cost_usd,
            created_at=now,
            expires_at=expires,
        ).on_conflict_do_update(
            index_elements=[LLMIdempotencyCache.__table__.c.request_key],
            set_={
                "response_json": payload,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "cost_usd": cost_usd,
                "expires_at": expires,
            },
        )
        await session.execute(stmt)
        await session.commit()
    except Exception as exc:  # noqa: BLE001 — best-effort
        _log.warning(
            "idempotency cache write failed for %s: %s", request_key[:12], exc,
        )


async def purge_expired(session: Any) -> int:
    """Delete rows past their expires_at. Returns count purged.

    Intended for a periodic cron sweep; not wired by this module.
    """
    from sqlmodel import delete

    try:
        result = await session.execute(
            delete(LLMIdempotencyCache).where(
                LLMIdempotencyCache.expires_at < utc_now(),
            )
        )
        await session.commit()
        return int(getattr(result, "rowcount", 0) or 0)
    except Exception as exc:  # noqa: BLE001
        _log.warning("idempotency cache purge failed: %s", exc)
        return 0
