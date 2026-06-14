"""LLM idempotency cache — request-key keyed cache for retry-safe LLM calls.

Sits between the LLM client and the upstream API. Callers pass a
``request_key`` derived from (investigation_id, branch_id, turn_number,
prompt_hash, case_state_hash). On cache HIT the cached response replays
without a network round-trip; on MISS the upstream is called and the
response persisted under the key.

The cache table is created by migration ``061_llm_idempotency_cache``.

Design notes:
* TTL is 7 days by default (migration server_default). Expired rows are
  pruned by the platform reaper cron (worker.py) which calls
  :func:`purge_expired` once per minute (§123 — Phase E15). The /reset
  endpoint does not cascade-delete by investigation_id; consumers that
  need that should call :func:`purge_for_investigation` explicitly.

* Costs (prompt_tokens / completion_tokens / cost_usd) are stored on
  the cache row so a HIT can record the COSTS THAT WERE SAVED — useful
  for ROI dashboards and detecting whether the cache is doing anything.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import DateTime, Index
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import DBAPIError, SQLAlchemyError
from sqlmodel import Field, SQLModel, delete, select

from aila.platform.contracts._common import utc_now

__all__ = [
    "LLMIdempotencyCache",
    "lookup_cached_response",
    "make_request_key",
    "purge_expired",
    "purge_for_investigation",
    "run_purge_expired_cron",
    "store_response",
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
    """Stable sha256 of the joined parts. Caller decides what's in.

    fix §120 (companion) — dicts and lists are required to be JSON-clean.
    The legacy ``default=str`` escape hatch was removed so a caller passing
    ``{"value": Decimal("1.0")}`` and ``{"value": "1.0"}`` no longer collide
    on the same key. Pre-serialize exotic types at the caller.
    """
    h = hashlib.sha256()
    for p in parts:
        if isinstance(p, (dict, list)):
            try:
                h.update(json.dumps(p, sort_keys=True).encode())
            except (TypeError, ValueError) as exc:
                raise TypeError(
                    "make_request_key part is not JSON-serializable "
                    "(strict mode — pre-serialize exotic types): "
                    f"{exc}",
                ) from exc
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
    except SQLAlchemyError as exc:
        # fix §124 — surface true DB failures at WARNING+ instead of swallowing
        # silently. The lookup remains best-effort (returns None so caller
        # falls back to a live LLM call) but the operator now sees broken-cache
        # symptoms in logs.
        _log.warning(
            "idempotency cache lookup db error for key=%s: %s",
            request_key[:12], exc,
        )
        return None
    except (OSError, RuntimeError, ValueError) as exc:
        _log.warning(
            "idempotency cache lookup transport error for key=%s: %s",
            request_key[:12], exc,
        )
        return None
    if row is None:
        return None
    expires = row.expires_at
    if expires is not None and expires.tzinfo is None:
        # fix §122 — normalize legacy tz-naive expires_at to UTC.
        from datetime import UTC  # noqa: PLC0415
        expires = expires.replace(tzinfo=UTC)
    if expires is None or expires < utc_now():
        return None
    try:
        return json.loads(row.response_json)
    except (ValueError, TypeError) as exc:
        _log.warning(
            "idempotency_cache: cached response parse FAILED key=%s reason=%s",
            request_key, exc,
        )
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

    now = utc_now()
    expires = now + timedelta(days=ttl_days)
    # fix §120 — reject non-JSON-serializable values at write time. The
    # default=str escape hatch made `Decimal("1.0")` and `"1.0"` serialize
    # identically, so two semantically-different responses collided on the
    # same cache key. Force callers to pre-serialize anything exotic.
    try:
        payload = json.dumps(response, sort_keys=True)
    except (TypeError, ValueError) as exc:
        _log.warning(
            "idempotency cache write rejected for %s — response is not "
            "JSON-serializable (%s); caller must pre-serialize.",
            request_key[:12], exc,
        )
        return
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
    except (SQLAlchemyError, DBAPIError) as exc:
        _log.warning(
            "idempotency cache write failed for %s: %s", request_key[:12], exc,
        )


async def purge_expired(session: Any) -> int:
    """Delete rows past their expires_at. Returns count purged.

    Wired into the platform reaper cron via :func:`run_purge_expired_cron`
    so expired rows are pruned once per minute (§123). Direct callers may
    also invoke this with their own session for ad-hoc cleanup.
    """
    try:
        result = await session.execute(
            delete(LLMIdempotencyCache).where(
                LLMIdempotencyCache.expires_at < utc_now(),
            )
        )
        await session.commit()
        # fix §69-style: rowcount can be -1 on some drivers when the row count
        # is unknown. Clamp at zero to avoid negative log lines.
        rc = int(getattr(result, "rowcount", 0) or 0)
        return rc if rc >= 0 else 0
    except (SQLAlchemyError, DBAPIError) as exc:
        _log.warning("idempotency cache purge failed: %s", exc)
        return 0


async def purge_for_investigation(
    session: Any, investigation_id: str,
) -> int:
    """Delete every cache row tied to ``investigation_id``.

    Used by ``/reset`` endpoints / explicit cascade deletes (§121). Returns
    the count deleted, or 0 on transport error (best-effort — the data is
    cache state, not source of truth).
    """
    if not investigation_id:
        return 0
    try:
        result = await session.execute(
            delete(LLMIdempotencyCache).where(
                LLMIdempotencyCache.investigation_id == investigation_id,
            )
        )
        await session.commit()
        rc = int(getattr(result, "rowcount", 0) or 0)
        return rc if rc >= 0 else 0
    except (SQLAlchemyError, DBAPIError) as exc:
        _log.warning(
            "idempotency cache purge_for_investigation(%s) failed: %s",
            investigation_id, exc,
        )
        return 0


async def run_purge_expired_cron() -> int:
    """Open a session and call :func:`purge_expired`.

    Wired into ``platform/tasks/worker.py:reaper`` (§123). Standalone
    function so the cron import surface stays narrow — the reaper does
    not need to know about session scopes.
    """
    from aila.storage.database import async_session_scope  # noqa: PLC0415

    async with async_session_scope() as session:
        return await purge_expired(session)
