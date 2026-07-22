"""C2 append-only, hash-chained platform journal.

One substrate for the audit trail, workflow transitions, domain events, tool /
LLM / MCP calls, evidence lifecycle, and operator messages. Every row is
chained to its predecessor within a ``chain_id`` (``team:{team_id}`` or
``global``) so a post-hoc rewrite is detectable: ``row_hash`` covers the row
envelope plus the previous row's hash, and ``payload_hash`` covers the (possibly
redacted) payload independently.

Consumers (#52 audit integrity, #39 observability, #23 graph journal, #32
replay corpus, #58 untrusted-execution evidence) call :func:`append` inside
their own transaction. ``append`` shares the caller's session, never commits
(the caller's UnitOfWork owns the boundary, C4), and fails closed --
:class:`JournalWriteError` is never caught to hide a broken audit trail.

Seq allocation follows the proven ``platform/workflows/log.py`` pattern: read
the chain head, compute the next seq and the row hash in Python, insert inside a
savepoint, and retry on a primary-key collision. The Postgres stored-function /
``FOR UPDATE NOWAIT`` hot-chain optimization in the design is a follow-on; the
retry loop here is correct under normal contention.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime
from typing import Any, Final
from uuid import uuid4

from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlmodel import Session, select
from sqlmodel.ext.asyncio.session import AsyncSession

from aila.platform.contracts import utc_now
from aila.storage.db_models import (
    PlatformJournalDeadletterRecord,
    PlatformJournalRecord,
)
from aila.storage.registry import is_secret_config_key

__all__ = [
    "JOURNAL_KINDS",
    "ChainVerifyResult",
    "JournalAppendResult",
    "JournalEntry",
    "JournalWriteError",
    "append",
    "append_or_deadletter",
    "append_sync",
    "verify_chain",
]

_log = logging.getLogger(__name__)

_MAX_SEQ_RETRIES: Final[int] = 5
_REDACTED: Final[str] = "[REDACTED]"

# Source-of-truth discriminator catalog for payload_json schema versioning.
JOURNAL_KINDS: Final[frozenset[str]] = frozenset(
    {
        "audit",
        "workflow_transition",
        "domain_event",
        "tool_call",
        "llm_prompt",
        "llm_response",
        "mcp_call",
        "evidence_added",
        "evidence_sealed",
        "operator_message",
    }
)


class JournalEntry(BaseModel):
    kind: str
    source: str
    action: str
    actor_kind: str = "system"
    actor_id: str = "system"
    status: str = "ok"
    payload: dict[str, Any] = Field(default_factory=dict)

    run_id: str | None = None
    investigation_id: str | None = None
    branch_id: str | None = None
    turn_number: int | None = None
    correlation_id: str | None = None
    parent_journal_id: str | None = None

    contains_secret: bool = False
    schema_version: int = 1
    occurred_at: datetime = Field(default_factory=utc_now)


class JournalAppendResult(BaseModel):
    journal_id: str
    seq: int
    chain_id: str
    row_hash: str


class ChainVerifyResult(BaseModel):
    chain_id: str
    ok: bool
    checked: int
    first_bad_seq: int | None = None
    detail: str | None = None


class JournalWriteError(RuntimeError):
    """Raised when append cannot complete. NEVER catch to hide."""


def _canonical_json(obj: Any) -> str:
    """Stable JSON: sorted keys, no whitespace, str-coerced scalars."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def _payload_hash(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def _envelope(
    *,
    chain_id: str,
    seq: int,
    journal_id: str,
    team_id: str | None,
    entry: JournalEntry,
    correlation_id: str,
    payload_hash: str,
    contains_secret: bool,
) -> dict[str, Any]:
    return {
        "chain_id": chain_id,
        "seq": seq,
        "journal_id": journal_id,
        "team_id": team_id,
        "kind": entry.kind,
        "source": entry.source,
        "actor_kind": entry.actor_kind,
        "actor_id": entry.actor_id,
        "action": entry.action,
        "status": entry.status,
        "run_id": entry.run_id,
        "investigation_id": entry.investigation_id,
        "branch_id": entry.branch_id,
        "turn_number": entry.turn_number,
        "correlation_id": correlation_id,
        "parent_journal_id": entry.parent_journal_id,
        "payload_hash": payload_hash,
        "contains_secret": contains_secret,
        "schema_version": entry.schema_version,
        "occurred_at": entry.occurred_at.isoformat(),
    }


def _row_hash(prev_hash: str | None, envelope: dict[str, Any]) -> str:
    prev_bytes = bytes.fromhex(prev_hash) if prev_hash else b"\x00" * 32
    return hashlib.sha256(
        prev_bytes + _canonical_json(envelope).encode("utf-8")
    ).hexdigest()


def _redact_payload(payload: dict[str, Any]) -> tuple[dict[str, Any], bool]:
    """Redact top-level values whose key is secret-classed (C6). Returns the
    redacted payload and whether any redaction was applied."""
    changed = False
    out: dict[str, Any] = {}
    for key, value in payload.items():
        if is_secret_config_key(str(key)):
            out[key] = _REDACTED
            changed = True
        else:
            out[key] = value
    return out, changed


def _resolve_team_id(session: Any, team_id: str | None) -> str | None:
    if team_id is not None:
        return team_id
    ctx = session.info.get("team_context")
    if ctx is not None:
        return getattr(ctx, "team_id", None)
    return None


def _prepare(
    session: Any, entry: JournalEntry, team_id: str | None
) -> tuple[str, str | None, dict[str, Any], bool, str, str, str]:
    """Shared append preamble: validate kind, resolve chain, redact, hash.

    Returns (chain_id, resolved_team, payload, contains_secret, payload_hash,
    journal_id, correlation_id).
    """
    if entry.kind not in JOURNAL_KINDS:
        raise JournalWriteError(f"unknown journal kind: {entry.kind!r}")
    resolved_team = _resolve_team_id(session, team_id)
    chain_id = f"team:{resolved_team}" if resolved_team else "global"
    payload, redacted = _redact_payload(entry.payload)
    contains_secret = entry.contains_secret or redacted
    payload_hash = _payload_hash(payload)
    journal_id = str(uuid4())
    correlation_id = (
        entry.correlation_id
        or entry.investigation_id
        or entry.run_id
        or journal_id
    )
    return (
        chain_id,
        resolved_team,
        payload,
        contains_secret,
        payload_hash,
        journal_id,
        correlation_id,
    )


def _build_row(
    *,
    chain_id: str,
    seq: int,
    prev_hash: str | None,
    journal_id: str,
    resolved_team: str | None,
    entry: JournalEntry,
    correlation_id: str,
    payload: dict[str, Any],
    payload_hash: str,
    contains_secret: bool,
) -> tuple[PlatformJournalRecord, str]:
    envelope = _envelope(
        chain_id=chain_id,
        seq=seq,
        journal_id=journal_id,
        team_id=resolved_team,
        entry=entry,
        correlation_id=correlation_id,
        payload_hash=payload_hash,
        contains_secret=contains_secret,
    )
    row_hash = _row_hash(prev_hash, envelope)
    row = PlatformJournalRecord(
        chain_id=chain_id,
        seq=seq,
        journal_id=journal_id,
        team_id=resolved_team,
        prev_hash=prev_hash,
        row_hash=row_hash,
        payload_hash=payload_hash,
        kind=entry.kind,
        source=entry.source,
        actor_kind=entry.actor_kind,
        actor_id=entry.actor_id,
        action=entry.action,
        status=entry.status,
        run_id=entry.run_id,
        investigation_id=entry.investigation_id,
        branch_id=entry.branch_id,
        turn_number=entry.turn_number,
        correlation_id=correlation_id,
        parent_journal_id=entry.parent_journal_id,
        payload_json=payload,
        contains_secret=contains_secret,
        schema_version=entry.schema_version,
        occurred_at=entry.occurred_at,
    )
    return row, row_hash


async def append(
    session: AsyncSession,
    *,
    entry: JournalEntry,
    team_id: str | None = None,
) -> JournalAppendResult:
    """Append one row inside the caller's transaction. Fail-closed (C2 0.5)."""
    (
        chain_id,
        resolved_team,
        payload,
        contains_secret,
        payload_hash,
        journal_id,
        correlation_id,
    ) = _prepare(session, entry, team_id)

    last_exc: Exception | None = None
    for _ in range(_MAX_SEQ_RETRIES):
        try:
            async with session.begin_nested():
                head = (
                    await session.exec(
                        select(
                            PlatformJournalRecord.seq,
                            PlatformJournalRecord.row_hash,
                        )
                        .where(PlatformJournalRecord.chain_id == chain_id)
                        .order_by(PlatformJournalRecord.seq.desc())
                        .limit(1)
                    )
                ).first()
                if head is None:
                    seq = 0
                    prev_hash: str | None = None
                else:
                    seq = int(head[0]) + 1
                    prev_hash = head[1]

                row, row_hash = _build_row(
                    chain_id=chain_id,
                    seq=seq,
                    prev_hash=prev_hash,
                    journal_id=journal_id,
                    resolved_team=resolved_team,
                    entry=entry,
                    correlation_id=correlation_id,
                    payload=payload,
                    payload_hash=payload_hash,
                    contains_secret=contains_secret,
                )
                session.add(row)
                await session.flush()
            return JournalAppendResult(
                journal_id=journal_id,
                seq=seq,
                chain_id=chain_id,
                row_hash=row_hash,
            )
        except IntegrityError as exc:
            last_exc = exc
            continue

    raise JournalWriteError(
        f"journal append to {chain_id} failed after {_MAX_SEQ_RETRIES} seq retries"
    ) from last_exc


async def append_or_deadletter(
    session: AsyncSession,
    *,
    entry: JournalEntry,
    team_id: str | None = None,
) -> JournalAppendResult | None:
    """Append if possible, else record to the dead-letter table (C2 0.5).

    Returns None when the entry was dead-lettered. Reserved for legacy paths
    that must not fail the business action when the audit chain is broken; new
    code MUST use :func:`append`.
    """
    try:
        return await append(session, entry=entry, team_id=team_id)
    except (JournalWriteError, SQLAlchemyError) as exc:
        resolved_team = _resolve_team_id(session, team_id)
        chain_id = f"team:{resolved_team}" if resolved_team else "global"
        failure_kind = (
            "chain_violation" if isinstance(exc, JournalWriteError) else "db_error"
        )
        try:
            async with session.begin_nested():
                session.add(
                    PlatformJournalDeadletterRecord(
                        chain_id=chain_id,
                        team_id=resolved_team,
                        entry_json=entry.model_dump(mode="json"),
                        failure_kind=failure_kind,
                        failure_detail=type(exc).__name__,
                    )
                )
                await session.flush()
        except SQLAlchemyError:
            _log.exception("journal dead-letter write failed for chain %s", chain_id)
            raise JournalWriteError(
                f"journal append AND dead-letter both failed for {chain_id}"
            ) from exc
        _log.warning(
            "journal append dead-lettered chain=%s kind=%s failure=%s",
            chain_id,
            entry.kind,
            failure_kind,
        )
        return None


def append_sync(
    session: Session,
    *,
    entry: JournalEntry,
    team_id: str | None = None,
) -> JournalAppendResult:
    """Synchronous :func:`append` for sync-session callers (worker-thread event
    emitter, CLI). Same fail-closed hash-chain semantics; shares the caller's
    sync transaction and never commits."""
    (
        chain_id,
        resolved_team,
        payload,
        contains_secret,
        payload_hash,
        journal_id,
        correlation_id,
    ) = _prepare(session, entry, team_id)

    last_exc: Exception | None = None
    for _ in range(_MAX_SEQ_RETRIES):
        try:
            with session.begin_nested():
                head = session.exec(
                    select(
                        PlatformJournalRecord.seq,
                        PlatformJournalRecord.row_hash,
                    )
                    .where(PlatformJournalRecord.chain_id == chain_id)
                    .order_by(PlatformJournalRecord.seq.desc())
                    .limit(1)
                ).first()
                if head is None:
                    seq = 0
                    prev_hash: str | None = None
                else:
                    seq = int(head[0]) + 1
                    prev_hash = head[1]

                row, row_hash = _build_row(
                    chain_id=chain_id,
                    seq=seq,
                    prev_hash=prev_hash,
                    journal_id=journal_id,
                    resolved_team=resolved_team,
                    entry=entry,
                    correlation_id=correlation_id,
                    payload=payload,
                    payload_hash=payload_hash,
                    contains_secret=contains_secret,
                )
                session.add(row)
                session.flush()
            return JournalAppendResult(
                journal_id=journal_id,
                seq=seq,
                chain_id=chain_id,
                row_hash=row_hash,
            )
        except IntegrityError as exc:
            last_exc = exc
            continue

    raise JournalWriteError(
        f"journal append to {chain_id} failed after {_MAX_SEQ_RETRIES} seq retries"
    ) from last_exc


async def verify_chain(
    session: AsyncSession,
    *,
    chain_id: str,
    since_seq: int = 0,
    limit: int | None = None,
) -> ChainVerifyResult:
    """Recompute the hash chain and confirm no row was rewritten or reordered.

    Walks rows in seq order, recomputing each ``payload_hash`` from the stored
    payload and each ``row_hash`` from the prior row's hash plus the envelope.
    A mismatch reports the first offending seq.
    """
    stmt = (
        select(PlatformJournalRecord)
        .where(
            PlatformJournalRecord.chain_id == chain_id,
            PlatformJournalRecord.seq >= since_seq,
        )
        .order_by(PlatformJournalRecord.seq.asc())
    )
    if limit is not None:
        stmt = stmt.limit(limit)
    rows = list((await session.exec(stmt)).all())

    checked = 0
    prev_hash: str | None = None
    for i, row in enumerate(rows):
        # Genesis (seq 0) has prev_hash None; every later row must link to the
        # previous row's row_hash. When starting mid-chain (since_seq > 0) the
        # first row's prev linkage is taken from its stored prev_hash.
        expected_prev = row.prev_hash if i == 0 else prev_hash
        if row.prev_hash != expected_prev:
            return ChainVerifyResult(
                chain_id=chain_id,
                ok=False,
                checked=checked,
                first_bad_seq=row.seq,
                detail="prev_hash link broken",
            )
        recomputed_payload = _payload_hash(row.payload_json)
        if recomputed_payload != row.payload_hash:
            return ChainVerifyResult(
                chain_id=chain_id,
                ok=False,
                checked=checked,
                first_bad_seq=row.seq,
                detail="payload_hash mismatch",
            )
        envelope = {
            "chain_id": row.chain_id,
            "seq": row.seq,
            "journal_id": row.journal_id,
            "team_id": row.team_id,
            "kind": row.kind,
            "source": row.source,
            "actor_kind": row.actor_kind,
            "actor_id": row.actor_id,
            "action": row.action,
            "status": row.status,
            "run_id": row.run_id,
            "investigation_id": row.investigation_id,
            "branch_id": row.branch_id,
            "turn_number": row.turn_number,
            "correlation_id": row.correlation_id,
            "parent_journal_id": row.parent_journal_id,
            "payload_hash": row.payload_hash,
            "contains_secret": row.contains_secret,
            "schema_version": row.schema_version,
            "occurred_at": row.occurred_at.isoformat(),
        }
        if _row_hash(row.prev_hash, envelope) != row.row_hash:
            return ChainVerifyResult(
                chain_id=chain_id,
                ok=False,
                checked=checked,
                first_bad_seq=row.seq,
                detail="row_hash mismatch",
            )
        prev_hash = row.row_hash
        checked += 1

    return ChainVerifyResult(chain_id=chain_id, ok=True, checked=checked)
