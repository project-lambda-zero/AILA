"""Eval transcript recorder (RFC-08 record-replay backbone).

An eval transcript is a frozen snapshot of ONE recorded turn: the
recorded wall-clock, the retrieval hits, the tool outputs, the LLM
request + response, and the parsed decision, plus the prompt key +
version that produced it. Replay (``platform/eval/replay.py``) rebuilds
the same turn under a candidate prompt version with those inputs held
constant so ONLY the prompt varies -- the harness scores determinism
across two replays and faithfulness of a replay against the recorded
decision.

:class:`TranscriptRecorder` reconstructs a row from ALREADY-PERSISTED
data; nothing on the live turn hot path writes here. The reader touches
three shared substrates:

* ``llm_idempotency_cache`` -- the recorded LLM response body and the
  wall-clock (``created_at``) the call landed at. REQUIRED. Missing ->
  :class:`TranscriptAssemblyError`.
* ``llm_cost_records`` -- the resolved ``prompt_version`` and
  ``task_type`` for the turn. REQUIRED for prompt attribution. Missing
  -> :class:`TranscriptAssemblyError`.
* ``platform_journal`` -- the ``llm_prompt`` payload (assembled messages
  + tool spec), ``tool_call`` payloads, ``knowledge_retrieval``
  payloads. Best-effort; an empty journal yields empty JSON arrays,
  never a fabricated row.

``prompt_key`` is derived by the ``f"{module_id}/{task_type}"``
convention used by the platform's live agent-side callers
(``vr/audit``, ``malware/audit``, ...); a caller with a bespoke key
scheme can override it with the ``prompt_key_override`` argument.

Row hardness: the recorder NEVER fabricates data. When a required
source row is absent it raises :class:`TranscriptAssemblyError` with a
message naming the missing source. Best-effort sources contribute an
empty JSON payload when absent -- the caller can distinguish "recorded
no retrieval hits" from "recorded no LLM call" by inspecting the
required-vs-empty fields.
"""
from __future__ import annotations

import json
import logging
from collections.abc import Sequence
from datetime import datetime
from typing import Any
from uuid import uuid4

from sqlalchemy import DateTime, Index, Text
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import Field, SQLModel, select

from aila.platform.contracts import utc_now
from aila.platform.llm.cost_record import LLMCostRecord
from aila.platform.llm.idempotency_cache import LLMIdempotencyCache
from aila.storage.database import async_session_scope

__all__ = [
    "EvalTranscriptRecord",
    "TranscriptAssemblyError",
    "TranscriptRecorder",
]

_log = logging.getLogger(__name__)

# Journal kinds this recorder harvests. All three ride the shared
# ``platform_journal`` substrate with (investigation_id, branch_id,
# turn_number) columns, so a per-turn lookup joins cleanly without
# touching module-specific tables.
_JOURNAL_KIND_LLM_PROMPT = "llm_prompt"
_JOURNAL_KIND_TOOL_CALL = "tool_call"
_JOURNAL_KIND_KNOWLEDGE = "knowledge_retrieval"


class TranscriptAssemblyError(RuntimeError):
    """Raised when a required persisted source row for a turn is missing.

    The exception message names the missing source (idempotency cache row,
    cost record row) so the operator can trace it back to the specific turn
    identifier. Never raised for best-effort sources (journal rows); those
    contribute empty JSON payloads.
    """


class EvalTranscriptRecord(SQLModel, table=True):
    """A frozen snapshot of one recorded turn.

    ``recorded_clock`` is the moment the recorded LLM call landed (from
    the idempotency cache). ``recorded_decision_json`` is the parsed
    LLM response body -- the model's decision structured as JSON when
    the response was JSON-shaped, otherwise ``{"raw_text": <content>}``
    so a replay can still compare against something concrete.
    """

    __tablename__ = "eval_transcripts"
    __table_args__ = (
        Index(
            "ix_eval_transcripts_turn",
            "investigation_id", "branch_id", "turn_number",
        ),
        Index(
            "ix_eval_transcripts_prompt", "prompt_key", "prompt_version",
        ),
        Index("ix_eval_transcripts_created_at", "created_at"),
    )

    id: str = Field(
        default_factory=lambda: str(uuid4()), primary_key=True, max_length=64,
    )
    investigation_id: str = Field(max_length=64)
    branch_id: str | None = Field(default=None, max_length=64)
    turn_number: int = Field()
    module_id: str = Field(max_length=64)
    recorded_clock: datetime = Field(sa_type=DateTime(timezone=True))
    retrieval_hits_json: str = Field(default="[]", sa_type=Text)
    tool_outputs_json: str = Field(default="[]", sa_type=Text)
    llm_request_json: str = Field(default="{}", sa_type=Text)
    llm_response_json: str = Field(default="{}", sa_type=Text)
    recorded_decision_json: str = Field(default="{}", sa_type=Text)
    prompt_key: str = Field(max_length=256)
    prompt_version: str = Field(max_length=32)
    created_at: datetime = Field(
        default_factory=utc_now, sa_type=DateTime(timezone=True),
    )


def _parse_decision_from_response(content: str | None) -> dict[str, Any]:
    """Parse the LLM response body into a structured decision dict.

    Returns ``{"raw_text": content}`` when the body is not JSON-shaped so
    the transcript never carries fabricated structure. An empty response
    yields ``{"raw_text": ""}`` for the same reason.
    """
    if not content:
        return {"raw_text": ""}
    try:
        parsed = json.loads(content)
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        _log.debug(
            "transcript recorded decision not JSON-shaped (falling back to raw_text): %s",
            exc,
        )
        return {"raw_text": content}
    if isinstance(parsed, dict):
        return parsed
    return {"raw_text": content, "parsed_scalar": parsed}


class TranscriptRecorder:
    """Reconstruct an :class:`EvalTranscriptRecord` from persisted data.

    Composed with the same shared session helpers the rest of the eval
    surface uses (``async_session_scope``). Every read is scoped to
    ``(investigation_id, branch_id, turn_number)`` via the shared
    substrates -- no module-specific tables are touched.
    """

    async def record_from_history(
        self,
        *,
        investigation_id: str,
        branch_id: str | None,
        turn_number: int,
        module_id: str,
        prompt_key_override: str | None = None,
    ) -> str:
        """Persist a transcript row for one already-run turn; return the id.

        Reads the required sources (``llm_idempotency_cache`` +
        ``llm_cost_records``) and the best-effort sources (three
        ``platform_journal`` kinds), assembles the row, commits it, and
        returns the row id. Raises :class:`TranscriptAssemblyError` when a
        required source is absent so the caller sees a clear failure
        instead of a fabricated row.
        """
        async with async_session_scope() as session:
            cache_row = await self._load_idempotency_row(
                session,
                investigation_id=investigation_id,
                branch_id=branch_id,
                turn_number=turn_number,
            )
            if cache_row is None:
                raise TranscriptAssemblyError(
                    "no llm_idempotency_cache row for "
                    f"investigation_id={investigation_id!r} "
                    f"branch_id={branch_id!r} turn_number={turn_number!r}",
                )
            cost_row = await self._load_cost_row(
                session,
                investigation_id=investigation_id,
                branch_id=branch_id,
                turn_number=turn_number,
            )
            if cost_row is None:
                raise TranscriptAssemblyError(
                    "no llm_cost_record row (needed for prompt_version + "
                    "task_type) for "
                    f"investigation_id={investigation_id!r} "
                    f"branch_id={branch_id!r} turn_number={turn_number!r}",
                )
            prompt_version = cost_row.prompt_version
            if not prompt_version:
                raise TranscriptAssemblyError(
                    "llm_cost_record.prompt_version is unset for "
                    f"investigation_id={investigation_id!r} "
                    f"branch_id={branch_id!r} turn_number={turn_number!r} "
                    "-- an inline prompt cannot be replayed under a "
                    "versioned candidate",
                )
            task_type = cost_row.task_type or ""
            prompt_key = prompt_key_override or f"{module_id}/{task_type}"

            llm_request_payload = await self._collect_journal_payloads(
                session,
                kind=_JOURNAL_KIND_LLM_PROMPT,
                investigation_id=investigation_id,
                branch_id=branch_id,
                turn_number=turn_number,
            )
            tool_output_payloads = await self._collect_journal_payloads(
                session,
                kind=_JOURNAL_KIND_TOOL_CALL,
                investigation_id=investigation_id,
                branch_id=branch_id,
                turn_number=turn_number,
            )
            retrieval_payloads = await self._collect_journal_payloads(
                session,
                kind=_JOURNAL_KIND_KNOWLEDGE,
                investigation_id=investigation_id,
                branch_id=branch_id,
                turn_number=turn_number,
            )

            # The idempotency cache stores the raw LLM response JSON string;
            # decode it once so the transcript's llm_response_json carries a
            # normalized dict and _parse_decision_from_response can look at
            # the model's actual content.
            try:
                cached_response = json.loads(cache_row.response_json)
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                raise TranscriptAssemblyError(
                    "llm_idempotency_cache.response_json is not valid JSON "
                    f"for request_key={cache_row.request_key!r}: {exc}",
                ) from exc
            if not isinstance(cached_response, dict):
                raise TranscriptAssemblyError(
                    "llm_idempotency_cache.response_json did not decode to a "
                    "JSON object (got "
                    f"{type(cached_response).__name__}) for "
                    f"request_key={cache_row.request_key!r}",
                )
            recorded_decision = _parse_decision_from_response(
                cached_response.get("content"),
            )

            # llm_request_json: at most one llm_prompt row per turn is
            # written by the shared record_llm_call_bodies path, but if a
            # module fires multiple LLM calls under the same turn number
            # the newest wins -- the recorded decision belongs to the
            # response captured in the idempotency cache, and the newest
            # prompt row is the one most likely to have produced it.
            llm_request_json = json.dumps(
                llm_request_payload[-1] if llm_request_payload else {},
            )
            record = EvalTranscriptRecord(
                investigation_id=investigation_id,
                branch_id=branch_id,
                turn_number=turn_number,
                module_id=module_id,
                recorded_clock=cache_row.created_at,
                retrieval_hits_json=json.dumps(retrieval_payloads),
                tool_outputs_json=json.dumps(tool_output_payloads),
                llm_request_json=llm_request_json,
                llm_response_json=json.dumps(cached_response),
                recorded_decision_json=json.dumps(recorded_decision),
                prompt_key=prompt_key,
                prompt_version=prompt_version,
            )
            session.add(record)
            await session.commit()
            await session.refresh(record)
            return record.id

    async def _load_idempotency_row(
        self,
        session: Any,
        *,
        investigation_id: str,
        branch_id: str | None,
        turn_number: int,
    ) -> LLMIdempotencyCache | None:
        """Return the newest cache row for the turn, or None on absence."""
        stmt = (
            select(LLMIdempotencyCache)
            .where(
                LLMIdempotencyCache.investigation_id == investigation_id,
                LLMIdempotencyCache.branch_id == branch_id,
                LLMIdempotencyCache.turn_number == turn_number,
            )
            .order_by(LLMIdempotencyCache.created_at.desc())
            .limit(1)
        )
        try:
            return (await session.exec(stmt)).first()
        except SQLAlchemyError as exc:
            _log.warning(
                "transcript idempotency-cache lookup failed inv=%s branch=%s turn=%s: %s",
                investigation_id, branch_id, turn_number, exc,
            )
            return None

    async def _load_cost_row(
        self,
        session: Any,
        *,
        investigation_id: str,
        branch_id: str | None,
        turn_number: int,
    ) -> Any:
        """Return the newest cost record for the turn, or None on absence.

        The cost record is the shared, module-neutral source of the
        resolved ``prompt_version`` and ``task_type`` for a turn; without
        it, the transcript cannot be attributed to a versioned prompt.
        """
        stmt = (
            select(LLMCostRecord)
            .where(
                LLMCostRecord.investigation_id == investigation_id,
                LLMCostRecord.branch_id == branch_id,
                LLMCostRecord.turn_number == turn_number,
            )
            .order_by(LLMCostRecord.created_at.desc())
            .limit(1)
        )
        try:
            return (await session.exec(stmt)).first()
        except SQLAlchemyError as exc:
            _log.warning(
                "transcript cost-record lookup failed inv=%s branch=%s turn=%s: %s",
                investigation_id, branch_id, turn_number, exc,
            )
            return None

    async def _collect_journal_payloads(
        self,
        session: Any,
        *,
        kind: str,
        investigation_id: str,
        branch_id: str | None,
        turn_number: int,
    ) -> list[dict[str, Any]]:
        """Return every journal payload for (kind, turn) ordered by ``seq``.

        Empty when no rows exist. Best-effort: a lookup failure logs and
        returns an empty list so an unavailable journal never blocks the
        transcript from being written; the caller can still replay with
        the LLM request + response alone.
        """
        # Deferred import: eval package initialization loads through
        # db_models -> eval.calibration -> eval/__init__ -> runner, so
        # importing db_models at transcript-module import time closes a
        # cycle. Deferring to first-use keeps transcript.py safe.
        from aila.storage.db_models import PlatformJournalRecord
        stmt = (
            select(PlatformJournalRecord)
            .where(
                PlatformJournalRecord.kind == kind,
                PlatformJournalRecord.investigation_id == investigation_id,
                PlatformJournalRecord.branch_id == branch_id,
                PlatformJournalRecord.turn_number == turn_number,
            )
            .order_by(PlatformJournalRecord.seq.asc())
        )
        try:
            rows: Sequence[Any] = (await session.exec(stmt)).all()
        except SQLAlchemyError as exc:
            _log.warning(
                "transcript journal lookup failed kind=%s inv=%s branch=%s turn=%s: %s",
                kind, investigation_id, branch_id, turn_number, exc,
            )
            return []
        payloads: list[dict[str, Any]] = []
        for row in rows:
            payload = getattr(row, "payload_json", None)
            if isinstance(payload, dict):
                payloads.append(payload)
        return payloads
