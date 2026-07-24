"""Shared pattern extractor (RFC-03 Phase 5).

``PatternExtractorBase.extract`` is the single per-outcome extraction
pass: load the outcome + investigation + target, render the transcript,
prompt the LLM through the idempotency cache, validate the response,
and persist each extracted pattern via the module's ``PatternStore``.
It was lifted verbatim from the byte-shared skeleton of the vr and
malware extractors; the per-module differences are expressed as class
attributes that every subclass sets:

* ``_LOG_LABEL`` -- log-line prefix (``"pattern_extractor"`` by default).
* ``_task_type`` -- the ``idempotent_llm_call`` task-type key (per module
  because cost / rate-limit routing is module-scoped).
* ``_extraction_outcome_kinds`` -- the frozenset of ``OutcomeKind`` values
  where extraction is meaningful. Every other kind returns ``skipped``.
* ``_outcome_kind_enum`` -- the module's ``OutcomeKind`` StrEnum, used to
  coerce ``outcome.outcome_kind`` (a raw string on the row) back to the
  enum for the ``should_extract`` gate.
* ``_pattern_kind_enum`` / ``_pattern_confidence_enum`` /
  ``_pattern_scope_enum`` -- the module's pattern enums. The schema
  builder emits each enum's ``.value`` list into the JSON schema so the
  LLM only picks from valid strings for that module.
* ``_pattern_create_cls`` -- the module's ``PatternCreate`` Pydantic
  model (``VRPatternCreate`` / ``MalwarePatternCreate``).
* ``_outcome_model`` / ``_investigation_model`` / ``_target_model`` /
  ``_message_model`` / ``_branch_model`` -- the module's SQLModel record
  classes, used in the read-only SELECT queries + the skip-event write.
* ``_prompt_path`` -- absolute path to the module's
  ``pattern_extraction.md`` template.

Public API kept identical to the pre-extraction modules:
``PatternExtractor``, ``PatternExtractionResult``, ``PatternExtractorError``.
Each module's thin subclass keeps the ``PatternExtractor`` class name so
existing aggregator re-exports and import sites work untouched.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

import httpx
from sqlalchemy.exc import SQLAlchemyError
from sqlmodel import select as _select

from aila.platform.agents.idempotent_llm import idempotent_llm_call
from aila.platform.contracts import utc_now
from aila.platform.contracts.enums import SenderKind
from aila.platform.contracts.mcp_payload import PayloadKind
from aila.platform.uow import UnitOfWork

__all__ = [
    "PatternExtractionResult",
    "PatternExtractorBase",
    "PatternExtractorError",
]

_log = logging.getLogger(__name__)

_MAX_TRANSCRIPT_CHARS = 30000  # cap to keep extraction prompt under budget
# fix §194 -- split the budget into a head + tail window so the seed
# prompt (lives in the first ~2000 chars) survives long investigations.
_TRANSCRIPT_HEAD_CHARS = 5000
_TRANSCRIPT_TAIL_CHARS = _MAX_TRANSCRIPT_CHARS - _TRANSCRIPT_HEAD_CHARS  # 25000
# fix §193 -- bound the SQL fetch. Investigations rarely exceed a few
# thousand messages; 5000 is a generous cap that keeps the worst-case
# materialisation under ~10MB at typical per-row sizes.
_TRANSCRIPT_ROW_LIMIT = 5000


class PatternExtractorError(Exception):
    """Raised when extraction can't proceed (missing rows / malformed LLM output)."""


@dataclass(slots=True)
class PatternExtractionResult:
    """Result of one extraction pass."""

    outcome_id: str
    investigation_id: str
    extracted_count: int
    pattern_ids: list[str]
    skipped_reason: str = ""


class PatternExtractorBase:
    """Extract reusable patterns from a successful investigation.

    Construction takes an ``llm_client`` (with a ``chat_json`` method)
    and the module's ``PatternStore``. Tests inject fakes for both.
    Subclasses set the class attributes documented on the module
    docstring; everything else is shared.
    """

    _LOG_LABEL: ClassVar[str] = "pattern_extractor"
    # Subclasses set the following (declared here for readers; the
    # methods below reach them off ``cls`` / ``self`` at call time).
    _task_type: ClassVar[str]
    _extraction_outcome_kinds: ClassVar[frozenset[Any]]
    _outcome_kind_enum: ClassVar[type[Any]]
    _pattern_kind_enum: ClassVar[type[Any]]
    _pattern_confidence_enum: ClassVar[type[Any]]
    _pattern_scope_enum: ClassVar[type[Any]]
    _pattern_create_cls: ClassVar[type[Any]]
    _outcome_model: ClassVar[type[Any]]
    _investigation_model: ClassVar[type[Any]]
    _target_model: ClassVar[type[Any]]
    _message_model: ClassVar[type[Any]]
    _branch_model: ClassVar[type[Any]]
    _prompt_path: ClassVar[Path]

    def __init__(
        self,
        llm_client: Any,
        pattern_store: Any,
    ) -> None:
        self._llm = llm_client
        self._store = pattern_store

    @classmethod
    def should_extract(cls, outcome_kind: Any) -> bool:
        """Return True when this outcome kind warrants extraction."""
        return outcome_kind in cls._extraction_outcome_kinds

    async def extract(
        self,
        outcome_id: str,
        team_id: str | None,
    ) -> PatternExtractionResult:
        """Run one extraction pass for a completed outcome.

        Loads the investigation transcript + outcome payload, prompts the
        LLM, validates the response, and persists each extracted pattern
        via PatternStore.create(). Empty responses are normal -- they
        return ``extracted_count=0`` with skipped_reason="".
        """
        outcome, investigation, target = await self._load(outcome_id)
        outcome_kind = self._outcome_kind_enum(outcome.outcome_kind)

        if not self.should_extract(outcome_kind):
            return PatternExtractionResult(
                outcome_id=outcome_id,
                investigation_id=investigation.id,
                extracted_count=0,
                pattern_ids=[],
                skipped_reason=f"outcome_kind={outcome_kind.value}_not_extractable",
            )

        transcript = await self._load_transcript(investigation.id)
        if not transcript.strip():
            return PatternExtractionResult(
                outcome_id=outcome_id,
                investigation_id=investigation.id,
                extracted_count=0,
                pattern_ids=[],
                skipped_reason="empty_transcript",
            )

        prompt = self._build_prompt(outcome, transcript)
        try:
            response, _ = await idempotent_llm_call(
                self._llm,
                method="chat_json",
                task_type=self._task_type,
                messages=[
                    {"role": "system", "content": "Extract reusable patterns from a security investigation."},
                    {"role": "user", "content": prompt},
                ],
                schema=self._extraction_schema(),
                investigation_id=investigation.id,
                team_id=team_id,
            )
        except (httpx.HTTPError, OSError, RuntimeError, ValueError, TypeError) as exc:
            # Broaden the narrow ``(OSError, TimeoutError, RuntimeError)``
            # filter. Pattern instance -- every LLM call site that catches
            # narrowly was missing httpx errors, pydantic validation
            # failures, JSON-decode errors raised before reaching the
            # outer parser, and provider-specific shapes. Log + re-raise
            # as PatternExtractorError so the caller sees the failure
            # type instead of crashing the worker.
            _log.warning(
                "pattern_extractor: LLM call failed outcome_id=%s err=%s",
                outcome_id, exc,
            )
            raise PatternExtractorError(
                f"LLM call failed for outcome {outcome_id}: {exc}",
            ) from exc

        if getattr(response, "disabled", False):
            # fix §192 -- surface the kill-switch skip. Previously
            # ``skipped_reason="llm_disabled"`` was returned silently:
            # the caller in investigation_emit logs the
            # PatternExtractionResult as a structured event but no
            # WARNING-level line fired and no operator-visible message
            # landed on the investigation. An operator who toggled the
            # kill switch had no in-app confirmation that pattern
            # extraction stopped happening.
            _log.warning(
                "pattern_extractor: LLM kill-switch active -- extraction "
                "skipped outcome_id=%s investigation_id=%s",
                outcome_id, investigation.id,
            )
            await self._emit_skip_event(
                investigation_id=investigation.id,
                outcome_id=outcome_id,
                reason="llm_kill_switch_active",
            )
            return PatternExtractionResult(
                outcome_id=outcome_id,
                investigation_id=investigation.id,
                extracted_count=0,
                pattern_ids=[],
                skipped_reason="llm_disabled",
            )

        try:
            parsed = json.loads(response.content)
        except json.JSONDecodeError as exc:
            raise PatternExtractorError(
                f"LLM returned non-JSON for outcome {outcome_id}: {exc}",
            ) from exc

        patterns_data = (
            parsed.get("patterns") if isinstance(parsed, dict) else parsed
        )
        if not isinstance(patterns_data, list):
            raise PatternExtractorError(
                f"LLM response is not a pattern list for outcome {outcome_id}",
            )

        persisted: list[str] = []
        for entry in patterns_data:
            if not isinstance(entry, dict):
                continue
            try:
                create_body = self._entry_to_create(
                    entry,
                    workspace_id=target.workspace_id,
                    investigation_id=investigation.id,
                )
            except (ValueError, KeyError) as exc:
                _log.warning(
                    "pattern_extractor: dropping malformed entry "
                    "outcome_id=%s err=%s entry=%r",
                    outcome_id, exc, entry,
                )
                continue

            try:
                summary = await self._store.create(create_body, team_id=team_id)
            except (OSError, RuntimeError, ValueError) as exc:
                _log.warning(
                    "pattern_extractor: store.create failed outcome_id=%s err=%s",
                    outcome_id, exc,
                )
                continue
            persisted.append(summary.id)

        _log.info(
            "pattern_extractor extracted outcome_id=%s investigation_id=%s count=%d",
            outcome_id, investigation.id, len(persisted),
        )
        return PatternExtractionResult(
            outcome_id=outcome_id,
            investigation_id=investigation.id,
            extracted_count=len(persisted),
            pattern_ids=persisted,
        )

    async def _load(
        self, outcome_id: str,
    ) -> tuple[Any, Any, Any]:
        outcome_model = self._outcome_model
        investigation_model = self._investigation_model
        target_model = self._target_model
        async with UnitOfWork() as uow:
            outcome = (await uow.session.exec(
                _select(outcome_model).where(
                    outcome_model.id == outcome_id,
                ),
            )).first()
            if outcome is None:
                raise PatternExtractorError(f"outcome {outcome_id} not found")
            investigation = (await uow.session.exec(
                _select(investigation_model).where(
                    investigation_model.id == outcome.investigation_id,
                ),
            )).first()
            if investigation is None:
                raise PatternExtractorError(
                    f"investigation {outcome.investigation_id} not found",
                )
            target = (await uow.session.exec(
                _select(target_model).where(
                    target_model.id == investigation.target_id,
                ),
            )).first()
            if target is None:
                raise PatternExtractorError(
                    f"target {investigation.target_id} not found",
                )
            return outcome, investigation, target

    async def _load_transcript(self, investigation_id: str) -> str:
        """Render the investigation's messages as a single transcript string.

        Budget is :data:`_MAX_TRANSCRIPT_CHARS`. When the full transcript
        exceeds the budget, the truncated rendering keeps:

          * the first :data:`_TRANSCRIPT_HEAD_CHARS` so the seed prompt
            (which sets the investigation's scope) survives,
          * a ``<<<...truncated N chars...>>>`` marker,
          * the last :data:`_TRANSCRIPT_TAIL_CHARS` so the final
            reasoning steps survive.

        fix §193 -- bound the SQL fetch with LIMIT. Investigations of
        ~5000 messages were materialising 20-100 MB into worker memory
        before truncation happened in Python. The LIMIT picks the
        newest messages (DESC) and reverses to chronological order
        so the head/tail rendering still matches the original
        timeline.

        fix §194 -- keep first 5000 chars + last 25000 chars (was
        last 30000). The seed prompt + initial hypothesis statement
        live in the first ~2000 chars; the previous "keep tail only"
        scheme dropped exactly the lens the extractor needs.

        fix §195 -- append the canonical outcome's ``panel_summary``
        (when present) at the END of the transcript so the extractor
        always sees the synthesised verdict regardless of where the
        message-row truncation landed.
        """
        message_model = self._message_model
        outcome_model = self._outcome_model
        async with UnitOfWork() as uow:
            rows = (await uow.session.exec(
                _select(message_model)
                .where(
                    message_model.investigation_id == investigation_id,
                )
                .order_by(message_model.created_at.desc())
                .limit(_TRANSCRIPT_ROW_LIMIT),
            )).all()
            # Newest-first fetch reverses to chronological so head/tail
            # rendering reflects the actual timeline.
            rows = list(reversed(rows))

            # fix §195 -- fetch the canonical outcome's panel_summary
            # separately and append at end. Synthesis output lives on
            # the outcome row, not on a message row, so the
            # message-table query above never includes it.
            panel_summary_row = (await uow.session.exec(
                _select(outcome_model)
                .where(
                    outcome_model.investigation_id == investigation_id,
                )
                .order_by(outcome_model.created_at.asc())
                .limit(1)
            )).first()

        parts: list[str] = []
        for row in rows:
            parts.append(
                f"[msg:{row.id} sender={row.sender_kind} kind={row.payload_kind}"
                f" turn={row.at_turn}]\n{row.payload_json or ''}\n",
            )
        full = "\n".join(parts)

        # Append the synthesis panel_summary if present (§195).
        if panel_summary_row is not None and panel_summary_row.payload_json:
            try:
                payload = json.loads(panel_summary_row.payload_json)
            except (ValueError, TypeError):
                payload = {}
            panel_summary = payload.get("panel_summary") if isinstance(payload, dict) else None
            if isinstance(panel_summary, dict):
                narrative = str(panel_summary.get("narrative") or "").strip()
                if narrative:
                    full = (
                        f"{full}\n\n"
                        f"[synthesis_panel_summary outcome_id={panel_summary_row.id}]\n"
                        f"{narrative}\n"
                    )

        if len(full) <= _MAX_TRANSCRIPT_CHARS:
            return full

        # fix §194 -- first 5000 + last 25000 with explicit truncation
        # marker. Preserves the seed prompt at the head and the final
        # reasoning at the tail.
        head = full[:_TRANSCRIPT_HEAD_CHARS]
        tail = full[-_TRANSCRIPT_TAIL_CHARS:]
        dropped = len(full) - _TRANSCRIPT_HEAD_CHARS - _TRANSCRIPT_TAIL_CHARS
        return (
            f"{head}\n\n<<<...truncated {dropped} chars "
            f"(full length {len(full)})...>>>\n\n{tail}"
        )

    def _build_prompt(self, outcome: Any, transcript: str) -> str:
        template = self._prompt_path.read_text(encoding="utf-8")
        outcome_summary = (
            f"kind={outcome.outcome_kind} confidence={outcome.confidence} "
            f"payload={outcome.payload_json or '{}'}"
        )
        return template.replace(
            "{outcome_summary}", outcome_summary,
        ).replace(
            "{transcript}", transcript,
        )

    @classmethod
    def _entry_to_create(
        cls,
        entry: dict[str, Any],
        *,
        workspace_id: str,
        investigation_id: str,
    ) -> Any:
        """Convert one LLM-emitted pattern dict into the module's PatternCreate.

        Defensive: raises ValueError on unknown enum values so the caller
        can drop the entry without crashing the whole extraction pass.
        """
        kind = cls._pattern_kind_enum(entry["kind"])
        confidence_raw = entry.get("confidence") or "medium"
        try:
            confidence = cls._pattern_confidence_enum(confidence_raw)
        except ValueError as exc:
            raise ValueError(
                f"unknown confidence {confidence_raw!r}",
            ) from exc

        summary = str(entry.get("summary") or "").strip()
        body = str(entry.get("body") or "").strip()
        if not summary or not body:
            raise ValueError("summary or body missing/empty")

        applicability = entry.get("applicability") or {}
        if not isinstance(applicability, dict):
            applicability = {}

        evidence_refs = entry.get("evidence_refs") or []
        if not isinstance(evidence_refs, list):
            evidence_refs = []

        return cls._pattern_create_cls(
            workspace_id=workspace_id,
            investigation_id=investigation_id,
            kind=kind,
            summary=summary[:512],
            body=body,
            applicability=applicability,
            confidence=confidence,
            evidence_refs=[str(r) for r in evidence_refs],
            scope=cls._pattern_scope_enum.LOCAL,
        )

    @classmethod
    def _extraction_schema(cls) -> dict[str, Any]:
        """Build the chat_json strict-mode schema from the module's enums.

        The schema is wrapped in an object with a single ``patterns``
        key because OpenAI structured output requires a top-level
        object. Enum values are derived from the module-bound
        ``_pattern_kind_enum`` + ``_pattern_confidence_enum`` so the LLM
        only picks from valid strings for that module.
        """
        return {
            "title": "PatternExtractionResponse",
            "type": "object",
            "properties": {
                "patterns": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "kind": {
                                "type": "string",
                                "enum": [k.value for k in cls._pattern_kind_enum],
                            },
                            "summary": {"type": "string", "minLength": 1},
                            "body": {"type": "string", "minLength": 1},
                            "applicability": {"type": "object"},
                            "confidence": {
                                "type": "string",
                                "enum": [c.value for c in cls._pattern_confidence_enum],
                            },
                            "evidence_refs": {
                                "type": "array",
                                "items": {"type": "string"},
                            },
                        },
                        "required": [
                            "kind",
                            "summary",
                            "body",
                            "applicability",
                            "confidence",
                            "evidence_refs",
                        ],
                        "additionalProperties": False,
                    },
                },
            },
            "required": ["patterns"],
            "additionalProperties": False,
        }

    async def _emit_skip_event(
        self, *, investigation_id: str, outcome_id: str, reason: str,
    ) -> None:
        """Write an operator-visible engine message announcing that pattern
        extraction was skipped.

        fix §192 -- kill-switch and config-disabled skips were previously
        invisible to the operator. Engine writes a text message addressed
        to the investigation's primary branch (broadcast semantics) so the
        UI conversation pane surfaces the skip alongside the rest of the
        engine's events. Best-effort: any failure inside this helper is
        swallowed so a logging failure can't derail the extraction caller.
        """
        branch_model = self._branch_model
        message_model = self._message_model
        try:
            async with UnitOfWork() as uow:
                primary_id = (await uow.session.exec(
                    _select(branch_model.id)
                    .where(branch_model.investigation_id == investigation_id)
                    .where(branch_model.parent_branch_id.is_(None))
                    .limit(1)
                )).first()
                if primary_id is None:
                    return
                payload = {
                    "text": (
                        "Pattern extraction skipped: "
                        f"{reason} (outcome_id={outcome_id})."
                    ),
                    "outcome_id": outcome_id,
                    "skip_reason": reason,
                }
                msg = message_model(
                    investigation_id=investigation_id,
                    branch_id=primary_id,
                    sender_kind=SenderKind.ENGINE.value,
                    sender_id="pattern_extractor",
                    payload_kind=PayloadKind.TEXT.value,
                    payload_json=json.dumps(payload),
                    created_at=utc_now(),
                )
                uow.session.add(msg)
                await uow.commit()
        except (SQLAlchemyError, OSError, RuntimeError, ValueError, TypeError) as exc:
            # fix §350 -- surface traceback. The skip-event emit is best-effort
            # but a recurring failure here means the operator-visible engine
            # message channel is broken, which needs the stack to diagnose.
            _log.warning(
                "pattern_extractor: failed to emit skip event "
                "investigation_id=%s outcome_id=%s err=%s",
                investigation_id, outcome_id, exc,
                exc_info=True,
            )
