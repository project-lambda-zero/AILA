"""Pattern extractor — runs at investigation completion (GA-42).

When a successful investigation closes with a positive outcome, this
agent re-prompts the LLM with the full reasoning transcript + the
outcome summary and asks: "Extract reusable patterns the team should
keep." Extracted patterns enter ``status=draft`` + ``scope=local`` and
become visible in the operator review queue.

Design contract — DO NOT relax these without updating the prompt:
  - Returns an empty list when nothing reusable was learned. Empty is OK.
  - Each pattern's ``evidence_refs`` must point at real message/outcome
    ids from the transcript.
  - Patterns persist immediately as ``draft`` so operator review is
    mandatory before any cross-investigation reuse.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sqlmodel import select as _select

from aila.modules.vr.contracts.outcome import OutcomeKind
from aila.modules.vr.contracts.pattern import (
    PatternConfidence,
    PatternKind,
    PatternScope,
    VRPatternCreate,
)
from aila.modules.vr.db_models import (
    VRInvestigationMessageRecord,
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
    VRTargetRecord,
)
from aila.modules.vr.services.pattern_store import PatternStore
from aila.platform.uow import UnitOfWork

__all__ = [
    "PatternExtractionResult",
    "PatternExtractor",
    "PatternExtractorError",
]

_log = logging.getLogger(__name__)

_PROMPT_PATH = Path(__file__).parent / "prompts" / "pattern_extraction.md"
_MAX_TRANSCRIPT_CHARS = 30000  # cap to keep extraction prompt under budget

# Outcome kinds where pattern extraction is meaningful. AUDIT_MEMO is
# explicitly INCLUDED — negative audits still encode reusable search
# heuristics + triage rules. ASSESSMENT_REPORT is excluded (low-signal
# self-aborts). VARIANT_HUNT_ORDER is excluded (the child investigation
# is what produces patterns, not the spawning order).
_EXTRACTION_OUTCOME_KINDS: frozenset[OutcomeKind] = frozenset({
    OutcomeKind.DIRECT_FINDING,
    OutcomeKind.AUDIT_MEMO,
    OutcomeKind.CRASH_TRIAGE_REPORT,
    OutcomeKind.PROFILE_SPEC_DRAFT,
    OutcomeKind.STRATEGY_DESCRIPTOR,
    OutcomeKind.PATCH_ASSESSMENT_REPORT,
})


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


class PatternExtractor:
    """Extract reusable patterns from a successful investigation.

    Construction takes an ``llm_client`` (with a ``chat_json`` method)
    and a ``PatternStore``. Tests inject fakes for both.
    """

    def __init__(
        self,
        llm_client: Any,
        pattern_store: PatternStore,
    ) -> None:
        self._llm = llm_client
        self._store = pattern_store

    @classmethod
    def should_extract(cls, outcome_kind: OutcomeKind) -> bool:
        """Return True when this outcome kind warrants extraction."""
        return outcome_kind in _EXTRACTION_OUTCOME_KINDS

    async def extract(
        self,
        outcome_id: str,
        team_id: str | None,
    ) -> PatternExtractionResult:
        """Run one extraction pass for a completed outcome.

        Loads the investigation transcript + outcome payload, prompts the
        LLM, validates the response, and persists each extracted pattern
        via PatternStore.create(). Empty responses are normal — they
        return ``extracted_count=0`` with skipped_reason="".
        """
        outcome, investigation, target = await self._load(outcome_id)
        outcome_kind = OutcomeKind(outcome.outcome_kind)

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

        prompt = _build_prompt(outcome, transcript)
        try:
            response = await self._llm.chat_json(
                task_type="vulnerability_research.pattern_extraction",
                messages=[
                    {"role": "system", "content": "Extract reusable patterns from a security investigation."},
                    {"role": "user", "content": prompt},
                ],
                schema=_EXTRACTION_SCHEMA,
            )
        except Exception as exc:  # noqa: BLE001 — fix §191
            # Broaden the narrow ``(OSError, TimeoutError, RuntimeError)``
            # filter. Pattern instance — every LLM call site that catches
            # narrowly was missing httpx errors, pydantic validation
            # failures, JSON-decode errors raised before reaching the
            # outer parser, and provider-specific shapes. Log + re-raise
            # as PatternExtractorError so the caller sees the failure
            # class instead of crashing the worker.
            _log.warning(
                "pattern_extractor: LLM call failed outcome_id=%s err=%s",
                outcome_id, exc,
            )
            raise PatternExtractorError(
                f"LLM call failed for outcome {outcome_id}: {exc}",
            ) from exc

        if getattr(response, "disabled", False):
            # fix §192 — surface the kill-switch skip. Previously
            # ``skipped_reason="llm_disabled"`` was returned silently:
            # the caller in investigation_emit logs the
            # PatternExtractionResult as a structured event but no
            # WARNING-level line fired and no operator-visible message
            # landed on the investigation. An operator who toggled the
            # kill switch had no in-app confirmation that pattern
            # extraction stopped happening.
            _log.warning(
                "pattern_extractor: LLM kill-switch active — extraction "
                "skipped outcome_id=%s investigation_id=%s",
                outcome_id, investigation.id,
            )
            await _emit_skip_event(
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
                create_body = _entry_to_create(
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
    ) -> tuple[
        VRInvestigationOutcomeRecord,
        VRInvestigationRecord,
        VRTargetRecord,
    ]:
        async with UnitOfWork() as uow:
            outcome = (await uow.session.exec(
                _select(VRInvestigationOutcomeRecord).where(
                    VRInvestigationOutcomeRecord.id == outcome_id,
                ),
            )).first()
            if outcome is None:
                raise PatternExtractorError(f"outcome {outcome_id} not found")
            investigation = (await uow.session.exec(
                _select(VRInvestigationRecord).where(
                    VRInvestigationRecord.id == outcome.investigation_id,
                ),
            )).first()
            if investigation is None:
                raise PatternExtractorError(
                    f"investigation {outcome.investigation_id} not found",
                )
            target = (await uow.session.exec(
                _select(VRTargetRecord).where(
                    VRTargetRecord.id == investigation.target_id,
                ),
            )).first()
            if target is None:
                raise PatternExtractorError(
                    f"target {investigation.target_id} not found",
                )
            return outcome, investigation, target

    async def _load_transcript(self, investigation_id: str) -> str:
        """Render the investigation's messages as a single transcript string.

        Truncated to ``_MAX_TRANSCRIPT_CHARS`` from the END (most recent
        messages preserved) so the extraction prompt stays under budget
        even for long investigations. The outcome summary is the lens —
        the model can extract patterns even from a tail slice.
        """
        async with UnitOfWork() as uow:
            rows = (await uow.session.exec(
                _select(VRInvestigationMessageRecord)
                .where(
                    VRInvestigationMessageRecord.investigation_id == investigation_id,
                )
                .order_by(VRInvestigationMessageRecord.created_at.asc()),
            )).all()

        parts: list[str] = []
        for row in rows:
            parts.append(
                f"[msg:{row.id} sender={row.sender_kind} kind={row.payload_kind}"
                f" turn={row.at_turn}]\n{row.payload_json or ''}\n",
            )
        full = "\n".join(parts)
        if len(full) <= _MAX_TRANSCRIPT_CHARS:
            return full
        return (
            f"[transcript truncated to last {_MAX_TRANSCRIPT_CHARS} chars; "
            f"full length {len(full)}]\n"
            + full[-_MAX_TRANSCRIPT_CHARS:]
        )


def _build_prompt(
    outcome: VRInvestigationOutcomeRecord,
    transcript: str,
) -> str:
    template = _PROMPT_PATH.read_text(encoding="utf-8")
    outcome_summary = (
        f"kind={outcome.outcome_kind} confidence={outcome.confidence} "
        f"payload={outcome.payload_json or '{}'}"
    )
    return template.replace(
        "{outcome_summary}", outcome_summary,
    ).replace(
        "{transcript}", transcript,
    )


def _entry_to_create(
    entry: dict[str, Any],
    *,
    workspace_id: str,
    investigation_id: str,
) -> VRPatternCreate:
    """Convert one LLM-emitted pattern dict into a VRPatternCreate.

    Defensive: raises ValueError on unknown enum values so the caller
    can drop the entry without crashing the whole extraction pass.
    """
    kind = PatternKind(entry["kind"])
    confidence_raw = entry.get("confidence") or "medium"
    try:
        confidence = PatternConfidence(confidence_raw)
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

    return VRPatternCreate(
        workspace_id=workspace_id,
        investigation_id=investigation_id,
        kind=kind,
        summary=summary[:512],
        body=body,
        applicability=applicability,
        confidence=confidence,
        evidence_refs=[str(r) for r in evidence_refs],
        scope=PatternScope.LOCAL,
    )


# JSON schema for chat_json strict-mode enforcement. Wrapped in an
# object with a single "patterns" key because OpenAI structured output
# requires a top-level object.
_EXTRACTION_SCHEMA: dict[str, Any] = {
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
                        "enum": [k.value for k in PatternKind],
                    },
                    "summary": {"type": "string", "minLength": 1},
                    "body": {"type": "string", "minLength": 1},
                    "applicability": {"type": "object"},
                    "confidence": {
                        "type": "string",
                        "enum": [c.value for c in PatternConfidence],
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
    *, investigation_id: str, outcome_id: str, reason: str,
) -> None:
    """Write an operator-visible engine message announcing that pattern
    extraction was skipped.

    fix §192 — kill-switch and config-disabled skips were previously
    invisible to the operator. Engine writes a text message addressed
    to the investigation's primary branch (broadcast semantics) so the
    UI conversation pane surfaces the skip alongside the rest of the
    engine's events. Best-effort: any failure inside this helper is
    swallowed so a logging failure can't derail the extraction caller.
    """
    from aila.modules.vr.contracts import PayloadKind, SenderKind  # noqa: PLC0415
    from aila.modules.vr.db_models import VRInvestigationBranchRecord  # noqa: PLC0415
    from aila.platform.contracts._common import utc_now  # noqa: PLC0415

    try:
        async with UnitOfWork() as uow:
            primary_id = (await uow.session.exec(
                _select(VRInvestigationBranchRecord.id)
                .where(VRInvestigationBranchRecord.investigation_id == investigation_id)
                .where(VRInvestigationBranchRecord.parent_branch_id.is_(None))
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
            msg = VRInvestigationMessageRecord(
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
    except Exception as exc:  # noqa: BLE001 — visibility helper must not crash caller
        _log.warning(
            "pattern_extractor: failed to emit skip event "
            "investigation_id=%s outcome_id=%s err=%s",
            investigation_id, outcome_id, exc,
        )
