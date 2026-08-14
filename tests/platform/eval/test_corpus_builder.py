"""DB-light tests for the trajectory -> SFT/DPO corpus builder (issue #158).

The builder mines the SAME substrates the transcript recorder does
(``platform_journal`` for per-turn bodies) plus each module's raw
``<module_id>_investigation_outcomes`` table for the CHOSEN vs
REJECTED preference signal. Both are exercised end-to-end here:

* Journal rows are inserted through the production
  :func:`aila.platform.services.journal.append` path so chain + hash
  invariants match a real deployment. That path does not require any
  module-specific tables.
* The outcome table is created for a synthetic module id ``test`` in
  the test DB (``test_investigation_outcomes``) via raw SQL, matching
  the four columns the builder reads (investigation_id, branch_id,
  outcome_kind, state) plus ``created_at``. The builder pulls it
  through raw SQL as well, so the fake module never touches
  ``aila.modules.*``.

The test asserts the two acceptance criteria from issue #158:

1. At least one :class:`SftRecord` is minted from the CHOSEN branch
   and its first message is the ``system`` prompt.
2. At least one :class:`DpoRecord` is emitted with ``chosen`` sourced
   from the approved branch and ``rejected`` sourced from the rejected
   sibling (the preference direction is asserted, not merely the
   existence of a pair).

No import of ``torch`` / ``trl`` / ``peft`` -- the training pipeline
lives behind the ``[training]`` optional extra and MUST NOT be
required to run the corpus builder tests.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from sqlalchemy import text as _sql_text

from aila.platform.eval.corpus import TrajectoryCorpusBuilder
from aila.platform.services.journal import JournalEntry, append
from aila.storage.database import async_session_scope

# ---------------------------------------------------------------------------
# Fixtures -- synthetic module + inserted trajectory.
# ---------------------------------------------------------------------------

_MODULE_ID = "test"
_OUTCOME_TABLE = f"{_MODULE_ID}_investigation_outcomes"


async def _create_outcome_table() -> None:
    """Provision a minimal ``test_investigation_outcomes`` table.

    Mirrors the four columns the builder reads (matches the shape
    OutcomeRecordBase declares) but skips the module-specific FKs so
    the fixture can insert orphan rows without seeding module tables.
    """
    async with async_session_scope() as session:
        await session.exec(_sql_text(
            f"CREATE TABLE IF NOT EXISTS {_OUTCOME_TABLE} ("
            "  id TEXT PRIMARY KEY,"
            "  investigation_id TEXT NOT NULL,"
            "  branch_id TEXT NOT NULL,"
            "  outcome_kind TEXT NOT NULL,"
            "  state TEXT NOT NULL,"
            "  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()"
            ")",
        ))
        await session.commit()


async def _drop_outcome_table() -> None:
    async with async_session_scope() as session:
        await session.exec(_sql_text(f"DROP TABLE IF EXISTS {_OUTCOME_TABLE}"))
        await session.commit()


async def _insert_outcome(
    *,
    investigation_id: str,
    branch_id: str,
    outcome_kind: str,
    state: str,
) -> None:
    async with async_session_scope() as session:
        await session.exec(
            _sql_text(
                f"INSERT INTO {_OUTCOME_TABLE} "  # noqa: S608 -- controlled ident
                "(id, investigation_id, branch_id, outcome_kind, state) "
                "VALUES (:id, :inv, :br, :kind, :state)",
            ).bindparams(
                id=str(uuid4()),
                inv=investigation_id,
                br=branch_id,
                kind=outcome_kind,
                state=state,
            ),
        )
        await session.commit()


async def _write_turn_journal(
    *,
    investigation_id: str,
    branch_id: str,
    turn_number: int,
    system_prompt: str,
    user_prompt: str,
    assistant_decision: dict,
) -> None:
    """Append matched llm_prompt + llm_response journal rows for one turn.

    Uses the production :func:`append` path so the row hash + seq +
    chain invariants match a real deployment. Rides the ``global``
    chain (no team_id set) which is the same fallback the LLM
    call-body writer uses when team scope is unset.
    """
    messages_body = json.dumps([
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt},
    ])
    async with async_session_scope() as session:
        await append(
            session,
            entry=JournalEntry(
                kind="llm_prompt",
                source="llm.test",
                action="llm.prompt",
                actor_kind="system",
                actor_id="test_client",
                status="ok",
                investigation_id=investigation_id,
                branch_id=branch_id,
                turn_number=turn_number,
                payload={
                    "run_id": "",
                    "model_id": "fake/test",
                    "task_type": "test",
                    "messages": messages_body,
                    "messages_meta": {"truncated": False, "original_bytes": len(messages_body)},
                    "tools": None,
                    "tools_meta": {"truncated": False, "original_bytes": 0},
                },
            ),
        )
        await append(
            session,
            entry=JournalEntry(
                kind="llm_response",
                source="llm.test",
                action="llm.response",
                actor_kind="system",
                actor_id="test_client",
                status="ok",
                investigation_id=investigation_id,
                branch_id=branch_id,
                turn_number=turn_number,
                payload={
                    "run_id": "",
                    "model_id": "fake/test",
                    "task_type": "test",
                    "response": json.dumps(assistant_decision),
                    "response_meta": {"truncated": False, "original_bytes": 128},
                    "usage": {},
                    "duration_ms": 100,
                    "status": "ok",
                },
            ),
        )
        await session.commit()


# ---------------------------------------------------------------------------
# Acceptance test -- one CHOSEN branch + one REJECTED sibling.
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_builder_emits_sft_for_chosen_and_dpo_with_correct_preference(
    test_db,
) -> None:
    """CHOSEN branch -> SftRecord; matched sibling -> DpoRecord with
    the ``chosen`` field pulled from the approved branch and the
    ``rejected`` field pulled from the rejected sibling."""
    del test_db
    investigation_id = f"inv-{uuid4().hex[:12]}"
    chosen_branch = f"br-chosen-{uuid4().hex[:8]}"
    rejected_branch = f"br-rejected-{uuid4().hex[:8]}"

    await _create_outcome_table()
    try:
        # Two turns on the CHOSEN branch so the min_turns=2 gate lets it
        # through and the terminal decision (turn 2) is the SFT+DPO
        # "chosen" text. Both llm_response bodies are JSON dicts so the
        # parseable-decision guard accepts them.
        await _write_turn_journal(
            investigation_id=investigation_id,
            branch_id=chosen_branch,
            turn_number=1,
            system_prompt="You are the security researcher persona.",
            user_prompt="Observation: candidate CVE identifier surfaced.",
            assistant_decision={"reasoning": "step 1", "command": {"tool": "search"}},
        )
        await _write_turn_journal(
            investigation_id=investigation_id,
            branch_id=chosen_branch,
            turn_number=2,
            system_prompt="You are the security researcher persona.",
            user_prompt="Observation: reproduction succeeded.",
            assistant_decision={
                "reasoning": "confirmed exploit",
                "decision": "direct_finding",
                "confidence": "high",
            },
        )
        # Rejected sibling: also two turns so the branch-turn cache has
        # a terminal decision to pair with. Its terminal body is a
        # different JSON shape so the DPO assertion can distinguish
        # chosen from rejected unambiguously.
        await _write_turn_journal(
            investigation_id=investigation_id,
            branch_id=rejected_branch,
            turn_number=1,
            system_prompt="You are the security researcher persona.",
            user_prompt="Observation: candidate CVE identifier surfaced.",
            assistant_decision={"reasoning": "step 1 alt", "command": {"tool": "grep"}},
        )
        await _write_turn_journal(
            investigation_id=investigation_id,
            branch_id=rejected_branch,
            turn_number=2,
            system_prompt="You are the security researcher persona.",
            user_prompt="Observation: reproduction failed.",
            assistant_decision={
                "reasoning": "cannot reproduce",
                "decision": "assessment_report",
                "confidence": "low",
                "rejected_marker": "SIBLING_WAS_REJECTED",
            },
        )

        await _insert_outcome(
            investigation_id=investigation_id,
            branch_id=chosen_branch,
            outcome_kind="direct_finding",
            state="approved",
        )
        await _insert_outcome(
            investigation_id=investigation_id,
            branch_id=rejected_branch,
            outcome_kind="assessment_report",
            state="rejected",
        )

        builder = TrajectoryCorpusBuilder(
            max_field_chars=4_000,
            sft_states=("approved", "dispatched"),
        )
        sft_records, dpo_records, manifest = await builder.collect(
            modules=[_MODULE_ID],
            min_turns=2,
        )

        # 1. SFT surfaced the CHOSEN branch only. The first message is
        #    the branch's shared system prompt; the assistant's terminal
        #    decision (turn 2) is present as the last assistant turn.
        chosen_sfts = [
            r for r in sft_records
            if r.meta.branch_id == chosen_branch
        ]
        assert chosen_sfts, "no SftRecord emitted for the approved branch"
        rejected_sfts = [
            r for r in sft_records
            if r.meta.branch_id == rejected_branch
        ]
        assert not rejected_sfts, (
            "SftRecord leaked from the rejected sibling -- SFT must only "
            "come from CHOSEN branches"
        )
        record = chosen_sfts[0]
        assert record.meta.module_id == _MODULE_ID
        assert record.meta.outcome_kind == "direct_finding"
        assert record.meta.outcome_state == "approved"
        assert record.messages, "SftRecord messages list is empty"
        assert record.messages[0].role == "system", (
            "the first message must be the system prompt (ShareGPT convention)"
        )
        assistants = [m for m in record.messages if m.role == "assistant"]
        assert assistants, "SftRecord has no assistant turns"
        assert "direct_finding" in assistants[-1].content, (
            "terminal assistant message must carry the chosen branch's "
            "final decision"
        )

        # 2. DPO surfaced the (chosen, rejected) pair with the correct
        #    preference direction: chosen text came from the approved
        #    branch's terminal, rejected text from the rejected sibling.
        assert dpo_records, "no DpoRecord emitted for the matched sibling pair"
        pair = dpo_records[0]
        assert "direct_finding" in pair.chosen
        assert "assessment_report" in pair.rejected
        assert "SIBLING_WAS_REJECTED" in pair.rejected, (
            "rejected text must come from the rejected sibling's terminal "
            "decision, not the chosen branch"
        )
        assert pair.meta["chosen_branch_id"] == chosen_branch
        assert pair.meta["rejected_branch_id"] == rejected_branch
        assert pair.meta["module_id"] == _MODULE_ID

        # Manifest counts line up with the extracted records.
        assert manifest.sft_count == len(sft_records)
        assert manifest.dpo_count == len(dpo_records)
        assert manifest.investigations >= 1
        assert manifest.module_breakdown.get(_MODULE_ID, 0) == len(chosen_sfts)
        assert isinstance(manifest.generated_at, datetime)
        assert manifest.generated_at.tzinfo is not None
        assert manifest.generated_at <= datetime.now(UTC)

    finally:
        await _drop_outcome_table()
