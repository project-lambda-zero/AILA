"""Tests for the RFC-08 record-replay decision harness.

Covers the four acceptance scenarios named in the RecordReplay slice:

1. Determinism -- two identical replays of the same candidate against the
   same transcript score ``determinism_score == 1.0``.
2. Faithfulness == 1.0 when the fake reproduces the recorded decision;
   < 1.0 when the fake diverges on at least one decision field.
3. ``DecisionDiff.field_diffs`` names the changed keys (per-key
   ``equal`` / ``changed`` / ``added`` / ``removed`` labels).
4. :meth:`TranscriptRecorder.record_from_history` raises
   :class:`TranscriptAssemblyError` when a required persisted source row
   is missing.

The tests inject a deterministic fake ``ReplayLLMClient`` so no real
model is ever called. The fake returns a fixed decision keyed by
prompt version, which lets the same fake power determinism (same
version = same output twice) and faithfulness (same version reproduces
the recorded decision; a different version diverges deterministically).

``async_session_scope`` is used to seed the shared substrates
(``llm_idempotency_cache``, ``llm_cost_records``) so
``record_from_history`` reads real rows written through the same code
path production uses.
"""
from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

import pytest

from aila.platform.contracts import utc_now
from aila.platform.eval.metrics import DecisionDiff, decision_field_diffs
from aila.platform.eval.replay import (
    DETERMINISM_FLOOR,
    FrozenInputs,
    ReplayHarness,
)
from aila.platform.eval.replay import (
    replay as run_replay,
)
from aila.platform.eval.runner import EvalRunner
from aila.platform.eval.transcript import (
    EvalTranscriptRecord,
    TranscriptAssemblyError,
    TranscriptRecorder,
)
from aila.platform.llm.cost_record import LLMCostRecord
from aila.platform.llm.idempotency_cache import LLMIdempotencyCache
from aila.platform.prompts.version_store import PromptVersionStore
from aila.storage.database import async_session_scope

# ---------------------------------------------------------------------------
# Fake ReplayLLMClient -- deterministic, keyed by prompt_version.
# ---------------------------------------------------------------------------


class _FakeReplayClient:
    """Deterministic fake LLM client for the replay harness.

    Constructed with a mapping ``{prompt_version: decision_dict}``. Each
    call to ``replay_decide`` returns a DEEP copy of the mapping value so
    the two determinism-scored calls produce byte-identical JSON. Records
    every call for assertions on call count + frozen-input propagation.
    """

    def __init__(self, decisions_by_version: dict[str, dict[str, Any]]) -> None:
        self._decisions = decisions_by_version
        self.calls: list[dict[str, Any]] = []

    async def replay_decide(
        self,
        *,
        prompt_key: str,
        prompt_version: str,
        prompt_body: str,
        frozen_inputs: FrozenInputs,
    ) -> dict[str, Any]:
        self.calls.append({
            "prompt_key": prompt_key,
            "prompt_version": prompt_version,
            "prompt_body": prompt_body,
            "frozen_inputs": frozen_inputs,
        })
        if prompt_version not in self._decisions:
            raise KeyError(
                f"fake replay client has no decision for version {prompt_version!r}",
            )
        # Deep-copy via json round-trip so callers can mutate results without
        # tainting the fake's fixture data; identical byte-output twice.
        return json.loads(json.dumps(self._decisions[prompt_version]))


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------


def _prompt_key() -> str:
    return f"eval/replay-{uuid4().hex[:8]}"


async def _seed_transcript(
    *,
    prompt_key: str,
    prompt_version: str,
    recorded_decision: dict[str, Any],
    investigation_id: str | None = None,
    branch_id: str | None = None,
    turn_number: int = 1,
    module_id: str = "eval-replay-test",
) -> EvalTranscriptRecord:
    """Persist a transcript with realistic frozen inputs and return it."""
    inv = investigation_id or f"inv-{uuid4().hex[:8]}"
    branch = branch_id or f"branch-{uuid4().hex[:8]}"
    request_payload = {
        "task_type": "audit",
        "model_id": "test-model",
        "messages": json.dumps([
            {"role": "system", "content": "recorded system prompt"},
            {"role": "user", "content": "recorded user context"},
        ]),
    }
    retrieval_hits = [
        {"id": "hit-1", "score": 0.9, "snippet": "recorded retrieval hit"},
    ]
    tool_outputs = [
        {"tool": "code_search.query", "args": {"q": "recorded"}, "output": {"n": 1}},
    ]
    llm_response = {
        "content": json.dumps(recorded_decision),
        "model": "test-model",
        "finish_reason": "stop",
    }
    record = EvalTranscriptRecord(
        investigation_id=inv,
        branch_id=branch,
        turn_number=turn_number,
        module_id=module_id,
        recorded_clock=utc_now(),
        retrieval_hits_json=json.dumps(retrieval_hits),
        tool_outputs_json=json.dumps(tool_outputs),
        llm_request_json=json.dumps(request_payload),
        llm_response_json=json.dumps(llm_response),
        recorded_decision_json=json.dumps(recorded_decision),
        prompt_key=prompt_key,
        prompt_version=prompt_version,
    )
    async with async_session_scope() as session:
        session.add(record)
        await session.commit()
        await session.refresh(record)
    return record


# ---------------------------------------------------------------------------
# 1. Determinism -- two identical replays => 1.0.
# ---------------------------------------------------------------------------


async def test_determinism_score_is_one_for_two_identical_replays(test_db) -> None:
    del test_db
    key = _prompt_key()
    store = PromptVersionStore()
    v_original = await store.register(key, "ORIGINAL BODY", author="test")
    v_candidate = await store.register(key, "CANDIDATE BODY", author="test")

    recorded_decision = {"verdict": "accept", "confidence": 0.8, "notes": "recorded"}
    transcript = await _seed_transcript(
        prompt_key=key,
        prompt_version=v_original,
        recorded_decision=recorded_decision,
    )

    # Same decision for both versions so faithfulness is also 1.0 in this
    # test; the determinism assertion is what we're proving here.
    fake = _FakeReplayClient({
        v_original: recorded_decision,
        v_candidate: {"verdict": "accept", "confidence": 0.85, "notes": "candidate"},
    })

    diff = await run_replay(
        transcript_id=transcript.id,
        candidate_version=v_candidate,
        llm_client=fake,
    )

    assert isinstance(diff, DecisionDiff)
    assert diff.transcript_id == transcript.id
    assert diff.determinism_score == 1.0
    assert diff.determinism_score >= DETERMINISM_FLOOR
    # Three calls: candidate x2 for determinism + original x1 for faithfulness.
    assert len(fake.calls) == 3
    versions_called = [call["prompt_version"] for call in fake.calls]
    assert versions_called[0] == v_candidate
    assert versions_called[1] == v_candidate
    assert versions_called[2] == v_original

    # Frozen inputs propagate: same recorded_clock + same retrieval hits +
    # same tool outputs on every call.
    for call in fake.calls:
        frozen = call["frozen_inputs"]
        assert frozen.clock.now() == transcript.recorded_clock
        assert len(frozen.retrieval.hits()) == 1
        assert frozen.retrieval.hits()[0]["id"] == "hit-1"
        assert len(frozen.tools.outputs()) == 1
        assert frozen.tools.outputs()[0]["tool"] == "code_search.query"


# ---------------------------------------------------------------------------
# 2. Faithfulness -- 1.0 on match, <1.0 on divergence.
# ---------------------------------------------------------------------------


async def test_faithfulness_is_one_when_fake_reproduces_recorded_decision(test_db) -> None:
    del test_db
    key = _prompt_key()
    store = PromptVersionStore()
    v_original = await store.register(key, "ORIGINAL BODY", author="test")
    v_candidate = await store.register(key, "CANDIDATE BODY", author="test")

    recorded_decision = {"verdict": "reject", "confidence": 0.7, "notes": "recorded"}
    transcript = await _seed_transcript(
        prompt_key=key,
        prompt_version=v_original,
        recorded_decision=recorded_decision,
    )

    fake = _FakeReplayClient({
        v_original: recorded_decision,
        v_candidate: recorded_decision,
    })
    diff = await run_replay(
        transcript_id=transcript.id,
        candidate_version=v_candidate,
        llm_client=fake,
    )
    assert diff.faithfulness == 1.0
    assert diff.faithful is True
    # Every field labels as 'equal'.
    assert set(diff.field_diffs.values()) == {"equal"}


async def test_faithfulness_less_than_one_when_replay_diverges(test_db) -> None:
    del test_db
    key = _prompt_key()
    store = PromptVersionStore()
    v_original = await store.register(key, "ORIGINAL BODY", author="test")
    v_candidate = await store.register(key, "CANDIDATE BODY", author="test")

    recorded_decision = {
        "verdict": "accept",
        "confidence": 0.9,
        "notes": "recorded",
    }
    divergent_replay = {
        "verdict": "reject",             # CHANGED
        "confidence": 0.9,               # equal
        "reason": "policy overturned",   # ADDED
        # 'notes' removed from the replayed decision.
    }
    transcript = await _seed_transcript(
        prompt_key=key,
        prompt_version=v_original,
        recorded_decision=recorded_decision,
    )
    fake = _FakeReplayClient({
        v_original: divergent_replay,   # faithfulness pass diverges from recorded
        v_candidate: divergent_replay,
    })
    diff = await run_replay(
        transcript_id=transcript.id,
        candidate_version=v_candidate,
        llm_client=fake,
    )
    assert diff.faithful is False
    assert 0.0 < diff.faithfulness < 1.0
    # Determinism still 1.0: both candidate calls return the same body.
    assert diff.determinism_score == 1.0

    # field_diffs names the changed keys explicitly.
    assert diff.field_diffs["verdict"] == "changed"
    assert diff.field_diffs["confidence"] == "equal"
    assert diff.field_diffs["reason"] == "added"
    assert diff.field_diffs["notes"] == "removed"

    # The recorded and replayed decisions are exposed on the diff so a
    # reviewer can eyeball the change without re-reading the transcript.
    assert diff.recorded_decision == recorded_decision
    assert diff.replayed_decision == divergent_replay


# ---------------------------------------------------------------------------
# 3. decision_field_diffs helper -- direct assertions on the pure function.
# ---------------------------------------------------------------------------


def test_decision_field_diffs_labels_every_key() -> None:
    recorded = {"a": 1, "b": 2, "c": 3}
    replayed = {"a": 1, "b": 99, "d": 4}
    diffs = decision_field_diffs(recorded, replayed)
    assert diffs == {
        "a": "equal",
        "b": "changed",
        "c": "removed",
        "d": "added",
    }


# ---------------------------------------------------------------------------
# 4. record_from_history raises when required source rows are missing.
# ---------------------------------------------------------------------------


async def test_record_from_history_raises_when_idempotency_cache_row_missing(
    test_db,
) -> None:
    del test_db
    recorder = TranscriptRecorder()
    with pytest.raises(TranscriptAssemblyError) as excinfo:
        await recorder.record_from_history(
            investigation_id=f"inv-{uuid4().hex[:8]}",
            branch_id=f"branch-{uuid4().hex[:8]}",
            turn_number=1,
            module_id="eval-replay-test",
        )
    assert "llm_idempotency_cache" in str(excinfo.value)


async def test_record_from_history_raises_when_cost_record_missing(test_db) -> None:
    del test_db
    inv = f"inv-{uuid4().hex[:8]}"
    branch = f"branch-{uuid4().hex[:8]}"
    turn = 3

    # Seed only the idempotency cache -- no cost record, so prompt_version is
    # unresolvable and the recorder must raise.
    async with async_session_scope() as session:
        session.add(LLMIdempotencyCache(
            request_key=uuid4().hex,
            investigation_id=inv,
            branch_id=branch,
            turn_number=turn,
            response_json=json.dumps({
                "content": json.dumps({"verdict": "accept"}),
                "model": "test-model",
                "finish_reason": "stop",
            }),
            expires_at=utc_now() + timedelta(days=7),
        ))
        await session.commit()

    recorder = TranscriptRecorder()
    with pytest.raises(TranscriptAssemblyError) as excinfo:
        await recorder.record_from_history(
            investigation_id=inv,
            branch_id=branch,
            turn_number=turn,
            module_id="eval-replay-test",
        )
    assert "llm_cost_record" in str(excinfo.value)


async def test_record_from_history_persists_row_when_required_sources_present(
    test_db,
) -> None:
    """A happy path complement so the raises tests aren't isolated."""
    del test_db
    inv = f"inv-{uuid4().hex[:8]}"
    branch = f"branch-{uuid4().hex[:8]}"
    turn = 7
    module_id = "eval-replay-test"
    prompt_version = "1.0.42"
    recorded_decision = {"verdict": "accept", "confidence": 0.5}

    cache_created_at = datetime.now(tz=UTC)
    async with async_session_scope() as session:
        session.add(LLMIdempotencyCache(
            request_key=uuid4().hex,
            investigation_id=inv,
            branch_id=branch,
            turn_number=turn,
            response_json=json.dumps({
                "content": json.dumps(recorded_decision),
                "model": "test-model",
                "finish_reason": "stop",
            }),
            created_at=cache_created_at,
            expires_at=cache_created_at + timedelta(days=7),
        ))
        session.add(LLMCostRecord(
            run_id="_no_run",
            investigation_id=inv,
            branch_id=branch,
            turn_number=turn,
            prompt_version=prompt_version,
            model_id="test-model",
            task_type="audit",
        ))
        await session.commit()

    recorder = TranscriptRecorder()
    transcript_id = await recorder.record_from_history(
        investigation_id=inv,
        branch_id=branch,
        turn_number=turn,
        module_id=module_id,
    )
    async with async_session_scope() as session:
        row = await session.get(EvalTranscriptRecord, transcript_id)
    assert row is not None
    assert row.investigation_id == inv
    assert row.branch_id == branch
    assert row.turn_number == turn
    assert row.module_id == module_id
    assert row.prompt_version == prompt_version
    # prompt_key follows the f"{module_id}/{task_type}" convention when the
    # caller does not override it.
    assert row.prompt_key == f"{module_id}/audit"
    assert json.loads(row.recorded_decision_json) == recorded_decision


# ---------------------------------------------------------------------------
# EvalRunner.replay -- thin delegate; verify it wires correctly.
# ---------------------------------------------------------------------------


async def test_eval_runner_replay_delegates_to_harness(test_db) -> None:
    del test_db
    key = _prompt_key()
    store = PromptVersionStore()
    v_original = await store.register(key, "ORIGINAL BODY", author="test")
    v_candidate = await store.register(key, "CANDIDATE BODY", author="test")

    recorded_decision = {"verdict": "accept"}
    transcript = await _seed_transcript(
        prompt_key=key,
        prompt_version=v_original,
        recorded_decision=recorded_decision,
    )
    fake = _FakeReplayClient({
        v_original: recorded_decision,
        v_candidate: recorded_decision,
    })
    runner = EvalRunner(store)
    diff = await runner.replay(
        transcript_id=transcript.id,
        candidate_version=v_candidate,
        llm_client=fake,
    )
    assert isinstance(diff, DecisionDiff)
    assert diff.determinism_score == 1.0
    assert diff.faithfulness == 1.0


async def test_replay_harness_frozen_inputs_are_immutable_and_present(
    test_db,
) -> None:
    """The FrozenInputs bundle exposes clock + retrieval + tools; is frozen."""
    del test_db
    key = _prompt_key()
    store = PromptVersionStore()
    v_original = await store.register(key, "ORIGINAL BODY", author="test")
    v_candidate = await store.register(key, "CANDIDATE BODY", author="test")

    recorded_decision = {"verdict": "accept"}
    transcript = await _seed_transcript(
        prompt_key=key,
        prompt_version=v_original,
        recorded_decision=recorded_decision,
    )
    fake = _FakeReplayClient({
        v_original: recorded_decision,
        v_candidate: recorded_decision,
    })
    harness = ReplayHarness(version_store=store)
    diff = await harness.replay(
        transcript_id=transcript.id,
        candidate_version=v_candidate,
        llm_client=fake,
    )
    assert diff.faithful is True

    # Every recorded call saw the SAME frozen instances (structural
    # equality) and the frozen dataclasses reject mutation.
    frozen = fake.calls[0]["frozen_inputs"]
    with pytest.raises(Exception):
        # Frozen dataclass: rebinding a slot raises FrozenInstanceError.
        frozen.clock.recorded_at = utc_now()
