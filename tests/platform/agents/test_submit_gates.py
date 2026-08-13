"""Tests for the defense-check submit gate (RFC #94).

Verifies that the gate rejects findings when the branch's tool-call
history is missing allocator reads, input-range reads, or callers_of
reachability traces.

Issue #136 moved the allocator / input-reader vocabulary out of the
platform gate constants and onto module-supplied ClassVars
(:attr:`AgentTurnRunnerBase.known_allocators` /
:attr:`AgentTurnRunnerBase.known_input_readers`). The gate now takes
those sets as keyword arguments; VR's vocabulary is imported here so
the historical VR behavior stays testable, and separate tests cover
the empty-vocabulary graceful-degradation contract.
"""
from __future__ import annotations

import json

import pytest

from aila.modules.vr.agents.vuln_researcher import HonestVulnResearcher
from aila.platform.agents.submit_gates import (
    check_defense_verification,
    classify_claim,
)

# VR's ClassVar-supplied vocabulary. Sourced directly from the researcher
# so a rename or deletion on the module side surfaces here as a test
# failure rather than a silent divergence.
_VR_KNOWN_ALLOCATORS = HonestVulnResearcher.known_allocators
_VR_INPUT_READERS = HonestVulnResearcher.known_input_readers


class TestClaimClassifier:
    def test_overflow_from_answer(self) -> None:
        assert classify_claim("direct_finding", {
            "answer": "Integer overflow in the allocation path.",
        }) == "overflow"

    def test_heap_oob_from_answer(self) -> None:
        assert classify_claim("direct_finding", {
            "answer": "Heap OOB write via unchecked index.",
        }) == "heap_oob"

    def test_bypass_from_answer(self) -> None:
        assert classify_claim("direct_finding", {
            "answer": "The data: protocol bypass allows...",
        }) == "bypass"

    def test_uaf_from_answer(self) -> None:
        assert classify_claim("direct_finding", {
            "answer": "Use-after-free in the connection handler.",
        }) == "uaf"

    def test_generic_fallback(self) -> None:
        assert classify_claim("direct_finding", {
            "answer": "The function does something bad.",
        }) == "generic"

    def test_audit_memo_always_none(self) -> None:
        assert classify_claim("audit_memo", {
            "answer": "Integer overflow in the allocation path.",
        }) == "none"

    def test_empty_answer(self) -> None:
        assert classify_claim("direct_finding", {}) == "generic"


# -- Mock session for DB queries --

class _FakeResult:
    def __init__(self, rows: list[tuple[str]]) -> None:
        self._rows = rows

    def all(self) -> list[tuple[str]]:
        return self._rows


class _FakeSession:
    def __init__(self, tool_calls: list[dict]) -> None:
        self._rows = [
            (json.dumps({"command": json.dumps(tc)}),) for tc in tool_calls
        ]

    async def execute(self, stmt) -> _FakeResult:
        return _FakeResult(self._rows)


def _session(tool_calls: list[dict]) -> _FakeSession:
    return _FakeSession(tool_calls)


class TestDefenseVerificationWithVRVocabulary:
    """Behavior preservation: with VR's vocabulary, the gate matches
    the pre-refactor VR outcomes exactly (RFC #94, issue #136)."""

    @pytest.mark.asyncio
    async def test_generic_claim_always_passes(self) -> None:
        ok, msg = await check_defense_verification(
            session=_session([]),
            branch_id="b1",
            claim_class="generic",
            message_table="vr_investigation_messages",
            known_allocators=_VR_KNOWN_ALLOCATORS,
            known_input_readers=_VR_INPUT_READERS,
        )
        assert ok is True

    @pytest.mark.asyncio
    async def test_none_claim_always_passes(self) -> None:
        ok, msg = await check_defense_verification(
            session=_session([]),
            branch_id="b1",
            claim_class="none",
            message_table="vr_investigation_messages",
            known_allocators=_VR_KNOWN_ALLOCATORS,
            known_input_readers=_VR_INPUT_READERS,
        )
        assert ok is True

    @pytest.mark.asyncio
    async def test_overflow_rejected_without_allocator_read(self) -> None:
        ok, msg = await check_defense_verification(
            session=_session([
                {"tool": "audit_mcp.semantic_search", "args": {}},
                {"tool": "audit_mcp.read_function", "args": {"name": "mov_read_senc"}},
                {"tool": "audit_mcp.callers_of", "args": {"name": "mov_read_senc"}},
            ]),
            branch_id="b1",
            claim_class="overflow",
            message_table="vr_investigation_messages",
            known_allocators=_VR_KNOWN_ALLOCATORS,
            known_input_readers=_VR_INPUT_READERS,
        )
        assert ok is False
        assert "allocator" in msg.lower()

    @pytest.mark.asyncio
    async def test_overflow_rejected_without_input_reader(self) -> None:
        ok, msg = await check_defense_verification(
            session=_session([
                {"tool": "audit_mcp.read_function", "args": {"name": "av_calloc"}},
                {"tool": "audit_mcp.callers_of", "args": {"name": "mov_read_senc"}},
            ]),
            branch_id="b1",
            claim_class="overflow",
            message_table="vr_investigation_messages",
            known_allocators=_VR_KNOWN_ALLOCATORS,
            known_input_readers=_VR_INPUT_READERS,
        )
        assert ok is False
        assert "bit-width" in msg.lower() or "input reader" in msg.lower()

    @pytest.mark.asyncio
    async def test_overflow_accepted_with_full_verification(self) -> None:
        ok, msg = await check_defense_verification(
            session=_session([
                {"tool": "audit_mcp.read_function", "args": {"name": "av_calloc"}},
                {"tool": "audit_mcp.read_function", "args": {"name": "avio_rb16"}},
                {"tool": "audit_mcp.callers_of", "args": {"name": "mov_read_senc"}},
            ]),
            branch_id="b1",
            claim_class="overflow",
            message_table="vr_investigation_messages",
            known_allocators=_VR_KNOWN_ALLOCATORS,
            known_input_readers=_VR_INPUT_READERS,
        )
        assert ok is True
        assert msg is None

    @pytest.mark.asyncio
    async def test_bypass_rejected_without_callers_of(self) -> None:
        ok, msg = await check_defense_verification(
            session=_session([
                {"tool": "audit_mcp.read_function", "args": {"name": "open_url"}},
                {"tool": "audit_mcp.semantic_search", "args": {}},
            ]),
            branch_id="b1",
            claim_class="bypass",
            message_table="vr_investigation_messages",
            known_allocators=_VR_KNOWN_ALLOCATORS,
            known_input_readers=_VR_INPUT_READERS,
        )
        assert ok is False
        assert "callers_of" in msg

    @pytest.mark.asyncio
    async def test_bypass_accepted_with_callers_of(self) -> None:
        ok, msg = await check_defense_verification(
            session=_session([
                {"tool": "audit_mcp.read_function", "args": {"name": "open_url"}},
                {"tool": "audit_mcp.callers_of", "args": {"name": "open_url"}},
            ]),
            branch_id="b1",
            claim_class="bypass",
            message_table="vr_investigation_messages",
            known_allocators=_VR_KNOWN_ALLOCATORS,
            known_input_readers=_VR_INPUT_READERS,
        )
        assert ok is True

    @pytest.mark.asyncio
    async def test_empty_history_rejected(self) -> None:
        ok, msg = await check_defense_verification(
            session=_session([]),
            branch_id="b1",
            claim_class="overflow",
            message_table="vr_investigation_messages",
            known_allocators=_VR_KNOWN_ALLOCATORS,
            known_input_readers=_VR_INPUT_READERS,
        )
        assert ok is False

    @pytest.mark.asyncio
    async def test_vr_vocabulary_covers_known_names(self) -> None:
        # Guard against a silent vocabulary regression on the VR
        # subclass -- if any of these disappear, the gate stops
        # recognising the historical live-behavior allocator or
        # input-reader names on VR.
        assert "av_calloc" in _VR_KNOWN_ALLOCATORS
        assert "malloc" in _VR_KNOWN_ALLOCATORS
        assert "ngx_palloc" in _VR_KNOWN_ALLOCATORS
        assert "kmalloc" in _VR_KNOWN_ALLOCATORS
        assert "OPENSSL_malloc" in _VR_KNOWN_ALLOCATORS
        assert "avio_rb16" in _VR_INPUT_READERS
        assert "get_bits" in _VR_INPUT_READERS


class TestDefenseVerificationWithEmptyVocabulary:
    """Empty-vocabulary graceful degradation (issue #136).

    A module that supplies no allocator / reader vocabulary (malware,
    forensics, hello_world today) must not crash and must not have its
    overflow-shaped submits blocked by a check whose vocabulary it
    doesn't participate in. The reachability check
    (``callers_of``) still runs for every claim.
    """

    @pytest.mark.asyncio
    async def test_overflow_accepted_without_vocab_when_callers_of_present(
        self,
    ) -> None:
        # No allocator / no reader read -- but callers_of was called,
        # so the reachability check passes and the gate does not
        # reject.
        ok, msg = await check_defense_verification(
            session=_session([
                {"tool": "audit_mcp.callers_of", "args": {"name": "somefunc"}},
            ]),
            branch_id="b1",
            claim_class="overflow",
            message_table="vr_investigation_messages",
            # empty vocab defaults
        )
        assert ok is True
        assert msg is None

    @pytest.mark.asyncio
    async def test_overflow_rejected_without_callers_of_even_when_vocab_empty(
        self,
    ) -> None:
        # The reachability check is domain-neutral -- it fires for
        # every claim regardless of vocabulary.
        ok, msg = await check_defense_verification(
            session=_session([
                {"tool": "audit_mcp.read_function", "args": {"name": "anything"}},
            ]),
            branch_id="b1",
            claim_class="overflow",
            message_table="vr_investigation_messages",
        )
        assert ok is False
        assert "callers_of" in msg

    @pytest.mark.asyncio
    async def test_empty_vocab_partial_coverage_still_gates_populated_side(
        self,
    ) -> None:
        # A module that publishes only the allocator side still gets
        # its allocator check; the input-reader side (empty) is a
        # no-op. Exercises the per-side gating in the gate.
        ok, msg = await check_defense_verification(
            session=_session([
                {"tool": "audit_mcp.callers_of", "args": {"name": "f"}},
            ]),
            branch_id="b1",
            claim_class="overflow",
            message_table="vr_investigation_messages",
            known_allocators=frozenset({"my_alloc"}),
            # readers empty -> reader check skipped
        )
        assert ok is False
        assert "allocator" in msg.lower()
