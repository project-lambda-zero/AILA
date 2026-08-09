"""Tests for the defense-check submit gate (RFC #94).

Verifies that the gate rejects findings when the branch's tool-call
history is missing allocator reads, input-range reads, or callers_of
reachability traces.
"""
from __future__ import annotations

import json

import pytest

from aila.platform.agents.submit_gates import (
    INPUT_READERS,
    KNOWN_ALLOCATORS,
    check_defense_verification,
    classify_claim,
)


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
        # Build mock payload_json rows from tool call specs
        self._rows: list[tuple[str]] = []
        for tc in tool_calls:
            payload = {
                "command": json.dumps({
                    "tool": tc.get("tool", ""),
                    "args": tc.get("args", {}),
                }),
            }
            self._rows.append((json.dumps(payload),))

    async def execute(self, stmt) -> _FakeResult:
        return _FakeResult(self._rows)


def _session(tool_calls: list[dict]) -> _FakeSession:
    return _FakeSession(tool_calls)


class TestDefenseVerification:
    @pytest.mark.asyncio
    async def test_generic_claim_always_passes(self) -> None:
        ok, msg = await check_defense_verification(
            session=_session([]),
            branch_id="b1",
            claim_class="generic",
            message_table="vr_investigation_messages",
        )
        assert ok is True

    @pytest.mark.asyncio
    async def test_none_claim_always_passes(self) -> None:
        ok, msg = await check_defense_verification(
            session=_session([]),
            branch_id="b1",
            claim_class="none",
            message_table="vr_investigation_messages",
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
        )
        assert ok is True

    @pytest.mark.asyncio
    async def test_empty_history_rejected(self) -> None:
        ok, msg = await check_defense_verification(
            session=_session([]),
            branch_id="b1",
            claim_class="overflow",
            message_table="vr_investigation_messages",
        )
        assert ok is False

    @pytest.mark.asyncio
    async def test_allocator_names_in_frozenset(self) -> None:
        assert "av_calloc" in KNOWN_ALLOCATORS
        assert "malloc" in KNOWN_ALLOCATORS
        assert "ngx_palloc" in KNOWN_ALLOCATORS

    @pytest.mark.asyncio
    async def test_input_reader_names_in_frozenset(self) -> None:
        assert "avio_rb16" in INPUT_READERS
        assert "get_bits" in INPUT_READERS
