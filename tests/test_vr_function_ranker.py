"""M3.T-3 — Function ranking dispatcher tests.

Covers the pure mapping functions (`_normalize_audit_mcp_entries`,
`_audit_mcp_score`) and the contract surface. Persistence-heavy paths
on the dispatcher itself are exercised in integration tests (separate)
that stand up a real DB row.
"""
from __future__ import annotations

import uuid
from datetime import UTC, datetime
from typing import Any

import pytest
from pydantic import ValidationError

from aila.modules.vr.enrichment.contracts import (
    FunctionRanking,
    RankedFunction,
    RankingSource,
)
from aila.modules.vr.enrichment.services import (
    FunctionRankerError,
    FunctionRankingDispatcher,
)
from aila.modules.vr.enrichment.services.function_ranker import (
    _PARSER_SINK_APIS,
    _audit_mcp_score,
    _normalize_audit_mcp_entries,
)


class TestRankedFunctionShape:
    def test_minimal_valid(self) -> None:
        f = RankedFunction(name="foo", score=0.5, rank=1)
        assert f.name == "foo"
        assert f.address == ""
        assert f.file_path == ""
        assert f.line is None
        assert f.reasons == []

    def test_score_range_rejects_negative(self) -> None:
        with pytest.raises(ValidationError):
            RankedFunction(name="foo", score=-0.1, rank=1)

    def test_score_range_rejects_above_one(self) -> None:
        with pytest.raises(ValidationError):
            RankedFunction(name="foo", score=1.5, rank=1)

    def test_rank_must_be_ge_one(self) -> None:
        with pytest.raises(ValidationError):
            RankedFunction(name="foo", score=0.5, rank=0)


class TestFunctionRankingShape:
    def test_round_trip(self) -> None:
        original = FunctionRanking(
            target_id="tgt-1",
            source=RankingSource.AUDIT_MCP_FUZZING_TARGETS,
            produced_at=datetime(2026, 5, 14, 12, 0, 0, tzinfo=UTC),
            total_candidates=128,
            top_k=[
                RankedFunction(name="parse_http_request", score=0.95, rank=1,
                               file_path="src/http.c", line=42,
                               reasons=["blast_radius=120", "tainted_from=recv"]),
                RankedFunction(name="parse_query_string", score=0.71, rank=2,
                               file_path="src/http.c", line=180),
            ],
            notes="",
        )
        dumped = original.model_dump(mode="json")
        restored = FunctionRanking.model_validate(dumped)
        assert restored == original


class TestRankingSourceEnum:
    def test_values(self) -> None:
        values = {m.value for m in RankingSource}
        assert values == {
            "audit_mcp_fuzzing_targets",
            "audit_mcp_correlated",
            "ida_assess_exploitability",
        }


class TestParserSinkApiList:
    def test_contains_expected_apis(self) -> None:
        assert "strcpy" in _PARSER_SINK_APIS
        assert "memcpy" in _PARSER_SINK_APIS
        assert "sprintf" in _PARSER_SINK_APIS
        assert "gets" in _PARSER_SINK_APIS

    def test_no_duplicates(self) -> None:
        assert len(_PARSER_SINK_APIS) == len(set(_PARSER_SINK_APIS))


class TestAuditMcpScoreExtraction:
    def test_prefers_risk_score(self) -> None:
        assert _audit_mcp_score({"risk_score": 0.8, "score": 0.5}) == 0.8

    def test_falls_back_through_keys(self) -> None:
        assert _audit_mcp_score({"score": 0.5}) == 0.5
        assert _audit_mcp_score({"priority": 7}) == 7.0
        assert _audit_mcp_score({"blast_radius": 42}) == 42.0

    def test_default_one_when_no_signal(self) -> None:
        assert _audit_mcp_score({}) == 1.0

    def test_ignores_zero_and_non_numeric(self) -> None:
        assert _audit_mcp_score({"risk_score": 0, "score": 3.5}) == 3.5
        assert _audit_mcp_score({"risk_score": "high", "score": 2.0}) == 2.0


class TestAuditMcpEntryNormalization:
    def test_empty_input(self) -> None:
        assert _normalize_audit_mcp_entries([], top_k=10) == []

    def test_basic_shape(self) -> None:
        raw = [
            {"function_name": "parse_pdu", "risk_score": 9.0,
             "file_path": "src/proto.c", "line": 100,
             "blast_radius": 80, "complexity": 22, "tainted_from": "recv"},
            {"function_name": "validate_token", "risk_score": 5.0,
             "file_path": "src/auth.c", "line": 50},
            {"function_name": "log_request", "risk_score": 1.0,
             "file_path": "src/log.c", "line": 12},
        ]
        out = _normalize_audit_mcp_entries(raw, top_k=10)
        assert len(out) == 3
        assert out[0].name == "parse_pdu"
        assert out[0].score == pytest.approx(1.0)
        assert out[0].rank == 1
        assert "blast_radius=80" in out[0].reasons
        assert "complexity=22" in out[0].reasons
        assert "tainted_from=recv" in out[0].reasons
        assert out[1].score == pytest.approx(5.0 / 9.0)
        assert out[2].score == pytest.approx(1.0 / 9.0)

    def test_falls_back_to_name_field(self) -> None:
        raw = [{"name": "f1", "risk_score": 1.0}]
        out = _normalize_audit_mcp_entries(raw, top_k=10)
        assert out[0].name == "f1"

    def test_top_k_cuts_list(self) -> None:
        raw = [{"function_name": f"f{i}", "risk_score": float(i)} for i in range(1, 11)]
        out = _normalize_audit_mcp_entries(raw, top_k=3)
        assert len(out) == 3
        assert [e.name for e in out] == ["f1", "f2", "f3"]

    def test_handles_missing_line_field(self) -> None:
        raw = [{"function_name": "f1", "risk_score": 1.0}]
        out = _normalize_audit_mcp_entries(raw, top_k=10)
        assert out[0].line is None


class _FakeMcp:
    """In-memory MCP stub. Records calls; returns canned responses by action."""

    def __init__(self, responses: dict[str, Any]) -> None:
        self._responses = responses
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def forward(self, action: str | None = None, **kwargs: Any) -> dict:
        self.calls.append((action or "", kwargs))
        resp = self._responses.get(action)
        if callable(resp):
            return resp(**kwargs)
        if resp is None:
            return {"status": "error", "error": f"no stub for {action!r}"}
        return resp


class TestDispatcherErrorPaths:
    """Dispatcher contract assertions that don't require a DB row."""

    @pytest.mark.asyncio
    async def test_target_not_found_raises(self) -> None:
        d = FunctionRankingDispatcher(ida=_FakeMcp({}), audit_mcp=_FakeMcp({}))
        with pytest.raises(FunctionRankerError):
            await d.rank(str(uuid.uuid4()))
