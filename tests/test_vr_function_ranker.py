"""M3.T-3 -- Function ranking dispatcher tests.

Covers the pure mapping function `_normalize_audit_mcp_entries` and the
contract surface. Persistence-heavy paths on the dispatcher itself are
exercised in integration tests (separate) that stand up a real DB row.
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
    FunctionRankingDispatcher,
)
from aila.modules.vr.enrichment.services.function_ranker import (
    FunctionRankerError,
    _normalize_audit_mcp_entries,
)
from aila.modules.vr.services.stage_tracker import StageTrackerError


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
            "ida_binary_survey",
        }


class TestAuditMcpEntryNormalization:
    """Composite-signal ranker (commit 34c1ab4 -- fix flat-1.00 scoring).

    The audit-mcp normalizer composes a real score from five signals,
    each normalized per-page so sparse responses still differentiate:
    blast_radius (0.40), complexity (0.25), tainted_from (0.20), inverse
    entrypoint_distance (0.10), position fallback (0.05). Entries with
    no signals get a position-only floor so the operator can still sort.
    """

    def test_empty_input(self) -> None:
        assert _normalize_audit_mcp_entries([], top_k=10) == []

    def test_dense_entry_saturates_score_ceiling(self) -> None:
        # parse_pdu hits the page-maximum on every weighted signal and
        # the position fallback, so its composite saturates the 1.0
        # ceiling. validate_token has middling blast/complexity/distance
        # but no tainted_from, so it slots in second. log_request has
        # nothing -- it falls to the per-position floor.
        raw = [
            {"function_name": "parse_pdu",
             "blast_radius": 80, "complexity": 22, "tainted_from": ["recv"],
             "entrypoint_distance": 1,
             "file_path": "src/proto.c", "line": 100},
            {"function_name": "validate_token",
             "blast_radius": 20, "complexity": 8,
             "entrypoint_distance": 3,
             "file_path": "src/auth.c", "line": 50},
            {"function_name": "log_request",
             "file_path": "src/log.c", "line": 12},
        ]
        out = _normalize_audit_mcp_entries(raw, top_k=10)
        assert [r.name for r in out] == ["parse_pdu", "validate_token", "log_request"]
        assert [r.rank for r in out] == [1, 2, 3]
        assert out[0].score == pytest.approx(1.0)
        assert out[0].score > out[1].score > out[2].score
        # Reasons surface every signal that actually contributed.
        assert "blast_radius=80" in out[0].reasons
        assert "complexity=22" in out[0].reasons
        assert "tainted_from=1 sources" in out[0].reasons
        assert "entrypoint_distance=1" in out[0].reasons

    def test_results_sorted_by_composite_descending(self) -> None:
        # Re-sort after composite + re-rank: input order is irrelevant.
        raw = [
            {"function_name": "low", "blast_radius": 1},
            {"function_name": "high", "blast_radius": 100},
            {"function_name": "mid", "blast_radius": 10},
        ]
        out = _normalize_audit_mcp_entries(raw, top_k=10)
        assert [r.name for r in out] == ["high", "mid", "low"]
        assert [r.rank for r in out] == [1, 2, 3]

    def test_fallback_reason_when_no_signals(self) -> None:
        # No blast/complexity/taint/distance -- the reasons collector
        # falls back to a position label so the operator can still see
        # WHY a row is ranked where it is. Score floored above zero.
        out = _normalize_audit_mcp_entries([{"function_name": "f1"}], top_k=10)
        assert out[0].name == "f1"
        assert out[0].score > 0
        assert out[0].reasons == ["audit-mcp position #1"]

    def test_name_field_fallbacks(self) -> None:
        # function_name → name → symbol → <unnamed>.
        assert _normalize_audit_mcp_entries(
            [{"name": "via_name"}], top_k=10,
        )[0].name == "via_name"
        assert _normalize_audit_mcp_entries(
            [{"symbol": "via_symbol"}], top_k=10,
        )[0].name == "via_symbol"
        assert _normalize_audit_mcp_entries([{}], top_k=10)[0].name == "<unnamed>"

    def test_top_k_cuts_before_composite(self) -> None:
        # 10 entries, top_k=3 → only f1/f2/f3 ever see the composite,
        # then re-sort drops them in score order. f3 dominates (highest
        # blast/complexity in the slice), so it ranks first.
        raw = [
            {"function_name": f"f{i}", "blast_radius": i, "complexity": i}
            for i in range(1, 11)
        ]
        out = _normalize_audit_mcp_entries(raw, top_k=3)
        assert len(out) == 3
        assert [r.name for r in out] == ["f3", "f2", "f1"]

    def test_complexity_falls_back_to_cyclomatic(self) -> None:
        # When only `cyclomatic_complexity` is provided, the reasons
        # branch surfaces it under its actual key (not `complexity`).
        raw = [{"function_name": "f1", "cyclomatic_complexity": 14}]
        out = _normalize_audit_mcp_entries(raw, top_k=10)
        assert "cyclomatic_complexity=14" in out[0].reasons

    def test_tainted_from_scalar_rendered_verbatim(self) -> None:
        # Non-collection tainted_from is rendered as-is (no len/count).
        raw = [{"function_name": "f1", "tainted_from": "recv"}]
        out = _normalize_audit_mcp_entries(raw, top_k=10)
        assert "tainted_from=recv" in out[0].reasons

    def test_handles_missing_line_field(self) -> None:
        out = _normalize_audit_mcp_entries(
            [{"function_name": "f1"}], top_k=10,
        )
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
    async def test_target_not_found_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # StageTracker.__aenter__ reaches the DB through
        # `load_target_stages` BEFORE the dispatcher's _load method
        # ever runs (commit 179a9d9 -- durable per-stage analysis).
        # That earlier check fires first on a missing row, so the
        # surfaced exception is StageTrackerError, not FunctionRankerError.
        # Monkeypatch keeps the test DB-independent.

        async def _raise(target_id: str) -> None:
            raise StageTrackerError(f"target {target_id} not found")

        monkeypatch.setattr(
            "aila.modules.vr.services.stage_tracker.load_target_stages",
            _raise,
        )
        d = FunctionRankingDispatcher(ida=_FakeMcp({}), audit_mcp=_FakeMcp({}))
        with pytest.raises(StageTrackerError):
            await d.rank(str(uuid.uuid4()))


class TestRankBinaryViaBinarySurvey:
    """The binary path ranks kuna ``binary_survey`` hotspots by cyclomatic
    complexity. ``_rank_binary`` only calls the IDA bridge (no DB), so it is
    exercised directly with a canned bridge.
    """

    @pytest.mark.asyncio
    async def test_missing_binary_id_raises(self) -> None:
        d = FunctionRankingDispatcher(ida=_FakeMcp({}), audit_mcp=_FakeMcp({}))
        with pytest.raises(FunctionRankerError):
            await d._rank_binary("tgt-1", {})

    @pytest.mark.asyncio
    async def test_survey_hotspots_ranked_by_complexity(self) -> None:
        ida = _FakeMcp({
            "binary_survey": {
                "hotspots": [
                    {"name": "mid", "address": "0x2000", "complexity": 8},
                    {"name": "hot", "address": "0x1000", "complexity": 40,
                     "callees_count": 12, "string_refs_count": 3},
                    {"name": "cold", "address": "0x3000", "complexity": 1},
                ],
            },
        })
        d = FunctionRankingDispatcher(ida=ida, audit_mcp=_FakeMcp({}))
        ranking = await d._rank_binary("tgt-1", {"binary_id": "b1"})

        assert ranking.source is RankingSource.IDA_BINARY_SURVEY
        assert [r.name for r in ranking.top_k] == ["hot", "mid", "cold"]
        assert [r.rank for r in ranking.top_k] == [1, 2, 3]
        # Most complex hotspot saturates the log-scale ceiling; scores fall off.
        assert ranking.top_k[0].score == pytest.approx(1.0)
        assert ranking.top_k[0].score > ranking.top_k[1].score > ranking.top_k[2].score
        assert ranking.total_candidates == 3
        # Secondary survey signals surface in the reasons.
        assert "cyclomatic_complexity=40" in ranking.top_k[0].reasons
        assert "callees=12" in ranking.top_k[0].reasons
        assert "string_refs=3" in ranking.top_k[0].reasons
        # Only the survey is called; no list_functions fallback.
        assert [c[0] for c in ida.calls] == ["binary_survey"]

    @pytest.mark.asyncio
    async def test_hotspots_without_address_dropped(self) -> None:
        ida = _FakeMcp({
            "binary_survey": {
                "hotspots": [
                    {"name": "keep", "address": "0x1000", "complexity": 5},
                    {"name": "drop_no_addr", "complexity": 99},
                ],
            },
        })
        d = FunctionRankingDispatcher(ida=ida, audit_mcp=_FakeMcp({}))
        ranking = await d._rank_binary("tgt-1", {"binary_id": "b1"})
        assert [r.name for r in ranking.top_k] == ["keep"]
        assert ranking.total_candidates == 1

    @pytest.mark.asyncio
    async def test_empty_survey_falls_back_to_list_functions(self) -> None:
        ida = _FakeMcp({
            "binary_survey": {"hotspots": []},
            "list_functions": {
                "functions": [
                    {"name": "big", "address": "0x4000", "cyclomatic_complexity": 30},
                    {"name": "small", "address": "0x5000", "cyclomatic_complexity": 2},
                ],
            },
        })
        d = FunctionRankingDispatcher(ida=ida, audit_mcp=_FakeMcp({}))
        ranking = await d._rank_binary("tgt-1", {"binary_id": "b1"})

        assert [r.name for r in ranking.top_k] == ["big", "small"]
        assert ranking.top_k[0].score == pytest.approx(1.0)
        # The fallback ordered by complexity_desc was issued.
        actions = [c[0] for c in ida.calls]
        assert actions == ["binary_survey", "list_functions"]
        assert ida.calls[1][1].get("order_by") == "complexity_desc"

    @pytest.mark.asyncio
    async def test_no_hotspots_anywhere_returns_empty_ranking(self) -> None:
        ida = _FakeMcp({
            "binary_survey": {"hotspots": []},
            "list_functions": {"functions": []},
        })
        d = FunctionRankingDispatcher(ida=ida, audit_mcp=_FakeMcp({}))
        ranking = await d._rank_binary("tgt-1", {"binary_id": "b1"})
        assert ranking.top_k == []
        assert ranking.total_candidates == 0
        assert "no hotspots" in ranking.notes
