"""M3.R-8 — Outcome dispatcher unit tests.

Tests cover the pure helpers (namespace builder, target_signature) and
the routing-table coverage. DB-bound dispatch handlers are exercised in
integration tests once the workflow runs end-to-end against a real DB.
"""
from __future__ import annotations

import pytest

from aila.modules.vr.agents.outcome_dispatcher import (
    _NOT_YET_DISPATCHABLE,
    _audit_memo_namespace,
    _compute_target_signature,
)
from aila.modules.vr.contracts import OutcomeKind


class TestAuditMemoNamespace:
    def test_global_scope(self) -> None:
        assert _audit_memo_namespace("global", "ws-1", "team-1") == "vr.audit_memo.global"

    def test_global_scope_case_insensitive(self) -> None:
        assert _audit_memo_namespace("GLOBAL", "ws-1", "team-1") == "vr.audit_memo.global"

    def test_team_scope(self) -> None:
        assert _audit_memo_namespace("team", "ws-1", "team-1") == "vr.audit_memo.team.team-1"

    def test_team_scope_without_team_id_falls_through_to_workspace(self) -> None:
        assert _audit_memo_namespace("team", "ws-1", None) == "vr.audit_memo.workspace.ws-1"

    def test_workspace_scope(self) -> None:
        assert _audit_memo_namespace("workspace", "ws-1", "team-1") == "vr.audit_memo.workspace.ws-1"

    def test_local_falls_through_to_workspace(self) -> None:
        # Local memos still need a place — workspace is the natural default
        assert _audit_memo_namespace("local", "ws-1", "team-1") == "vr.audit_memo.workspace.ws-1"

    def test_no_workspace_no_team_falls_through_to_global(self) -> None:
        assert _audit_memo_namespace("workspace", None, None) == "vr.audit_memo.global"


class TestTargetSignature:
    def test_deterministic_with_region(self) -> None:
        s1 = _compute_target_signature("tgt-1", {"region_descriptor": "fn foo at addr 0x1"})
        s2 = _compute_target_signature("tgt-1", {"region_descriptor": "fn foo at addr 0x1"})
        assert s1 == s2
        assert len(s1) == 64  # sha256 hex

    def test_different_targets_distinct(self) -> None:
        s1 = _compute_target_signature("tgt-1", {"region_descriptor": "r"})
        s2 = _compute_target_signature("tgt-2", {"region_descriptor": "r"})
        assert s1 != s2

    def test_different_regions_distinct(self) -> None:
        s1 = _compute_target_signature("tgt-1", {"region_descriptor": "r1"})
        s2 = _compute_target_signature("tgt-1", {"region_descriptor": "r2"})
        assert s1 != s2

    def test_no_region_returns_unique_sig(self) -> None:
        s1 = _compute_target_signature("tgt-1", {})
        s2 = _compute_target_signature("tgt-1", {})
        assert s1 != s2  # no region → unique each call so memos don't dedup
        assert s1.startswith("tgt-1|")


class TestRoutingTableCoverage:
    """Verify _NOT_YET_DISPATCHABLE covers every kind not handled directly."""

    def test_three_kinds_have_real_handlers(self) -> None:
        # These three are explicitly dispatched (AuditMemo, DirectFinding,
        # VariantHuntOrder) — should NOT appear in _NOT_YET_DISPATCHABLE.
        assert OutcomeKind.AUDIT_MEMO not in _NOT_YET_DISPATCHABLE
        assert OutcomeKind.DIRECT_FINDING not in _NOT_YET_DISPATCHABLE
        assert OutcomeKind.VARIANT_HUNT_ORDER not in _NOT_YET_DISPATCHABLE

    def test_remaining_8_kinds_listed_explicitly(self) -> None:
        # The other 8 of 11 D-43 outcome kinds must each be in the
        # NOT_YET_DISPATCHABLE map so the dispatcher emits SKIPPED with a
        # real reason rather than silently no-op.
        expected_not_yet = {
            OutcomeKind.ASSESSMENT_REPORT,
            OutcomeKind.STRATEGY_DESCRIPTOR,
            OutcomeKind.PROFILE_SPEC_DRAFT,
            OutcomeKind.CONFIG_DELTA,
            OutcomeKind.PATCH_ASSESSMENT_REPORT,
            OutcomeKind.CRASH_TRIAGE_REPORT,
            OutcomeKind.CAMPAIGN_LAUNCH,
            OutcomeKind.SUB_INVESTIGATION,
        }
        assert set(_NOT_YET_DISPATCHABLE.keys()) == expected_not_yet

    def test_every_outcome_kind_accounted_for(self) -> None:
        # No kind should be a silent gap.
        handled = {
            OutcomeKind.AUDIT_MEMO,
            OutcomeKind.DIRECT_FINDING,
            OutcomeKind.VARIANT_HUNT_ORDER,
        }
        skipped = set(_NOT_YET_DISPATCHABLE.keys())
        all_listed = handled | skipped
        for kind in OutcomeKind:
            assert kind in all_listed, f"OutcomeKind.{kind.name} has no dispatch policy"


class _FakeKnowledge:
    """Stub matching KnowledgeService.store signature."""

    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def store(
        self,
        namespace: str,
        content: str,
        metadata: dict | None = None,
        dedup_key: str | None = None,
        session=None,
    ) -> dict:
        self.calls.append(
            {
                "namespace": namespace,
                "content": content,
                "metadata": metadata or {},
                "dedup_key": dedup_key,
            },
        )
        return {
            "status": "stored",
            "operation": "inserted",
            "entry_id": 42,
            "namespace": namespace,
        }


class TestKnowledgeStub:
    @pytest.mark.asyncio
    async def test_fake_knowledge_returns_expected_shape(self) -> None:
        fake = _FakeKnowledge()
        result = await fake.store(
            namespace="vr.audit_memo.workspace.ws-1",
            content="claim text",
            metadata={"k": "v"},
            dedup_key="sig",
        )
        assert result["entry_id"] == 42
        assert fake.calls[0]["namespace"] == "vr.audit_memo.workspace.ws-1"
        assert fake.calls[0]["dedup_key"] == "sig"
