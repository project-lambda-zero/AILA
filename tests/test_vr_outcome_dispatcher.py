"""M3.R-8 -- Outcome dispatcher unit tests.

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
        # Local memos still need a place -- workspace is the natural default
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

    def test_six_kinds_have_real_handlers(self) -> None:
        # These six are explicitly dispatched -- should NOT appear in
        # _NOT_YET_DISPATCHABLE.
        for handled in (
            OutcomeKind.AUDIT_MEMO,
            OutcomeKind.DIRECT_FINDING,
            OutcomeKind.VARIANT_HUNT_ORDER,
            OutcomeKind.CAMPAIGN_LAUNCH,
            OutcomeKind.PROFILE_SPEC_DRAFT,
            OutcomeKind.PATCH_ASSESSMENT_REPORT,
        ):
            assert handled not in _NOT_YET_DISPATCHABLE

    def test_remaining_5_kinds_listed_explicitly(self) -> None:
        # The other 5 of 11 D-43 outcome kinds must each be in the
        # NOT_YET_DISPATCHABLE map so the dispatcher emits SKIPPED with
        # a real reason rather than silently no-op.
        expected_not_yet = {
            OutcomeKind.ASSESSMENT_REPORT,
            OutcomeKind.STRATEGY_DESCRIPTOR,
            OutcomeKind.CONFIG_DELTA,
            OutcomeKind.CRASH_TRIAGE_REPORT,
            OutcomeKind.SUB_INVESTIGATION,
        }
        assert set(_NOT_YET_DISPATCHABLE.keys()) == expected_not_yet

    def test_every_outcome_kind_accounted_for(self) -> None:
        # No kind should be a silent gap.
        handled = {
            OutcomeKind.AUDIT_MEMO,
            OutcomeKind.DIRECT_FINDING,
            OutcomeKind.VARIANT_HUNT_ORDER,
            OutcomeKind.CAMPAIGN_LAUNCH,
            OutcomeKind.PROFILE_SPEC_DRAFT,
            OutcomeKind.PATCH_ASSESSMENT_REPORT,
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


# ────────────────────────────────────────────────────────────────────────────
# Pure-handler tests using fakes (no DB) -- exercise the validation +
# routing semantics of the 3 new dispatch kinds. The DB-bound load
# step is monkey-patched out.
# ────────────────────────────────────────────────────────────────────────────

from dataclasses import dataclass  # noqa: E402
from unittest.mock import AsyncMock, MagicMock, patch  # noqa: E402

from aila.modules.vr.agents.outcome_dispatcher import OutcomeDispatcher  # noqa: E402
from aila.modules.vr.contracts import OutcomeDispatchStatus  # noqa: E402


@dataclass
class _FakeTarget:
    id: str = "tgt-x"
    workspace_id: str = "ws-x"
    team_id: str | None = "team-x"


@dataclass
class _FakeInvestigation:
    id: str = "inv-x"
    title: str = "Patch X audit"
    team_id: str | None = "team-x"
    cost_budget_usd: float = 100.0
    auto_pilot: bool = False
    project_id: str | None = None


class _FakeTaskHandle:
    def __init__(self, task_id: str = "task-001") -> None:
        self.task_id = task_id


class _FakeTaskQueue:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    async def submit(self, **kwargs) -> _FakeTaskHandle:
        self.calls.append(kwargs)
        return _FakeTaskHandle()


def _patch_load(dispatcher: OutcomeDispatcher) -> AsyncMock:
    """Replace _load_target_for_investigation with a fake returning known rows."""
    target = _FakeTarget()
    inv = _FakeInvestigation()
    mock = AsyncMock(return_value=(target, inv))
    dispatcher._load_target_for_investigation = mock  # type: ignore[method-assign]
    return mock


def _seed_campaign_launch_fixtures(
    *,
    workspace_id: str = "ws-x",
    target_id: str = "tgt-x",
    investigation_id: str = "inv-x",
    branch_id: str = "br-x",
    outcome_id: str = "oc-1",
) -> None:
    """Seed the FK-required rows so a fresh VRFuzzCampaignProposalRecord
    INSERT succeeds against the real aila_test schema.

    _dispatch_campaign_launch persists via UnitOfWork -- no longer via
    KnowledgeService -- so the FK graph (workspace -> target ->
    investigation -> branch -> outcome) has to exist before the insert.
    """
    from aila.modules.vr.db_models import (
        VRInvestigationBranchRecord,
        VRInvestigationOutcomeRecord,
        VRInvestigationRecord,
        VRTargetRecord,
        VRWorkspaceRecord,
    )
    from aila.storage.database import session_scope

    with session_scope() as sess:
        # The models carry FK columns without ORM relationships, so SQLAlchemy
        # cannot infer insert order; flush after each level so every parent row
        # exists before its children reference it.
        sess.add(VRWorkspaceRecord(
            id=workspace_id, name="ws", slug=workspace_id,
        ))
        sess.flush()
        sess.add(VRTargetRecord(
            id=target_id, workspace_id=workspace_id,
            display_name="tgt", kind="native_binary",
        ))
        sess.flush()
        sess.add(VRInvestigationRecord(
            id=investigation_id, target_id=target_id,
            title="seed", kind="discovery",
            strategy_family="vulnerability_research.discovery_research",
        ))
        sess.flush()
        sess.add(VRInvestigationBranchRecord(
            id=branch_id, investigation_id=investigation_id,
        ))
        sess.flush()
        sess.add(VRInvestigationOutcomeRecord(
            id=outcome_id, investigation_id=investigation_id,
            branch_id=branch_id, outcome_kind="campaign_launch",
            confidence="strong", state="approved",
        ))
        sess.commit()


class TestDispatchCampaignLaunch:
    async def test_persists_fuzz_proposal_when_payload_valid(
        self, test_db,
    ) -> None:
        # _dispatch_campaign_launch was refactored from a
        # KnowledgeService write to a direct INSERT into
        # vr_fuzz_campaign_proposals (see
        # src/aila/modules/vr/agents/outcome_dispatcher.py::
        # _dispatch_campaign_launch). This test now verifies the DB
        # row + returned dispatch_target.
        del test_db  # activates the aila_test engine
        _seed_campaign_launch_fixtures()

        fake_knowledge = _FakeKnowledge()
        d = OutcomeDispatcher(knowledge=fake_knowledge)
        _patch_load(d)
        outcome = MagicMock(confidence="strong")

        result = await d._dispatch_campaign_launch(
            "oc-1", "inv-x",
            {
                "profile": "V8MapInferenceProfile",
                "target_descriptor": {
                    "binary_path": "/tmp/d8",
                    "harness": "MyHarness",
                },
                "suggested_duration_hours": 24,
            },
            outcome,
        )

        assert result.dispatch_status == OutcomeDispatchStatus.DISPATCHED
        assert result.dispatch_target is not None
        assert result.dispatch_target.startswith("fuzz_proposal:")
        # New impl no longer writes to KnowledgeService for campaign
        # launch -- proposal lives in vr_fuzz_campaign_proposals now.
        assert fake_knowledge.calls == []

        # Verify the DB row landed with the expected shape.
        from aila.modules.vr.db_models import VRFuzzCampaignProposalRecord
        from aila.storage.database import session_scope
        with session_scope() as sess:
            row = sess.query(VRFuzzCampaignProposalRecord).filter_by(
                investigation_id="inv-x", outcome_id="oc-1",
            ).one()
            assert row.profile == "V8MapInferenceProfile"
            assert row.status == "pending"
            assert row.suggested_duration_hours == 24

    @pytest.mark.asyncio
    async def test_rejects_missing_profile(self) -> None:
        d = OutcomeDispatcher(knowledge=_FakeKnowledge())
        _patch_load(d)
        result = await d._dispatch_campaign_launch(
            "oc-1", "inv-x",
            {"target_descriptor": {"binary_path": "/tmp/d8"}},
            MagicMock(confidence="strong"),
        )
        assert result.dispatch_status == OutcomeDispatchStatus.FAILED
        # Failure branch runs entirely before the DB insert, so no
        # seeding is needed.
        assert "missing_profile" in result.reason

    @pytest.mark.asyncio
    async def test_rejects_missing_descriptor(self) -> None:
        d = OutcomeDispatcher(knowledge=_FakeKnowledge())
        _patch_load(d)
        result = await d._dispatch_campaign_launch(
            "oc-1", "inv-x",
            {"profile": "X"},
            MagicMock(confidence="strong"),
        )
        assert result.dispatch_status == OutcomeDispatchStatus.FAILED


class TestDispatchProfileSpecDraft:
    @pytest.mark.asyncio
    async def test_writes_to_knowledge(self) -> None:
        fake_knowledge = _FakeKnowledge()
        d = OutcomeDispatcher(knowledge=fake_knowledge)
        _patch_load(d)
        result = await d._dispatch_profile_spec_draft(
            "oc-2", "inv-x",
            {"profile_name": "NgxHttpFuzzProfile",
             "profile_kind": "fuzzing",
             "spec": {"strategy": "request-grammar", "seed_corpus": "rfc7230"}},
            MagicMock(confidence="strong"),
        )
        assert result.dispatch_status == OutcomeDispatchStatus.DISPATCHED
        call = fake_knowledge.calls[0]
        assert call["namespace"] == "vr.profile_spec.workspace.ws-x"
        assert call["metadata"]["profile_name"] == "NgxHttpFuzzProfile"
        assert call["metadata"]["status"] == "draft"
        # Dedup key now mixes in a 16-char hex hash of the canonical
        # JSON spec (fix \u00a7264) so two drafts with the same name but
        # different spec content no longer collapse to one row. Old
        # form was 'ws-x|fuzzing|NgxHttpFuzzProfile'; new form appends
        # '|<sha256[:16]>' -- see
        # src/aila/modules/vr/agents/outcome_dispatcher.py::
        # _dispatch_profile_spec_draft.
        assert call["dedup_key"].startswith(
            "ws-x|fuzzing|NgxHttpFuzzProfile|",
        )
        _, _, _, spec_hash = call["dedup_key"].split("|")
        assert len(spec_hash) == 16
        assert all(c in "0123456789abcdef" for c in spec_hash)

    @pytest.mark.asyncio
    async def test_rejects_empty_spec(self) -> None:
        d = OutcomeDispatcher(knowledge=_FakeKnowledge())
        _patch_load(d)
        result = await d._dispatch_profile_spec_draft(
            "oc-2", "inv-x",
            {"profile_name": "X", "profile_kind": "fuzzing", "spec": {}},
            MagicMock(confidence="strong"),
        )
        assert result.dispatch_status == OutcomeDispatchStatus.FAILED
        assert "missing_profile_name_or_spec" in result.reason


class TestDispatchPatchAssessmentReport:
    # _dispatch_patch_assessment_report was rewritten to run two
    # parallel paths (variant_hunt_orders spawn + optional nday
    # enqueue) and now ALWAYS returns DISPATCHED, folding per-path
    # errors into ``reason``. Contract signature also dropped the
    # trailing `outcome` positional argument. See
    # src/aila/modules/vr/agents/outcome_dispatcher.py.

    @pytest.mark.asyncio
    async def test_enqueues_vr_nday(self) -> None:
        fake_queue = _FakeTaskQueue()
        d = OutcomeDispatcher(
            knowledge=_FakeKnowledge(),
            task_queue_factory=lambda: fake_queue,
        )
        _patch_load(d)
        with patch(
            "aila.modules.vr.agents.outcome_dispatcher.enqueue_vr_nday",
            new=AsyncMock(return_value=_FakeTaskHandle("task-nday-001")),
        ) as enqueue_mock:
            result = await d._dispatch_patch_assessment_report(
                "oc-3", "inv-x",
                {
                    "patch_descriptor": {
                        "vulnerable_ref": "abc123",
                        "patched_ref": "def456",
                        "repo_url": "https://github.com/x/y",
                    },
                    "assessment": {"verdict": "incomplete_fix"},
                },
            )
        assert result.dispatch_status == OutcomeDispatchStatus.DISPATCHED
        # dispatch_target now encodes both paths:
        # ``children=[<spawned_ids>];nday=<task_id>``. With no
        # variant_hunt_orders in the payload, spawned_children is [].
        assert result.dispatch_target == "children=[];nday=task-nday-001"
        assert "nday_task=task-nday-001" in result.reason
        enqueue_mock.assert_awaited_once()
        kwargs = enqueue_mock.await_args.kwargs
        assert kwargs["source_outcome_id"] == "oc-3"
        assert kwargs["patch_descriptor"]["vulnerable_ref"] == "abc123"
        assert kwargs["target_id"] == "tgt-x"
        assert kwargs["parent_investigation_id"] == "inv-x"

    @pytest.mark.asyncio
    async def test_no_patch_descriptor_falls_through_as_verdict_only(
        self,
    ) -> None:
        # Old contract: missing patch_descriptor -> FAILED. New contract:
        # patch_descriptor is optional. When neither variant_hunt_orders
        # nor patch_descriptor are supplied, the dispatcher reports
        # DISPATCHED with reason="verdict_only:no_variants_no_nday_descriptor"
        # so the operator UI still shows green for a pure verdict
        # report. See the verdict-only branch of
        # _dispatch_patch_assessment_report.
        d = OutcomeDispatcher(knowledge=_FakeKnowledge())
        _patch_load(d)
        result = await d._dispatch_patch_assessment_report(
            "oc-3", "inv-x",
            {"assessment": {"verdict": "ok"}},
        )
        assert result.dispatch_status == OutcomeDispatchStatus.DISPATCHED
        assert result.reason == "verdict_only:no_variants_no_nday_descriptor"
        assert result.dispatch_target is None

    @pytest.mark.asyncio
    async def test_enqueue_failure_surfaces_in_reason_not_status(
        self,
    ) -> None:
        # Old contract: enqueue failure -> FAILED with 'enqueue_failed'
        # in reason. New contract: the whole dispatch still reports
        # DISPATCHED but ``reason`` carries ``nday_error=<type>:<msg>``.
        # This is a design smell (see migration report -- an enqueue
        # failure being reported as DISPATCHED can mask real errors
        # from the operator dashboard) but it matches current source.
        d = OutcomeDispatcher(
            knowledge=_FakeKnowledge(),
            task_queue_factory=lambda: _FakeTaskQueue(),
        )
        _patch_load(d)
        with patch(
            "aila.modules.vr.agents.outcome_dispatcher.enqueue_vr_nday",
            new=AsyncMock(side_effect=RuntimeError("redis down")),
        ):
            result = await d._dispatch_patch_assessment_report(
                "oc-3", "inv-x",
                {"patch_descriptor": {
                    "vulnerable_ref": "x",
                    "patched_ref": "y",
                    "repo_url": "https://example.com/repo",
                }},
            )
        assert result.dispatch_status == OutcomeDispatchStatus.DISPATCHED
        assert "nday_error=" in result.reason
        assert "redis down" in result.reason
        assert "RuntimeError" in result.reason
