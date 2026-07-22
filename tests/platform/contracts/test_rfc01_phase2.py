"""RFC-01 Phase 2: converted concretes subclass the platform bases and carry the
structurally-derived constraint names (no hand-written names that could collide
across modules).
"""
from __future__ import annotations

from sqlalchemy import Index, UniqueConstraint

from aila.modules.malware.db_models.investigation import MalwareInvestigationRecord
from aila.modules.malware.db_models.investigation_target import (
    MalwareInvestigationTargetRecord,
)
from aila.modules.malware.db_models.mcp_call_log import MalwareMcpCallLogRecord
from aila.modules.malware.db_models.message import MalwareInvestigationMessageRecord
from aila.modules.malware.db_models.pattern import MalwarePatternRecord
from aila.modules.malware.db_models.project import MalwareProjectRecord
from aila.modules.malware.db_models.target import (
    MalwareTargetRecord,
    MalwareTargetTagIndexRecord,
)
from aila.modules.malware.db_models.workspace import MalwareWorkspaceRecord
from aila.modules.vr.db_models.branch import VRInvestigationBranchRecord
from aila.modules.vr.db_models.investigation import VRInvestigationRecord
from aila.modules.vr.db_models.investigation_target import VRInvestigationTargetRecord
from aila.modules.vr.db_models.mcp_call_log import VRMcpCallLogRecord
from aila.modules.vr.db_models.message import VRInvestigationMessageRecord
from aila.modules.vr.db_models.outcome import VRInvestigationOutcomeRecord
from aila.modules.vr.db_models.outcome_review import VRInvestigationOutcomeReviewRecord
from aila.modules.vr.db_models.pattern import VRPatternRecord
from aila.modules.vr.db_models.project import VRProjectRecord
from aila.modules.vr.db_models.target import VRTargetRecord, VRTargetTagIndexRecord
from aila.modules.vr.db_models.workspace import VRWorkspaceRecord
from aila.platform.contracts.branch_base import BranchRecordBase
from aila.platform.contracts.investigation_base import InvestigationRecordBase
from aila.platform.contracts.investigation_target_base import (
    InvestigationTargetRecordBase,
)
from aila.platform.contracts.mcp_call_log_base import McpCallLogRecordBase
from aila.platform.contracts.message_base import MessageRecordBase
from aila.platform.contracts.outcome_base import OutcomeRecordBase
from aila.platform.contracts.outcome_review_base import OutcomeReviewRecordBase
from aila.platform.contracts.pattern_base import PatternRecordBase
from aila.platform.contracts.project_base import ProjectRecordBase
from aila.platform.contracts.target_base import TargetRecordBase, TargetTagIndexBase
from aila.platform.contracts.workspace_base import WorkspaceRecordBase


def _uq(cls: type) -> set[str]:
    return {c.name for c in cls.__table__.constraints if isinstance(c, UniqueConstraint)}


def _fk_ondelete(cls: type) -> set[tuple[str, str | None]]:
    return {(fk.parent.name, fk.ondelete) for fk in cls.__table__.foreign_keys}


def _index_cols(cls: type, name: str) -> tuple[str, ...] | None:
    for ix in cls.__table__.indexes:
        if ix.name == name:
            return tuple(c.name for c in ix.columns)
    return None


def test_converted_concretes_subclass_bases() -> None:
    assert issubclass(VRInvestigationOutcomeRecord, OutcomeRecordBase)
    assert issubclass(VRInvestigationBranchRecord, BranchRecordBase)
    assert issubclass(VRInvestigationOutcomeReviewRecord, OutcomeReviewRecordBase)
    assert issubclass(VRInvestigationTargetRecord, InvestigationTargetRecordBase)
    assert issubclass(VRMcpCallLogRecord, McpCallLogRecordBase)
    assert issubclass(MalwareMcpCallLogRecord, McpCallLogRecordBase)


def test_derived_unique_constraint_names() -> None:
    assert _uq(VRInvestigationTargetRecord) == {"uq_vr_investigation_targets_investigation_target"}
    assert _uq(MalwareInvestigationTargetRecord) == {
        "uq_malware_investigation_targets_investigation_target",
    }
    assert _uq(VRInvestigationOutcomeReviewRecord) == {"uq_vr_outcome_reviews_outcome_reviewer"}
    assert _uq(VRInvestigationOutcomeRecord) == set()
    assert _uq(VRInvestigationBranchRecord) == set()


def test_outcome_review_cascade_preserved() -> None:
    ondeletes = _fk_ondelete(VRInvestigationOutcomeReviewRecord)
    assert ondeletes
    assert all(od == "CASCADE" for _, od in ondeletes)


def test_vr_mcp_keeps_join_key_residue() -> None:
    vr_cols = set(VRMcpCallLogRecord.model_fields)
    assert {"investigation_id", "branch_id", "turn_number"} <= vr_cols
    mw_cols = set(MalwareMcpCallLogRecord.model_fields)
    assert not ({"investigation_id", "branch_id", "turn_number"} & mw_cols)


def test_domain_concretes_subclass_bases() -> None:
    assert issubclass(VRWorkspaceRecord, WorkspaceRecordBase)
    assert issubclass(MalwareWorkspaceRecord, WorkspaceRecordBase)
    assert issubclass(VRTargetRecord, TargetRecordBase)
    assert issubclass(MalwareTargetRecord, TargetRecordBase)
    assert issubclass(VRTargetTagIndexRecord, TargetTagIndexBase)
    assert issubclass(MalwareTargetTagIndexRecord, TargetTagIndexBase)
    assert issubclass(VRInvestigationRecord, InvestigationRecordBase)
    assert issubclass(MalwareInvestigationRecord, InvestigationRecordBase)
    assert issubclass(VRInvestigationMessageRecord, MessageRecordBase)
    assert issubclass(MalwareInvestigationMessageRecord, MessageRecordBase)
    assert issubclass(VRPatternRecord, PatternRecordBase)
    assert issubclass(MalwarePatternRecord, PatternRecordBase)
    assert issubclass(VRProjectRecord, ProjectRecordBase)
    assert issubclass(MalwareProjectRecord, ProjectRecordBase)


def test_domain_derived_unique_constraint_names() -> None:
    assert _uq(VRWorkspaceRecord) == {"uq_vr_workspaces_team_slug"}
    assert _uq(MalwareWorkspaceRecord) == {"uq_malware_workspaces_team_slug"}
    assert _uq(VRTargetTagIndexRecord) == {"uq_vr_target_tag_index_target_tag_source"}
    assert _uq(MalwareTargetTagIndexRecord) == {
        "uq_malware_target_tag_index_target_tag_source",
    }


def test_message_index_split_preserved() -> None:
    # vr keeps its composite dedup index; malware keeps its full-column index.
    assert _index_cols(
        VRInvestigationMessageRecord, "ix_vr_investigation_messages_auto_steering_key",
    ) == ("investigation_id", "auto_steering_key")
    assert _index_cols(
        MalwareInvestigationMessageRecord,
        "ix_malware_investigation_messages_auto_steering_key",
    ) == ("auto_steering_key",)


def test_investigation_index_split_preserved() -> None:
    # vr keeps its partial index; malware keeps its full-column index.
    assert _index_cols(
        VRInvestigationRecord, "ix_vr_investigations_is_favorite_true",
    ) == ("is_favorite",)
    assert _index_cols(
        MalwareInvestigationRecord, "ix_malware_investigations_is_favorite",
    ) == ("is_favorite",)


def test_project_residue_and_shared_column() -> None:
    vr_cols = set(VRProjectRecord.model_fields)
    mw_cols = set(MalwareProjectRecord.model_fields)
    residue = {"cve_id", "patched_target_id", "poc_system_id"}
    assert residue <= vr_cols
    assert not (residue & mw_cols)
    # analysis_system_id is shared -- lives on the base, present on both.
    assert "analysis_system_id" in vr_cols
    assert "analysis_system_id" in mw_cols


def test_malware_target_residue() -> None:
    mw_cols = set(MalwareTargetRecord.model_fields)
    assert {"parent_target_id", "sha256"} <= mw_cols
    vr_cols = set(VRTargetRecord.model_fields)
    assert not ({"parent_target_id", "sha256"} & vr_cols)


def test_concrete_mro_preserves_team_scoped_order() -> None:
    """RFC-01 risk mitigation: every concrete record keeps TeamScopedMixin ahead
    of SQLModel in its MRO (the pre-RFC order) and resolves its platform base.
    """
    from sqlmodel import SQLModel

    from aila.modules.malware.db_models.branch import MalwareInvestigationBranchRecord
    from aila.modules.malware.db_models.outcome import MalwareInvestigationOutcomeRecord
    from aila.modules.malware.db_models.outcome_review import (
        MalwareInvestigationOutcomeReviewRecord,
    )
    from aila.storage.mixins import TeamScopedMixin

    pairs: list[tuple[type, type]] = [
        (VRWorkspaceRecord, WorkspaceRecordBase),
        (MalwareWorkspaceRecord, WorkspaceRecordBase),
        (VRTargetRecord, TargetRecordBase),
        (MalwareTargetRecord, TargetRecordBase),
        (VRTargetTagIndexRecord, TargetTagIndexBase),
        (MalwareTargetTagIndexRecord, TargetTagIndexBase),
        (VRInvestigationRecord, InvestigationRecordBase),
        (MalwareInvestigationRecord, InvestigationRecordBase),
        (VRInvestigationMessageRecord, MessageRecordBase),
        (MalwareInvestigationMessageRecord, MessageRecordBase),
        (VRInvestigationBranchRecord, BranchRecordBase),
        (MalwareInvestigationBranchRecord, BranchRecordBase),
        (VRInvestigationOutcomeRecord, OutcomeRecordBase),
        (MalwareInvestigationOutcomeRecord, OutcomeRecordBase),
        (VRInvestigationOutcomeReviewRecord, OutcomeReviewRecordBase),
        (MalwareInvestigationOutcomeReviewRecord, OutcomeReviewRecordBase),
        (VRMcpCallLogRecord, McpCallLogRecordBase),
        (MalwareMcpCallLogRecord, McpCallLogRecordBase),
        (VRInvestigationTargetRecord, InvestigationTargetRecordBase),
        (MalwareInvestigationTargetRecord, InvestigationTargetRecordBase),
        (VRPatternRecord, PatternRecordBase),
        (MalwarePatternRecord, PatternRecordBase),
        (VRProjectRecord, ProjectRecordBase),
        (MalwareProjectRecord, ProjectRecordBase),
    ]
    for concrete, base in pairs:
        mro = concrete.__mro__
        assert base in mro, f"{concrete.__name__} must subclass {base.__name__}"
        assert SQLModel in mro
        if TeamScopedMixin in mro:
            assert mro.index(TeamScopedMixin) < mro.index(SQLModel), (
                f"{concrete.__name__}: TeamScopedMixin must precede SQLModel in MRO"
            )
