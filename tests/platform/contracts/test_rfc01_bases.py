"""RFC-01 Phase 0b: record bases carry exactly the shared columns of the
concrete module records, so a Phase-2 subclass reproduces the current schema.

Compares the platform base's field set to the current vr concrete record's
field set; a mismatch means the base would change the table shape when a
concrete record subclasses it.
"""
from __future__ import annotations

from sqlmodel import SQLModel

from aila.modules.vr.contracts.branch import VRBranchSummary
from aila.modules.vr.contracts.workspace import (
    VRWorkspaceCreate,
    VRWorkspacePatch,
    VRWorkspaceSummary,
)
from aila.modules.vr.db_models.branch import VRInvestigationBranchRecord
from aila.modules.vr.db_models.workspace import VRWorkspaceRecord
from aila.platform.contracts.branch_base import BranchRecordBase, BranchSummaryBase
from aila.platform.contracts.workspace_base import (
    WorkspaceCreateBase,
    WorkspacePatchBase,
    WorkspaceRecordBase,
    WorkspaceSummaryBase,
)


def _fields(cls: type) -> set[str]:
    return set(cls.model_fields)


def test_workspace_record_base_columns_match_vr() -> None:
    assert _fields(WorkspaceRecordBase) == _fields(VRWorkspaceRecord)


def test_branch_record_base_columns_match_vr() -> None:
    assert _fields(BranchRecordBase) == _fields(VRInvestigationBranchRecord)


def test_workspace_contract_bases_are_shared_subset() -> None:
    # ``theme`` is the only module-specific field on the vr workspace contracts.
    assert _fields(WorkspaceSummaryBase) == _fields(VRWorkspaceSummary) - {"theme"}
    assert _fields(WorkspaceCreateBase) == _fields(VRWorkspaceCreate) - {"theme"}
    assert _fields(WorkspacePatchBase) == _fields(VRWorkspacePatch) - {"theme"}


def test_branch_summary_base_matches_vr() -> None:
    # branch is a zero-domain table: the base carries every vr summary field.
    assert _fields(BranchSummaryBase) == _fields(VRBranchSummary)


def test_record_bases_register_no_table() -> None:
    tables = set(SQLModel.metadata.tables)
    assert "workspacerecordbase" not in tables
    assert "branchrecordbase" not in tables


# --- Residue-aware parity for the remaining record bases -------------------
# The base carries the vr ∩ malware shared columns. Where the vr concrete has
# module-specific residue columns, the base is that residue smaller.

def _import_remaining():
    from aila.modules.vr.db_models.investigation import VRInvestigationRecord
    from aila.modules.vr.db_models.investigation_target import (
        VRInvestigationTargetRecord,
    )
    from aila.modules.vr.db_models.mcp_call_log import VRMcpCallLogRecord
    from aila.modules.vr.db_models.message import VRInvestigationMessageRecord
    from aila.modules.vr.db_models.outcome import VRInvestigationOutcomeRecord
    from aila.modules.vr.db_models.outcome_review import (
        VRInvestigationOutcomeReviewRecord,
    )
    from aila.modules.vr.db_models.pattern import VRPatternRecord
    from aila.modules.vr.db_models.project import VRProjectRecord
    from aila.modules.vr.db_models.target import VRTargetRecord
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
    from aila.platform.contracts.target_base import TargetRecordBase
    return [
        (TargetRecordBase, VRTargetRecord, set()),
        (InvestigationRecordBase, VRInvestigationRecord, set()),
        (MessageRecordBase, VRInvestigationMessageRecord, set()),
        (PatternRecordBase, VRPatternRecord, set()),
        (
            ProjectRecordBase,
            VRProjectRecord,
            {"cve_id", "patched_target_id", "poc_system_id"},
        ),
        (OutcomeRecordBase, VRInvestigationOutcomeRecord, set()),
        (OutcomeReviewRecordBase, VRInvestigationOutcomeReviewRecord, set()),
        (McpCallLogRecordBase, VRMcpCallLogRecord, set()),
        (InvestigationTargetRecordBase, VRInvestigationTargetRecord, set()),
    ]


def test_remaining_record_bases_match_vr_minus_residue() -> None:
    for base, concrete, vr_residue in _import_remaining():
        assert _fields(base) == _fields(concrete) - vr_residue, base.__name__
