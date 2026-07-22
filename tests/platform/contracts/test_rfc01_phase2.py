"""RFC-01 Phase 2: converted concretes subclass the platform bases and carry the
structurally-derived constraint names (no hand-written names that could collide
across modules).
"""
from __future__ import annotations

from sqlalchemy import UniqueConstraint

from aila.modules.malware.db_models.investigation_target import (
    MalwareInvestigationTargetRecord,
)
from aila.modules.malware.db_models.mcp_call_log import MalwareMcpCallLogRecord
from aila.modules.vr.db_models.branch import VRInvestigationBranchRecord
from aila.modules.vr.db_models.investigation_target import VRInvestigationTargetRecord
from aila.modules.vr.db_models.mcp_call_log import VRMcpCallLogRecord
from aila.modules.vr.db_models.outcome import VRInvestigationOutcomeRecord
from aila.modules.vr.db_models.outcome_review import VRInvestigationOutcomeReviewRecord
from aila.platform.contracts.branch_base import BranchRecordBase
from aila.platform.contracts.investigation_target_base import (
    InvestigationTargetRecordBase,
)
from aila.platform.contracts.mcp_call_log_base import McpCallLogRecordBase
from aila.platform.contracts.outcome_base import OutcomeRecordBase
from aila.platform.contracts.outcome_review_base import OutcomeReviewRecordBase


def _uq(cls: type) -> set[str]:
    return {c.name for c in cls.__table__.constraints if isinstance(c, UniqueConstraint)}


def _fk_ondelete(cls: type) -> set[tuple[str, str | None]]:
    return {(fk.parent.name, fk.ondelete) for fk in cls.__table__.foreign_keys}


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
