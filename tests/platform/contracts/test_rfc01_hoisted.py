"""RFC-01 Phase 0: platform enums/contracts are faithful hoists.

Proves the platform copies are member-for-member and value-for-value identical
to the current vr AND malware definitions, so the Phase-1 re-export in each
module is behavior-preserving. A divergence here means an enum is not actually
shared and must stay module-owned.
"""
from __future__ import annotations

import pytest

from aila.modules.malware.contracts import branch as mw_b
from aila.modules.malware.contracts import investigation as mw_i
from aila.modules.malware.contracts import message as mw_m
from aila.modules.malware.contracts import outcome as mw_o
from aila.modules.malware.contracts import pattern as mw_p
from aila.modules.malware.contracts import target as mw_t
from aila.modules.malware.contracts import workspace as mw_ws
from aila.modules.vr.contracts import branch as vr_b
from aila.modules.vr.contracts import hypothesis as vr_h
from aila.modules.vr.contracts import investigation as vr_i
from aila.modules.vr.contracts import message as vr_m
from aila.modules.vr.contracts import outcome as vr_o
from aila.modules.vr.contracts import pattern as vr_p
from aila.modules.vr.contracts import target as vr_t
from aila.modules.vr.contracts import target_stages as vr_ts
from aila.modules.vr.contracts import workspace as vr_ws
from aila.platform.contracts import enums as pe
from aila.platform.contracts import target_stages as p_ts
from aila.platform.contracts.hypothesis import HypothesisState as PHypState


def _members(enum_cls: type) -> dict[str, str]:
    return {m.name: m.value for m in enum_cls}


_VR_PAIRS = [
    (pe.WorkspaceStatus, vr_ws.WorkspaceStatus),
    (pe.TargetStatus, vr_t.TargetStatus),
    (pe.AnalysisState, vr_t.AnalysisState),
    (pe.TargetTagSource, vr_t.TargetTagSource),
    (pe.BranchStatus, vr_b.BranchStatus),
    (pe.PersonaVoice, vr_b.PersonaVoice),
    (pe.BranchOperation, vr_b.BranchOperation),
    (pe.InvestigationStatus, vr_i.InvestigationStatus),
    (pe.InvestigationPauseReason, vr_i.InvestigationPauseReason),
    (pe.OutcomeConfidence, vr_o.OutcomeConfidence),
    (pe.OutcomeDispatchStatus, vr_o.OutcomeDispatchStatus),
    (pe.SenderKind, vr_m.SenderKind),
    (pe.OperatorIntent, vr_m.OperatorIntent),
    (pe.PatternStatus, vr_p.PatternStatus),
    (pe.PatternScope, vr_p.PatternScope),
    (pe.PatternConfidence, vr_p.PatternConfidence),
    (pe.HypothesisState, vr_h.HypothesisState),
    (pe.StageState, vr_ts.StageState),
    (pe.StageName, vr_ts.StageName),
]

_MW_PAIRS = [
    (pe.WorkspaceStatus, mw_ws.WorkspaceStatus),
    (pe.TargetStatus, mw_t.TargetStatus),
    (pe.AnalysisState, mw_t.AnalysisState),
    (pe.TargetTagSource, mw_t.TargetTagSource),
    (pe.BranchStatus, mw_b.BranchStatus),
    (pe.PersonaVoice, mw_b.PersonaVoice),
    (pe.BranchOperation, mw_b.BranchOperation),
    (pe.InvestigationStatus, mw_i.InvestigationStatus),
    (pe.InvestigationPauseReason, mw_i.InvestigationPauseReason),
    (pe.OutcomeConfidence, mw_o.OutcomeConfidence),
    (pe.OutcomeDispatchStatus, mw_o.OutcomeDispatchStatus),
    (pe.SenderKind, mw_m.SenderKind),
    (pe.OperatorIntent, mw_m.OperatorIntent),
    (pe.PatternStatus, mw_p.PatternStatus),
    (pe.PatternScope, mw_p.PatternScope),
    (pe.PatternConfidence, mw_p.PatternConfidence),
]


@pytest.mark.parametrize("platform_enum,vr_enum", _VR_PAIRS, ids=lambda e: getattr(e, "__name__", ""))
def test_hoisted_enum_matches_vr(platform_enum: type, vr_enum: type) -> None:
    assert _members(platform_enum) == _members(vr_enum)


@pytest.mark.parametrize("platform_enum,mw_enum", _MW_PAIRS, ids=lambda e: getattr(e, "__name__", ""))
def test_hoisted_enum_matches_malware(platform_enum: type, mw_enum: type) -> None:
    assert _members(platform_enum) == _members(mw_enum)


def test_all_nineteen_enums_exported() -> None:
    assert len(pe.__all__) == 19


def test_hypothesis_state_is_the_hoisted_enum() -> None:
    assert PHypState is pe.HypothesisState


def test_target_stages_rollup_parity() -> None:
    stages = p_ts.TargetAnalysisStages()
    for stage in p_ts.StageName:
        stages.set(stage, p_ts.StageStatus(state=p_ts.StageState.DONE))
    assert p_ts.roll_up_overall_state(stages) == pe.AnalysisState.READY
    stages.set(p_ts.StageName.INGESTION, p_ts.StageStatus(state=p_ts.StageState.FAILED))
    assert p_ts.roll_up_overall_state(stages) == pe.AnalysisState.FAILED
