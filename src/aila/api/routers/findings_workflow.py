"""Finding workflow router for AILA REST API.

Provides state machine transitions for finding lifecycle management.

Per BE-08 / D-29: operator+ role for transitions (T-138-16/T-138-22).
Per D-27: DataEnvelope response.
Per D-31: slowapi rate limiting.

State machine (server-side enforcement):
  new -> investigating -> mitigated -> verified -> closed
  investigating -> new  (reopen)
  mitigated -> investigating  (reopen)
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlmodel import select

from aila.api.auth import AuthContext, require_user_or_api_key
from aila.api.constants import ROLE_OPERATOR
from aila.api.limiter import limiter
from aila.api.schemas.endpoints import (
    ALL_STATES,
    VALID_TRANSITIONS,
    FindingTransitionRequest,
    FindingWorkflowHistoryResponse,
    FindingWorkflowStateResponse,
    WorkflowStateDefinition,
)
from aila.api.schemas.envelope import DataEnvelope
from aila.storage.database import async_session_scope
from aila.storage.db_models import FindingWorkflowRecord

__all__ = ["router"]

_log = logging.getLogger(__name__)

router = APIRouter(prefix="/findings", tags=["findings-workflow"], dependencies=[Depends(require_user_or_api_key)])

_ROLE_LEVELS: dict[str, int] = {"reader": 0, "operator": 1, "admin": 2}


def _require_operator(auth: AuthContext = Depends(require_user_or_api_key)) -> AuthContext:
    if _ROLE_LEVELS.get(auth.role, -1) < _ROLE_LEVELS[ROLE_OPERATOR]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Finding workflow requires '{ROLE_OPERATOR}' role or higher; current role: '{auth.role}'",
        )
    return auth


def _record_to_response(r: FindingWorkflowRecord) -> FindingWorkflowHistoryResponse:
    return FindingWorkflowHistoryResponse(
        id=r.id,
        finding_id=r.finding_id,
        module_id=r.module_id,
        current_state=r.current_state,
        previous_state=r.previous_state,
        transitioned_by=r.transitioned_by,
        notes=r.notes,
        created_at=r.created_at,
    )


@router.get(
    "/workflow/states",
    response_model=DataEnvelope[WorkflowStateDefinition],
    summary="Get finding workflow state machine definition",
)
@limiter.limit("120/minute")
async def get_workflow_states(
    request: Request,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> DataEnvelope[WorkflowStateDefinition]:
    """Return the canonical state machine definition (states + allowed transitions).

    Also merges module-contributed workflow definitions if any modules
    implement workflow_definitions().
    """
    merged_states = list(ALL_STATES)
    merged_transitions = dict(VALID_TRANSITIONS)

    platform = getattr(request.app.state, "platform", None)
    if platform is not None:
        try:
            for module in platform.runtime.module_registry.modules:
                if not hasattr(module, "workflow_definitions"):
                    continue
                for _wf_id, wf_def in module.workflow_definitions().items():
                    for s in wf_def.get("states", []):
                        if s not in merged_states:
                            merged_states.append(s)
                    for from_state, to_states in wf_def.get("transitions", {}).items():
                        if from_state not in merged_transitions:
                            merged_transitions[from_state] = []
                        for ts in to_states:
                            if ts not in merged_transitions[from_state]:
                                merged_transitions[from_state].append(ts)
        except Exception:
            _log.debug("Module workflow_definitions collection failed", exc_info=True)

    return DataEnvelope(
        data=WorkflowStateDefinition(
            states=merged_states,
            transitions=merged_transitions,
        )
    )


@router.get(
    "/{finding_id}/workflow",
    response_model=DataEnvelope[FindingWorkflowStateResponse],
    summary="Get workflow state and history for a finding",
)
@limiter.limit("120/minute")
async def get_finding_workflow(
    request: Request,
    finding_id: str,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> DataEnvelope[FindingWorkflowStateResponse]:
    """Return current workflow state and full transition history for a finding."""
    async with async_session_scope() as session:
        stmt = (
            select(FindingWorkflowRecord)
            .where(FindingWorkflowRecord.finding_id == finding_id)
            .order_by(FindingWorkflowRecord.created_at.asc())  # type: ignore[attr-defined]
        )
        history = (await session.exec(stmt)).all()

    if not history:
        # Finding has no workflow record yet — return initial state
        return DataEnvelope(
            data=FindingWorkflowStateResponse(
                finding_id=finding_id,
                current_state="new",
                history=[],
            )
        )

    current_state = history[-1].current_state
    return DataEnvelope(
        data=FindingWorkflowStateResponse(
            finding_id=finding_id,
            current_state=current_state,
            history=[_record_to_response(r) for r in history],
        )
    )


@router.post(
    "/{finding_id}/transition",
    response_model=DataEnvelope[FindingWorkflowHistoryResponse],
    status_code=status.HTTP_201_CREATED,
    summary="Transition a finding to a new workflow state",
)
@limiter.limit("60/minute")
async def transition_finding(
    request: Request,
    finding_id: str,
    body: FindingTransitionRequest,
    auth: AuthContext = Depends(_require_operator),
) -> DataEnvelope[FindingWorkflowHistoryResponse]:
    """Transition a finding to target_state.

    Server-side state machine enforcement (T-138-22):
    - Validates the transition is legal for the current state.
    - Invalid transitions return 422 Unprocessable Entity.
    - Records previous_state and transitioned_by for audit trail.
    """
    async with async_session_scope() as session:
        # Get the most recent workflow record for this finding
        stmt = (
            select(FindingWorkflowRecord)
            .where(FindingWorkflowRecord.finding_id == finding_id)
            .order_by(FindingWorkflowRecord.created_at.desc())  # type: ignore[attr-defined]
            .limit(1)
        )
        latest = (await session.exec(stmt)).first()
        current_state = latest.current_state if latest else "new"

        # Validate transition (T-138-22: server-side enforcement)
        allowed = VALID_TRANSITIONS.get(current_state, [])
        if body.target_state not in allowed:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=(
                    f"Transition from '{current_state}' to '{body.target_state}' is not allowed. "
                    f"Allowed transitions from '{current_state}': {allowed}"
                ),
            )

        record = FindingWorkflowRecord(
            finding_id=finding_id,
            module_id=body.module_id,
            current_state=body.target_state,
            previous_state=current_state,
            transitioned_by=auth.user_id,
            notes=body.notes,
        )
        session.add(record)
        await session.commit()
        await session.refresh(record)

    _log.info(
        "Finding %s transitioned %s -> %s by %s",
        finding_id,
        current_state,
        body.target_state,
        auth.user_id,
    )
    return DataEnvelope(data=_record_to_response(record))


# ---------------------------------------------------------------------------
# Evidence chain — UX-05
# ---------------------------------------------------------------------------


class EvidenceNode(BaseModel):
    """A single node in the evidence provenance graph."""

    id: str
    type: str
    label: str
    metadata: dict = field(default_factory=dict)  # type: ignore[assignment]

    model_config = {"arbitrary_types_allowed": True}


class EvidenceEdge(BaseModel):
    """A directed edge between two evidence nodes."""

    from_id: str
    to_id: str
    label: str


class EvidenceChain(BaseModel):
    """Full evidence provenance graph for a finding."""

    finding_id: int
    nodes: list[EvidenceNode]
    edges: list[EvidenceEdge]


def _unavailable_node(node_id: str, node_type: str, label: str) -> EvidenceNode:
    """Return a placeholder node for data that is not stored."""
    return EvidenceNode(
        id=node_id,
        type=node_type,
        label=label,
        metadata={"available": False},
    )


@dataclass
class _ChainBuilder:
    """Mutable builder accumulating nodes and edges for a single finding."""

    nodes: list[EvidenceNode] = field(default_factory=list)
    edges: list[EvidenceEdge] = field(default_factory=list)

    def add_node(self, node: EvidenceNode) -> None:
        self.nodes.append(node)

    def add_edge(self, from_id: str, to_id: str, label: str) -> None:
        self.edges.append(EvidenceEdge(from_id=from_id, to_id=to_id, label=label))


@router.get(
    "/{finding_id}/evidence-chain",
    response_model=DataEnvelope[EvidenceChain],
    summary="Get evidence provenance chain for a finding",
)
@limiter.limit("60/minute")
async def get_evidence_chain(
    request: Request,
    finding_id: int,
    auth: AuthContext = Depends(require_user_or_api_key),
) -> DataEnvelope[EvidenceChain]:
    """Return an evidence provenance graph for a finding (UX-05).

    Assembles nodes and edges from real stored data:
    - LatestFindingRecord (the finding itself)
    - CacheRecord with namespace 'cve_intel' (CVSS / EPSS enrichment)
    - FindingWorkflowRecord (triage decisions)
    - PrioritizedFindingRecord (scan run linkage)

    Nodes with no stored data are marked metadata.available=false — no fabrication.
    """
    platform = getattr(request.app.state, "platform", None)
    if platform is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Platform not initialized -- vulnerability module unavailable.",
        )
    module = platform.runtime.module_registry.require("vulnerability")

    async with async_session_scope() as session:
        chain = await module.evidence_chain(finding_id, session)
    if chain is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding {finding_id} not found.",
        )
    return DataEnvelope(data=EvidenceChain.model_validate(chain))
