"""Deterministically project VR ledger discoveries into reviewable outcomes."""

from __future__ import annotations

import json
from typing import Any, cast

from sqlalchemy.ext.asyncio import AsyncSession
from sqlmodel import col, select
from sqlmodel.ext.asyncio.session import AsyncSession as SQLModelAsyncSession

from aila.modules.vr.contracts import OutcomeKind
from aila.modules.vr.db_models import (
    VRInvestigationOutcomeRecord,
    VRInvestigationRecord,
)
from aila.platform.services.ledger import InvestigationLedgerRecord

__all__ = ["project_discovery_outcomes"]

_PROJECTION_ID_PREFIX = "ledger-discovery-"


def _text(value: Any) -> str:
    return value.strip() if isinstance(value, str) and value.strip() else ""


def _discovery_title(payload: dict[str, Any], discovery_id: int) -> str:
    for key in ("title", "claim", "vulnerability", "proposal", "pattern", "criterion", "surface"):
        title = _text(payload.get(key))
        if title:
            return title
    return f"Discovery #{discovery_id}"


def _evidence_refs(payload: dict[str, Any], confirmed_by: str) -> list[str]:
    refs: list[str] = []
    raw_refs = payload.get("evidence_refs")
    if isinstance(raw_refs, list):
        refs.extend(ref.strip() for ref in raw_refs if isinstance(ref, str) and ref.strip())
    if confirmed_by and confirmed_by not in refs:
        refs.append(confirmed_by)
    return refs


async def project_discovery_outcomes(
    investigation_id: str,
    *,
    session: AsyncSession,
) -> list[str]:
    """Create one draft outcome per discovery, independently of agent submits.

    The investigation lock serializes concurrent branch projections. The
    deterministic primary key makes retries idempotent without a migration.
    Ledger provenance remains authoritative; only an explicit ``confirmed_by``
    citation can produce a positive direct-finding draft.
    """
    sql_session = cast(SQLModelAsyncSession, session)
    investigation = (await sql_session.exec(
        select(VRInvestigationRecord)
        .where(VRInvestigationRecord.id == investigation_id)
        .with_for_update()
    )).first()
    if investigation is None:
        raise ValueError(f"Investigation {investigation_id} not found")

    discoveries = list((await sql_session.exec(
        select(InvestigationLedgerRecord)
        .where(InvestigationLedgerRecord.investigation_id == investigation_id)
        .where(InvestigationLedgerRecord.kind == "discovery")
        .order_by(col(InvestigationLedgerRecord.id))
    )).all())
    created: list[str] = []
    for discovery in discoveries:
        if discovery.id is None:
            raise RuntimeError("Persisted ledger discovery has no id")
        discovery_id = discovery.id
        outcome_id = f"{_PROJECTION_ID_PREFIX}{discovery_id}"
        existing = await session.get(VRInvestigationOutcomeRecord, outcome_id)
        if existing is not None:
            if existing.investigation_id != investigation_id:
                raise RuntimeError(
                    f"Projected outcome {outcome_id} belongs to another investigation",
                )
            continue
        try:
            payload = json.loads(discovery.payload_json or "{}")
        except (json.JSONDecodeError, TypeError):
            payload = {}
        if not isinstance(payload, dict):
            payload = {}

        confirmed_by = _text(payload.get("confirmed_by"))
        title = _discovery_title(payload, discovery_id)
        why_plausible = _text(payload.get("why_plausible"))
        answer = title
        if why_plausible and why_plausible != title:
            answer = f"{title}\n\n{why_plausible}"
        outcome_payload = {
            "title": title,
            "answer": answer,
            "ledger_discovery_id": discovery_id,
            "review_state": "confirmed" if confirmed_by else "unverified",
        }
        for key in ("hypothesis_id", "source", "phase_mission"):
            value = _text(payload.get(key))
            if value:
                outcome_payload[key] = value

        session.add(VRInvestigationOutcomeRecord(
            id=outcome_id,
            investigation_id=investigation_id,
            branch_id=discovery.author_branch_id,
            outcome_kind=(
                OutcomeKind.DIRECT_FINDING.value if confirmed_by
                else OutcomeKind.ASSESSMENT_REPORT.value
            ),
            confidence="strong" if confirmed_by else "unknown",
            payload_json=json.dumps(outcome_payload),
            evidence_refs_json=json.dumps(_evidence_refs(payload, confirmed_by)),
            state="draft",
            dispatch_status="pending",
        ))
        created.append(outcome_id)
    if created:
        await session.flush()
    return created
