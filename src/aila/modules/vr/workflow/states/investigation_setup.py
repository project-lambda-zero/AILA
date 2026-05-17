"""Investigation setup state (M3.R-7).

Validates that the investigation + primary branch exist, marks status
as RUNNING, stamps started_at. Forwards investigation_id + branch_id to
the loop state.
"""
from __future__ import annotations

import logging
from typing import Any

from sqlmodel import select as _select

from aila.modules.vr.contracts.investigation import InvestigationStatus
from aila.modules.vr.db_models import (
    VRInvestigationBranchRecord,
    VRInvestigationRecord,
)
from aila.platform.contracts._common import utc_now
from aila.platform.uow import UnitOfWork
from aila.platform.workflows.types import StateResult

__all__ = ["state_investigation_setup"]

_log = logging.getLogger(__name__)


async def state_investigation_setup(input: dict[str, Any], services: Any) -> StateResult:
    """Validate + mark RUNNING. Returns input + resolved branch_id."""
    del services

    investigation_id = str(input.get("investigation_id") or "")
    if not investigation_id:
        raise ValueError("investigation_setup: missing investigation_id")

    async with UnitOfWork() as uow:
        inv = (await uow.session.exec(
            _select(VRInvestigationRecord).where(
                VRInvestigationRecord.id == investigation_id,
            )
        )).first()
        if inv is None:
            raise ValueError(
                f"investigation_setup: investigation {investigation_id} not found",
            )

        branch = (await uow.session.exec(
            _select(VRInvestigationBranchRecord).where(
                VRInvestigationBranchRecord.investigation_id == investigation_id,
                VRInvestigationBranchRecord.parent_branch_id.is_(None),
            ).limit(1)
        )).first()
        if branch is None:
            raise ValueError(
                f"investigation_setup: no primary branch for {investigation_id}",
            )

        now = utc_now()
        inv.status = InvestigationStatus.RUNNING.value
        if inv.started_at is None:
            inv.started_at = now
        inv.updated_at = now
        uow.session.add(inv)
        await uow.commit()

    # Resolve any CVE ids mentioned in the operator's question so the
    # agent gets honest "found" / "not_found" / "error" status instead
    # of inventing details when NVD has nothing. Mirrors the existing
    # IntelService path used by the vulnerability module's read
    # endpoint, but produces a structured list the prompt builder
    # renders explicitly.
    from aila.modules.vr.services.cve_intel_resolver import (  # noqa: PLC0415
        extract_cve_ids,
        resolve_cve_intel,
    )
    cve_ids = extract_cve_ids(inv.initial_question)
    cve_intel: list[dict[str, Any]] = []
    if cve_ids:
        try:
            resolutions = await resolve_cve_intel(cve_ids)
            cve_intel = [r.to_dict() for r in resolutions]
        except Exception as exc:  # noqa: BLE001 — never block setup on intel failure
            _log.warning(
                "investigation_setup: CVE intel resolve failed: %s", exc,
            )

    _log.info(
        "investigation_setup READY investigation_id=%s branch_id=%s "
        "strategy=%s cve_intel=%d",
        investigation_id, branch.id, inv.strategy_family, len(cve_intel),
    )

    return StateResult(
        next_state="investigation_loop",
        output={
            "investigation_id": investigation_id,
            "branch_id": branch.id,
            "strategy_family": inv.strategy_family,
            "auto_pilot": inv.auto_pilot,
            "cost_budget_usd": inv.cost_budget_usd,
            "team_id": inv.team_id,
            "cve_intel": cve_intel,
        },
    )
