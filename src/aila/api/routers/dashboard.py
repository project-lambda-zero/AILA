"""Dashboard aggregation router for AILA REST API.

Provides GET /dashboard: collects platform stats and module contributions.
Per BE-01 / D-34: operator+ role required.
Per D-27: DataEnvelope response.
Per D-31: slowapi rate limiting.
"""
from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta

from fastapi import APIRouter, Depends, Request
from sqlmodel import select

from aila.api.limiter import limiter
from aila.api.auth import AuthContext, require_user_or_api_key
from aila.api.constants import ROLE_OPERATOR
from aila.api.schemas.endpoints import DashboardResponse, FleetStats
from aila.api.schemas.envelope import DataEnvelope
from aila.storage.database import async_session_scope
from aila.storage.db_models import FindingWorkflowRecord, ManagedSystemRecord

__all__ = ["router"]

_log = logging.getLogger(__name__)

router = APIRouter(prefix="/dashboard", tags=["dashboard"], dependencies=[Depends(require_user_or_api_key)])

_ROLE_LEVELS: dict[str, int] = {"reader": 0, "operator": 1, "admin": 2}


def _require_operator(auth: AuthContext = Depends(require_user_or_api_key)) -> AuthContext:
    if _ROLE_LEVELS.get(auth.role, -1) < _ROLE_LEVELS[ROLE_OPERATOR]:
        from fastapi import HTTPException, status

        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Dashboard requires '{ROLE_OPERATOR}' role or higher; current role: '{auth.role}'",
        )
    return auth


@router.get("", response_model=DataEnvelope[DashboardResponse], summary="Platform dashboard aggregation")
@limiter.limit("60/minute")
async def get_dashboard(
    request: Request,
    auth: AuthContext = Depends(_require_operator),
) -> DataEnvelope[DashboardResponse]:
    """Return aggregated platform stats and module-contributed dashboard data.

    Collects total systems, finding severity distribution (from LatestFindingRecord
    if available), and module contributions via dashboard_providers().

    Per BE-01: requires operator or higher role.
    Per D-34: module data merged from all registered modules.
    """
    async with async_session_scope() as session:
        # System count
        systems_result = await session.exec(select(ManagedSystemRecord))
        all_systems = systems_result.all()
        total_systems = len(all_systems)

        # Finding severity counts — vulnerability module contribution if registered
        critical = high = medium = low = total_findings = 0
        platform = getattr(request.app.state, "platform", None)
        if platform is not None:
            try:
                module = platform.runtime.module_registry.require("vulnerability")
                counts = await module.report_count("", session)
                total_findings = int(counts.get("total_findings", 0))
                critical = int(counts.get("critical", 0))
                high = int(counts.get("high", 0))
                medium = int(counts.get("medium", 0))
                low = int(counts.get("low", 0))
            except Exception:
                _log.debug("vulnerability report_count unavailable; finding counts will be 0", exc_info=True)

        # MTTR: mean time to resolution from FindingWorkflowRecord (closed transitions)
        # Use last 30 days of closed transitions for a meaningful MTTR estimate
        thirty_days_ago = datetime.now(UTC) - timedelta(days=30)
        workflow_result = await session.exec(
            select(FindingWorkflowRecord).where(
                FindingWorkflowRecord.current_state == "closed",
                FindingWorkflowRecord.created_at >= thirty_days_ago,
            )
        )
        closed_transitions = workflow_result.all()
        # Risk score: weighted finding severity distribution on 0-10 scale
        risk_score = 0.0
        if total_findings > 0:
            risk_score = min(
                10.0,
                round(
                    (critical * 10.0 + high * 7.0 + medium * 4.0 + low * 1.0) / total_findings,
                    2,
                ),
            )

    fleet_stats = FleetStats(
        total_systems=total_systems,
        online_systems=total_systems,  # no live ping — treat all registered as online
        total_findings=total_findings,
        critical_findings=critical,
        high_findings=high,
        medium_findings=medium,
        low_findings=low,
    )

    # Module contributions via dashboard_providers()
    module_data: dict[str, object] = {}
    platform = getattr(request.app.state, "platform", None)
    if platform is not None:
        try:
            modules = platform.runtime.module_registry.modules
            for module in modules:
                if not hasattr(module, "dashboard_providers"):
                    continue
                providers = module.dashboard_providers()
                for name, provider in providers.items():
                    try:
                        result = await provider() if asyncio_iscoroutinefunction(provider) else provider()
                        module_data[f"{module.module_id}.{name}"] = result
                    except Exception:
                        _log.debug("Dashboard provider %s.%s failed", module.module_id, name)
        except Exception:
            _log.debug("Could not collect module dashboard data", exc_info=True)

    payload = DashboardResponse(
        risk_score=risk_score,
        fleet_stats=fleet_stats,
        module_data=module_data,
        generated_at=datetime.now(UTC),
    )
    return DataEnvelope(data=payload, meta={"closed_last_30d": len(closed_transitions)})


def asyncio_iscoroutinefunction(fn: object) -> bool:
    import asyncio

    return asyncio.iscoroutinefunction(fn)
