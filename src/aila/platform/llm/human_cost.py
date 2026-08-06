"""Platform-driven human-equivalent cost estimation (Phase 175 / D-06).

After a scan completes, call estimate_human_cost() to ask the LLM
how many hours a human security consultant would need for equivalent work.
The estimation itself uses task_type="cost_estimation" so its LLM cost
is tracked separately and excluded from ROI calculations (D-06b).

Human cost is stored by UPDATING the original run's LLMCostRecords
(human_cost_hours and human_cost_usd columns) rather than creating
sentinel records. This keeps ROI queries simple -- just SUM from the
same table with no special-case filtering.

Design decision: Option A -- UPDATE original records (no sentinel run_id="_human_estimate").
  - ROI queries: SUM(human_cost_usd) WHERE human_cost_usd IS NOT NULL
  - No asymmetry between LLM cost and human cost in the same table
  - Clean queries in the /cost/roi endpoint
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import TYPE_CHECKING

import pydantic
import sqlalchemy.exc
import structlog
from pydantic import BaseModel

from ..exceptions import AILAError
from ..prompts import PromptRegistry
from .correlation import correlation_scope, current_join_keys, current_prompt_version
from .errors import LLMError

if TYPE_CHECKING:
    from ...storage.registry import ConfigRegistry
    from .client import AilaLLMClient

_log = structlog.get_logger(__name__)

_DEFAULT_HOURLY_RATE = 150.0

_PROMPT_DIR = Path(__file__).resolve().parents[1] / "prompts"
_PROMPT_REGISTRY = PromptRegistry(_PROMPT_DIR, fallback_base="system_human_cost.md")


def _load_human_cost_prompt() -> str:
    """Return the estimator system prompt from the platform prompt registry.

    RFC-09 criterion 1: prompt lives in a versionable ``.md`` file, not an
    inline literal. ``PromptRegistry.load("human_cost")`` reads
    ``system_human_cost.md`` under the platform prompts directory (its
    canonical fallback base), so the callable stays honest even if a
    strategy-specific variant is later dropped in.
    """
    return _PROMPT_REGISTRY.load("human_cost")


class HumanCostEstimate(BaseModel):
    """Structured output from the estimation LLM call."""

    estimated_hours: float
    reasoning: str
    confidence: str  # "high", "medium", "low"


async def estimate_human_cost(
    *,
    llm_client: AilaLLMClient,
    registry: ConfigRegistry,
    team_id: str | None,
    run_id: str,
    target_count: int,
    finding_count: int,
    task_types_performed: list[str],
    scan_duration_minutes: float,
) -> HumanCostEstimate | None:
    """Estimate human-equivalent cost for a completed scan.

    Sends a structured prompt to the LLM and stores the result
    by UPDATING existing LLMCostRecords for the given run_id
    with human_cost_hours and human_cost_usd.

    Args:
        llm_client: AilaLLMClient instance for chat_structured call.
        registry: ConfigRegistry for hourly rate lookup.
        team_id: Team that owns the scan (for cost record attribution).
        run_id: The scan run_id whose records will be updated.
        target_count: Number of targets scanned.
        finding_count: Number of findings produced.
        task_types_performed: List of task_types executed during the scan.
        scan_duration_minutes: Wall-clock scan duration.

    Returns:
        HumanCostEstimate on success, None on failure or no records found.

    Never raises -- logs and returns None on any error.
    """
    try:
        system_prompt = _load_human_cost_prompt()
        messages = [
            {"role": "system", "content": system_prompt},
            {
                "role": "user",
                "content": json.dumps({
                    "targets_scanned": target_count,
                    "findings_produced": finding_count,
                    "tasks_performed": task_types_performed,
                    "scan_duration_minutes": round(scan_duration_minutes, 1),
                }),
            },
        ]

        # RFC-09 criterion 2: stamp the resolved prompt's content hash so
        # this LLM call's LLMCostRecord + AuditSealRecord attribute back to
        # the exact prompt template. Version stays None until the estimator
        # prompt is registered in the platform PromptVersionStore. Preserve
        # any outer join keys so a caller that already opened a scope keeps
        # its investigation/branch/turn attribution.
        prompt_hash = hashlib.sha256(system_prompt.encode("utf-8")).hexdigest()
        _inv, _br, _turn = current_join_keys()
        with correlation_scope(
            investigation_id=_inv, branch_id=_br, turn_number=_turn,
            prompt_content_hash=prompt_hash,
            prompt_version=current_prompt_version(),
        ):
            response = await llm_client.chat_structured(
                "cost_estimation",
                messages,
                HumanCostEstimate,
                run_id=None,   # NOT attributed to the scan run (D-06b)
                team_id=team_id,
            )

        if response.disabled:
            _log.warning(
                "human_cost_estimation_llm_disabled",
                run_id=run_id,
                team_id=team_id,
            )
            return None

        # Parse from response.content (LLMResponse has no .parsed attribute --
        # chat_structured validates internally but returns content as JSON string)
        try:
            estimate = HumanCostEstimate.model_validate_json(response.content)
        except pydantic.ValidationError:
            _log.warning(
                "human_cost_estimation_parse_failed",
                run_id=run_id,
                team_id=team_id,
                content_preview=response.content[:200] if response.content else "",
            )
            return None

        # Look up hourly rate from ConfigRegistry (D-06a)
        rate_raw = await registry.get("platform", "llm_human_consultant_hourly_rate")
        if rate_raw is not None:
            try:
                hourly_rate = float(rate_raw)
            except (ValueError, TypeError):
                hourly_rate = _DEFAULT_HOURLY_RATE
        else:
            hourly_rate = _DEFAULT_HOURLY_RATE

        human_cost_usd = estimate.estimated_hours * hourly_rate

        # UPDATE original run's cost records (not sentinel records)
        # This approach keeps ROI queries simple: just SUM human_cost_usd
        # over LLMCostRecord rows where it's not null.
        from sqlmodel import select

        from aila.platform.llm.cost_record import LLMCostRecord
        from aila.storage.database import async_session_scope

        async with async_session_scope() as session:
            stmt = select(LLMCostRecord).where(
                LLMCostRecord.run_id == run_id,
            )
            records = (await session.exec(stmt)).all()

            if not records:
                _log.warning(
                    "human_cost_no_records_for_run",
                    run_id=run_id,
                    team_id=team_id,
                )
                return None

            # Distribute human cost evenly across all records for the run.
            # Even distribution is simpler for ROI queries (SUM aggregates correctly).
            hours_per_record = estimate.estimated_hours / len(records)
            usd_per_record = human_cost_usd / len(records)
            for record in records:
                record.human_cost_hours = hours_per_record
                record.human_cost_usd = usd_per_record
                session.add(record)
            await session.commit()

        _log.info(
            "human_cost_estimated",
            team_id=team_id,
            run_id=run_id,
            estimated_hours=estimate.estimated_hours,
            human_cost_usd=human_cost_usd,
            confidence=estimate.confidence,
            records_updated=len(records),
        )
        return estimate

    except (
        AILAError,
        LLMError,
        pydantic.ValidationError,
        sqlalchemy.exc.SQLAlchemyError,
    ):
        _log.warning(
            "human_cost_estimation_failed",
            team_id=team_id,
            run_id=run_id,
            exc_info=True,
        )
        return None
