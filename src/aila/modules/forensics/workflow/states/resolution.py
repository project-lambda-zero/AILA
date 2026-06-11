"""Question resolution state handler.

Maps investigation goals to artifact families. For each question-type,
identifies the primary artifact + transform + corroboration path.
Uses the ``ResolverAgent`` to attempt LLM-backed resolution of each
question family against collected artifacts.
"""
from __future__ import annotations

import json
import logging
from typing import Any

from aila.platform.exceptions import AILAError

__all__ = ["state_resolution"]

_log = logging.getLogger(__name__)

state_resolution_parallel_safe = False
state_resolution_writes_fields = ["answers"]


async def state_resolution(
    input: dict[str, Any],
    services: Any,
) -> dict[str, Any]:
    """Map questions to artifact families and attempt resolution.

    Enriches each lead with question family tags, then uses the
    ``ResolverAgent`` to attempt LLM-backed resolution for the
    top-scoring leads.

    Args:
        input: Workflow input with 'project_id', 'top_leads'.
        services: ForensicsWorkflowServices instance.

    Returns:
        Dict with 'answers_found', 'questions_mapped', 'project_id'.
    """
    project_id = input.get("project_id", "")
    top_leads = input.get("top_leads", [])

    await services.emitter.emit("resolution", "Mapping leads to answerable question families...")

    from sqlmodel import select

    from aila.modules.forensics.db_models import LeadRecord
    from aila.platform.uow import UnitOfWork

    question_families: set[str] = set()

    async with UnitOfWork() as uow:
        leads = (await uow.session.exec(
            select(LeadRecord)
            .where(LeadRecord.project_id == project_id)
            .order_by(LeadRecord.score.desc())
        )).all()

        for lead in leads:
            families = _infer_question_families(lead.artifact_family, lead.reason)
            question_families.update(families)

            lead.question_families_json = json.dumps(sorted(families))
            uow.session.add(lead)

        await uow.commit()

    await services.emitter.emit(
        "resolution",
        f"Mapped {len(leads)} leads to {len(question_families)} question families.",
        {"question_families": sorted(question_families)},
    )

    answers_found = 0
    resolved_answers: list[dict[str, Any]] = []

    if question_families:
        try:
            import time as _time

            from aila.modules.forensics.agents.resolver_agent import ResolverAgent

            resolver = ResolverAgent(services, project_id)
            families_to_try = sorted(question_families)[:10]
            await services.emitter.emit(
                "resolution",
                f"Resolver: attempting LLM-backed answers for {len(families_to_try)} family/ies",
                {"stage": "resolver_begin", "families": families_to_try},
            )

            for idx, family in enumerate(families_to_try, 1):
                await services.emitter.emit(
                    "resolution",
                    f"Resolver {idx}/{len(families_to_try)}: querying LLM for '{family}'",
                    {"stage": "resolver_query_start", "family": family, "step": idx, "total": len(families_to_try)},
                )
                qstart = _time.monotonic()
                result = await resolver.resolve(
                    f"Based on the collected evidence, what can be determined about: {family}?"
                )
                elapsed = _time.monotonic() - qstart
                resolved = bool(result.get("resolved"))
                if resolved:
                    answers_found += 1
                    resolved_answers.append({
                        "question_family": family,
                        "answer": result.get("answer"),
                        "confidence": result.get("confidence"),
                        "reasoning": result.get("reasoning"),
                    })
                await services.emitter.emit(
                    "resolution",
                    f"Resolver {idx}/{len(families_to_try)}: '{family}' {'resolved' if resolved else 'unresolved'} in {elapsed:.1f}s",
                    {
                        "stage": "resolver_query_done",
                        "family": family,
                        "resolved": resolved,
                        "elapsed_s": round(elapsed, 1),
                        "confidence": result.get("confidence"),
                        "answer_preview": (result.get("answer") or "")[:300],
                    },
                )
        except (RuntimeError, ValueError, KeyError, OSError, AILAError):
            _log.warning("ResolverAgent failed during resolution", exc_info=True)
            await services.emitter.emit(
                "resolution",
                "Resolver crashed — continuing with empty resolved-answers list.",
                {"stage": "resolver_failed"},
            )

    if resolved_answers:
        await services.emitter.emit(
            "resolution",
            f"Resolved {answers_found} question families via artifact analysis.",
            {"resolved_answers": resolved_answers},
        )

    from aila.platform.workflows.types import StateResult

    return StateResult(
        next_state="writeup",
        output={
            "answers_found": answers_found,
            "questions_mapped": len(question_families),
            "resolved_answers": resolved_answers,
            "project_id": project_id,
            "top_leads": top_leads,
            "valuable_items": input.get("valuable_items", {}),
            "integration": input.get("integration", {}),
            "evidence_directory": input.get("evidence_directory", ""),
            "analyzer_os": input.get("analyzer_os", "linux"),
        },
    )


def _infer_question_families(artifact_family: str, reason: str) -> list[str]:
    """Infer which question families a lead can help answer."""
    families: list[str] = []
    reason_lower = reason.lower()

    family_mapping = {
        "malware": ["malware_identification", "malware_behavior", "persistence"],
        "network": ["c2_communication", "network_activity", "data_exfiltration"],
        "execution": ["process_activity", "malware_execution", "persistence"],
        "host": ["system_identification", "user_activity"],
        "user": ["user_activity", "credentials"],
        "browser": ["user_activity", "download_history"],
        "memory": ["process_activity", "malware_behavior", "injection"],
    }
    families.extend(family_mapping.get(artifact_family, []))

    keyword_families = {
        "c2": "c2_communication",
        "injection": "injection",
        "persistence": "persistence",
        "credential": "credentials",
        "reverse_shell": "c2_communication",
    }
    for keyword, family in keyword_families.items():
        if keyword in reason_lower and family not in families:
            families.append(family)

    return families


state_resolution.parallel_safe = state_resolution_parallel_safe  # type: ignore[attr-defined]
state_resolution.writes_fields = state_resolution_writes_fields  # type: ignore[attr-defined]
