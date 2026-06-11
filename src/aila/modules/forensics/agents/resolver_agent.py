"""Resolver agent — maps questions to artifact families.

The resolver takes a set of questions and attempts to answer them by
querying existing artifacts and leads. Unlike the free-flow agent, it
does NOT generate or execute scripts — it works purely with already-collected data.
"""
from __future__ import annotations

import json
import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aila.modules.forensics.workflow.services import ForensicsWorkflowServices
    from aila.platform.llm import AilaLLMClient

__all__ = ["ResolverAgent"]

_log = logging.getLogger(__name__)


def _llm_client_from_services(services: ForensicsWorkflowServices | None) -> AilaLLMClient:
    """Return the LLM client from ``services``, falling back to the
    ServiceFactory singleton when the caller does not have a services
    bag on hand.

    Fix §24 — every resolver path now shares the memoized
    ``ServiceFactory.llm_client`` instance instead of constructing a
    fresh ``AilaLLMClient`` (with its own ConfigRegistry + SecretStore
    I/O) on every resolution.
    """
    if services is not None:
        return services.llm_client
    from aila.platform.services.factory import ServiceFactory

    return ServiceFactory().llm_client


class ResolverAgent:
    """Maps investigation questions to existing artifacts for resolution."""

    def __init__(
        self,
        services: ForensicsWorkflowServices | None,
        project_id: str,
    ) -> None:
        # fix §24 — services bag carries the memoized AilaLLMClient.
        # Tests that don't need an LLM may pass services=None; in that
        # case _attempt_resolution falls back to the ServiceFactory
        # singleton via _llm_client_from_services.
        self._services = services
        self.project_id = project_id

    async def resolve(self, question: str) -> dict[str, Any]:
        """Attempt to answer a question using existing artifacts.

        Args:
            question: The forensic question to resolve.

        Returns:
            Dict with 'answer', 'confidence', 'primary_artifact_id',
            'corroboration', 'resolved' (bool).
        """
        artifacts = await self._get_relevant_artifacts(question)
        leads = await self._get_relevant_leads(question)

        if not artifacts and not leads:
            return {
                "resolved": False,
                "answer": None,
                "confidence": "caveated",
                "reasoning": "No artifacts or leads match this question.",
                "primary_artifact_id": None,
            }

        return await self._attempt_resolution(question, artifacts, leads)

    async def _get_relevant_artifacts(self, question: str) -> list[dict[str, Any]]:
        """Retrieve artifacts potentially relevant to the question."""
        from sqlmodel import select

        from aila.modules.forensics.db_models import ArtifactRecord
        from aila.platform.uow import UnitOfWork

        question_lower = question.lower()
        family_hints = _infer_families_from_question(question_lower)

        async with UnitOfWork() as uow:
            query = select(ArtifactRecord).where(
                ArtifactRecord.project_id == self.project_id
            )
            if family_hints:
                query = query.where(ArtifactRecord.artifact_family.in_(family_hints))
            rows = (await uow.session.exec(query.limit(100))).all()

        return [
            {
                "id": r.id,
                "family": r.artifact_family,
                "type": r.artifact_type,
                "data": json.loads(r.data_json) if r.data_json else {},
                "score": r.lead_score,
            }
            for r in rows
        ]

    async def _get_relevant_leads(self, question: str) -> list[dict[str, Any]]:
        """Retrieve leads relevant to the question, prioritizing family matches."""
        from sqlmodel import select

        from aila.modules.forensics.db_models import LeadRecord
        from aila.platform.uow import UnitOfWork

        question_families = _infer_families_from_question(question.lower())

        async with UnitOfWork() as uow:
            query = (
                select(LeadRecord)
                .where(LeadRecord.project_id == self.project_id)
                .order_by(LeadRecord.score.desc())
            )
            if question_families:
                query = query.where(LeadRecord.artifact_family.in_(question_families))
            rows = (await uow.session.exec(query.limit(20))).all()

            if not rows and question_families:
                rows = (await uow.session.exec(
                    select(LeadRecord)
                    .where(LeadRecord.project_id == self.project_id)
                    .order_by(LeadRecord.score.desc())
                    .limit(20)
                )).all()

        return [
            {
                "id": r.id,
                "artifact_id": r.artifact_id,
                "score": r.score,
                "reason": r.reason,
                "family": r.artifact_family,
            }
            for r in rows
        ]

    async def _attempt_resolution(
        self,
        question: str,
        artifacts: list[dict[str, Any]],
        leads: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Use LLM to attempt answering the question from artifacts/leads."""
        context = json.dumps({
            "artifacts": artifacts[:20],
            "leads": leads[:10],
        }, indent=2, default=str)[:4000]

        prompt = (
            f"Question: {question}\n\n"
            f"Available evidence:\n{context}\n\n"
            "If you can answer the question from this evidence, provide the answer. "
            "If not, explain what additional investigation is needed.\n"
            "Return JSON: {\"resolved\": bool, \"answer\": str|null, "
            "\"confidence\": str, \"reasoning\": str, \"primary_artifact_id\": str|null}"
        )

        try:
            # fix §24 — share the run-scoped LLM client memoized on
            # ``services`` instead of building a fresh one (and a
            # fresh ConfigRegistry / SecretStore) per resolution.
            client = _llm_client_from_services(self._services)
            resp = await client.chat(
                task_type="forensics_resolver",
                messages=[
                    {"role": "system", "content": "You are a forensic evidence resolver. Answer questions using only the provided evidence."},
                    {"role": "user", "content": prompt},
                ],
            )
            if resp.disabled:
                _log.warning("LLM disabled — cannot resolve")
            else:
                response = resp.content
                start = response.find("{")
                end = response.rfind("}") + 1
                if start >= 0 and end > start:
                    parsed = json.loads(response[start:end])
                    return {
                        "resolved": bool(parsed.get("resolved", False)),
                        "answer": parsed.get("answer"),
                        "confidence": parsed.get("confidence", "caveated"),
                        "reasoning": parsed.get("reasoning", ""),
                        "primary_artifact_id": parsed.get("primary_artifact_id"),
                    }
        except (RuntimeError, ValueError, OSError, TimeoutError):
            _log.warning("LLM resolution failed", exc_info=True)

        return {
            "resolved": False,
            "answer": None,
            "confidence": "caveated",
            "reasoning": "Could not resolve from existing artifacts.",
            "primary_artifact_id": None,
        }


def _infer_families_from_question(question_lower: str) -> list[str]:
    """Heuristically infer artifact families from question keywords."""
    families: list[str] = []
    keyword_map = {
        "malware": "malware",
        "virus": "malware",
        "trojan": "malware",
        "rootkit": "malware",
        "ip address": "network",
        "c2": "network",
        "network": "network",
        "port": "network",
        "protocol": "network",
        "dns": "network",
        "process": "execution",
        "pid": "execution",
        "execute": "execution",
        "inject": "execution",
        "file name": "filesystem",
        "file path": "filesystem",
        "sha256": "filesystem",
        "hash": "filesystem",
        "user": "user",
        "password": "user",
        "login": "user",
        "browser": "browser",
        "memory": "memory",
        "dump": "memory",
    }
    for keyword, family in keyword_map.items():
        if keyword in question_lower and family not in families:
            families.append(family)
    return families
