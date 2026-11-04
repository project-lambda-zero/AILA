"""VRWorkflowServices -- service bag for VR workflow state handlers.

Constructed once per workflow run by ``definitions_hub._build_services``
(a fresh instance per run; Phase 178 D-15 freshness contract, no caching
across handlers). Each state handler receives it as its ``services``
argument.
"""
from __future__ import annotations

from dataclasses import dataclass

from aila.platform.llm.client import AilaLLMClient
from aila.platform.services.factory import ServiceFactory

__all__ = ["VRWorkflowServices"]


@dataclass(slots=True)
class VRWorkflowServices:
    """Service bag for VR workflow state handlers.

    Fields:
        run_id: Unique identifier for this workflow execution.
        llm_client: Platform LLM client for agent reasoning steps.
    """

    run_id: str
    llm_client: AilaLLMClient

    @classmethod
    async def build(cls, run_id: str) -> VRWorkflowServices:
        """Construct a fresh services bundle for ``run_id`` (D-15: no caching)."""
        return cls(run_id=run_id, llm_client=ServiceFactory().llm_client)
