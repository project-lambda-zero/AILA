"""TemplateWorkflowServices -- minimal service bag for template state handlers.

Every workflow definition supplies a ``services_factory`` that the
platform engine calls once per state execution. The template ships
the SMALLEST bag the investigation loop needs (a live ``llm_client``);
copiers extend it with the module-specific bridges + services their
state handlers actually consume.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from aila.config import Settings, get_settings
from aila.platform.llm.client import AilaLLMClient
from aila.platform.services.factory import ServiceFactory

__all__ = ["TemplateWorkflowServices"]

_log = logging.getLogger(__name__)


@dataclass(slots=True)
class TemplateWorkflowServices:
    """Minimal per-run service bundle for template state handlers.

    Fields:
        run_id: The workflow run identifier.
        settings: Live platform :class:`Settings`.
        llm_client: The platform LLM client the investigation loop
            hands to :class:`CyberReasoningEngine`.
    """

    run_id: str
    settings: Settings
    llm_client: AilaLLMClient

    @classmethod
    async def build(cls, run_id: str) -> TemplateWorkflowServices:
        """Construct a fresh bag per attempt (D-15 freshness contract)."""
        return cls(
            run_id=run_id,
            settings=get_settings(),
            llm_client=ServiceFactory().llm_client,
        )
