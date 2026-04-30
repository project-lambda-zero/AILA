"""ForensicsWorkflowServices — wired service bag for workflow state handlers.

Built once per workflow run by the ``_build_services`` factory in
``definitions.py``. Each state handler receives this as its ``services``
argument.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from aila.config import Settings, get_settings
from aila.modules.forensics.workflow.emitter import ForensicsWorkflowEmitter
from aila.platform.services.factory import ServiceFactory
from aila.platform.services.reasoning import CyberReasoningEngine
from aila.platform.services.reasoning_graphs import ReasoningGraphService

__all__ = ["ForensicsWorkflowServices"]

_log = logging.getLogger(__name__)


@dataclass
class ForensicsWorkflowServices:
    """Dependency bag for forensics workflow state handlers."""

    run_id: str
    settings: Settings
    emitter: ForensicsWorkflowEmitter
    reasoning_engine: CyberReasoningEngine
    reasoning_graphs: ReasoningGraphService
    project_id: str = ""
    evidence_directory: str = ""
    integration: dict[str, Any] = field(default_factory=dict)
    @classmethod
    async def build(cls, run_id: str) -> ForensicsWorkflowServices:
        """Construct services for a specific workflow run.

        Args:
            run_id: Unique identifier for this workflow execution.

        Returns:
            Fully-wired services instance.
        """
        settings = get_settings()
        factory = ServiceFactory()
        emitter = ForensicsWorkflowEmitter(run_id=run_id, module_id="forensics")
        return cls(
            run_id=run_id,
            settings=settings,
            emitter=emitter,
            reasoning_engine=factory.reasoning_engine,
            reasoning_graphs=factory.reasoning_graphs,
        )
