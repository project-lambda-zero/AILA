"""VR module domain services.

Most services live in their own submodules and are imported directly by
callers (`from aila.modules.vr.services.machine_readiness import ...`).
``TargetIngestionService`` is re-exported here because it is the canonical
entrypoint used by both the setup state handler and the upload API router.
"""
from __future__ import annotations

from aila.modules.vr.services.target_ingestion import TargetIngestionService

__all__ = ["TargetIngestionService"]
