"""AILA API error envelope package (Phase 176a).

Exports:
- :class:`ErrorEnvelope` -- canonical error response body.
- :data:`ERROR_HINTS` -- operator-facing prescriptive hint registry.
- :func:`register_error_handlers` -- wire envelope handlers onto a FastAPI app.
"""
from __future__ import annotations

from aila.api.errors.envelope import ErrorEnvelope
from aila.api.errors.handlers import register_error_handlers
from aila.api.errors.hints import ERROR_HINTS

__all__ = ["ErrorEnvelope", "ERROR_HINTS", "register_error_handlers"]
