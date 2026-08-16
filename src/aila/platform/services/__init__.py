"""Platform-owned shared service adapters."""

from __future__ import annotations

from .audit import record_audit_event
from .context_assembler import (
    AssembledContext,
    ContextAssembler,
    ContextSection,
    ContextTier,
    PinnedOverflowError,
    SummaryProducer,
)
from .embedding import BGEProvider, EmbeddingProvider, MiniLMProvider, resolve_provider
from .factory import ServiceFactory
from .http import build_async_http_client, build_http_client
from .knowledge import KnowledgeService
from .ledger import LedgerService
from .oracle import Oracle
from .reasoning import CyberReasoningEngine
from .reasoning_graphs import ReasoningGraphService
from .report import ReportService
from .ssh import SSHService
from .storage import StorageService
from .system import SystemService

__all__ = [
    "AssembledContext",
    "BGEProvider",
    "ContextAssembler",
    "ContextSection",
    "ContextTier",
    "CyberReasoningEngine",
    "EmbeddingProvider",
    "KnowledgeService",
    "LedgerService",
    "MiniLMProvider",
    "Oracle",
    "PinnedOverflowError",
    "ReasoningGraphService",
    "ReportService",
    "SSHService",
    "ServiceFactory",
    "StorageService",
    "SummaryProducer",
    "SystemService",
    "build_async_http_client",
    "build_http_client",
    "record_audit_event",
    "resolve_provider",
]
