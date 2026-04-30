"""Platform-owned shared service adapters."""

from __future__ import annotations

from .audit import record_audit_event
from .embedding import BGEProvider, EmbeddingProvider, MiniLMProvider, resolve_provider
from .factory import ServiceFactory
from .http import build_http_client
from .knowledge import KnowledgeService
from .reasoning import CyberReasoningEngine
from .reasoning_graphs import ReasoningGraphService
from .report import ReportService
from .ssh import SSHService
from .storage import StorageService
from .system import SystemService

__all__ = [
    "BGEProvider",
    "CyberReasoningEngine",
    "EmbeddingProvider",
    "KnowledgeService",
    "MiniLMProvider",
    "ReasoningGraphService",
    "ReportService",
    "SSHService",
    "ServiceFactory",
    "StorageService",
    "SystemService",
    "build_http_client",
    "record_audit_event",
    "resolve_provider",
]
