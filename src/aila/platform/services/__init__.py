"""Platform-owned shared service adapters."""

from __future__ import annotations

from .audit import record_audit_event
from .context_assembler import (
    AssembledContext,
    ContextAssembler,
    ContextSection,
    ContextTier,
    PinnedOverflowError,
    RetrievalProvider,
    RetrievalRequest,
    SummaryProducer,
)
from .context_retrieval import KnowledgeRetrievalProvider
from .embedding import BGEProvider, EmbeddingProvider, MiniLMProvider, resolve_provider

# NOTE: :mod:`aila.platform.services.dynamic_execution` (issue #21) is
# intentionally NOT re-exported here. It imports the platform
# observation writer (``aila.platform.agents.observation``) whose
# package ``__init__`` closes an import cycle through
# ``platform.agents.claim_verifier -> platform.mcp -> platform.tools ->
# storage.memory``. ``storage.db_models`` -- imported very early during
# process boot -- pulls this ``__init__`` and would tip the cycle over.
# Callers import from :mod:`aila.platform.services.dynamic_execution`
# directly, matching the pattern the sandbox subpackage already uses.
from .factory import ServiceFactory
from .http import build_async_http_client, build_http_client
from .knowledge import KnowledgeService
from .ledger import LedgerService
from .lsp import (
    LANGUAGE_SPECS,
    LanguageSpec,
    LspResult,
    LspService,
    get_lsp_service,
    language_for_path,
    reset_lsp_service,
)
from .oracle import Oracle
from .reasoning import CyberReasoningEngine
from .reasoning_graphs import ReasoningGraphService
from .report import ReportService
from .shared_context_pool import (
    SHARED_POOL_NAMESPACE_PREFIX,
    SharedContextPool,
    shared_pool_namespace,
)

# NOTE: :mod:`aila.platform.services.speculator` (issue #156) is
# intentionally NOT re-exported here. The speculator's only consumer is
# the platform ``tool_executor`` which imports it lazily inside
# ``execute()`` so an operator with the feature flag OFF pays for
# nothing (the module -- including its lazy ``AilaLLMClient`` build --
# is only imported the first time speculation actually triggers). Same
# pattern the ``dynamic_execution`` note above documents.
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
    "KnowledgeRetrievalProvider",
    "KnowledgeService",
    "LANGUAGE_SPECS",
    "LanguageSpec",
    "LedgerService",
    "LspResult",
    "LspService",
    "MiniLMProvider",
    "Oracle",
    "PinnedOverflowError",
    "ReasoningGraphService",
    "ReportService",
    "RetrievalProvider",
    "RetrievalRequest",
    "SHARED_POOL_NAMESPACE_PREFIX",
    "SSHService",
    "ServiceFactory",
    "SharedContextPool",
    "StorageService",
    "SummaryProducer",
    "SystemService",
    "build_async_http_client",
    "build_http_client",
    "get_lsp_service",
    "language_for_path",
    "record_audit_event",
    "reset_lsp_service",
    "resolve_provider",
    "shared_pool_namespace",
]
