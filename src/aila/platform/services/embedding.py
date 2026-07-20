from __future__ import annotations

import threading
from typing import Protocol, runtime_checkable


@runtime_checkable
class EmbeddingProvider(Protocol):
    """Protocol for swappable embedding models per D-08.

    Implementations produce dense float vectors from text.
    The dimension property must match the pgvector column width.

    The Protocol exposes both a sync (:meth:`encode`) and an async
    (:meth:`encode_async`) surface: sync callers stay on the existing path,
    async callers use :meth:`encode_async` which offloads the blocking
    ``model.encode(...)`` call to a worker thread via
    :func:`aila.platform.services.runtime.run_blocking_io` so the event
    loop is never stalled by CPU-bound embedding work (design #64-3.1b).
    """

    @property
    def dimension(self) -> int:
        """Vector dimensionality (must match pgvector column)."""
        ...

    @property
    def model_name(self) -> str:
        """Human-readable model identifier."""
        ...

    def encode(self, text: str) -> list[float]:
        """Encode text to a dense float vector. Synchronous -- called outside DB transactions."""
        ...

    async def encode_async(self, text: str) -> list[float]:
        """Async companion to :meth:`encode`; offloads the sync encode via ``run_blocking_io``."""
        ...


class BGEProvider:
    """BGE-M3 embedding provider: 1024-dim, dense+sparse, CPU, free/local.

    Default provider per D-08. Loaded lazily on first encode() call.
    Thread-safe via module-level lock (same pattern as existing knowledge.py).
    """

    _model: object | None = None
    _lock: threading.Lock = threading.Lock()

    @property
    def dimension(self) -> int:
        return 1024

    @property
    def model_name(self) -> str:
        return "BAAI/bge-m3"

    def encode(self, text: str) -> list[float]:
        model = self._ensure_model()
        return model.encode(text).tolist()

    async def encode_async(self, text: str) -> list[float]:
        """Async encode: offloads the CPU-bound ``SentenceTransformer.encode``
        call to a platform-owned worker thread so the event loop stays
        responsive (design #64-3.1b, matches the ``run_blocking_io`` pattern
        already used by :mod:`aila.platform.tools.knowledge`).
        """
        # Deferred import: services.runtime imports back into this package via
        # __init__ during startup; loading run_blocking_io at call time avoids
        # the bootstrap cycle without forcing an eager top-level dependency.
        from aila.platform.services.runtime import run_blocking_io
        return await run_blocking_io(self.encode, text)

    def _ensure_model(self) -> object:
        if BGEProvider._model is None:
            with BGEProvider._lock:
                if BGEProvider._model is None:
                    from sentence_transformers import SentenceTransformer  # type: ignore[import-untyped]
                    BGEProvider._model = SentenceTransformer("BAAI/bge-m3")
        return BGEProvider._model


class MiniLMProvider:
    """all-MiniLM-L6-v2 embedding provider: 384-dim, fastest, fallback.

    Fallback provider per D-08. Uses the same lazy singleton pattern.
    NOTE: When used with the 1024-dim pgvector column, vectors are zero-padded
    to 1024 dimensions. This is a compatibility measure -- use BGEProvider
    for full-quality 1024-dim embeddings.
    """

    _model: object | None = None
    _lock: threading.Lock = threading.Lock()

    @property
    def dimension(self) -> int:
        return 384

    @property
    def model_name(self) -> str:
        return "sentence-transformers/all-MiniLM-L6-v2"

    def encode(self, text: str) -> list[float]:
        model = self._ensure_model()
        return model.encode(text).tolist()

    async def encode_async(self, text: str) -> list[float]:
        """Async encode: offloads the CPU-bound ``SentenceTransformer.encode``
        call to a platform-owned worker thread so the event loop stays
        responsive (design #64-3.1b).
        """
        from aila.platform.services.runtime import run_blocking_io
        return await run_blocking_io(self.encode, text)

    def _ensure_model(self) -> object:
        if MiniLMProvider._model is None:
            with MiniLMProvider._lock:
                if MiniLMProvider._model is None:
                    from sentence_transformers import SentenceTransformer  # type: ignore[import-untyped]
                    MiniLMProvider._model = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
        return MiniLMProvider._model


# --- Provider registry ---

_PROVIDERS: dict[str, type[BGEProvider] | type[MiniLMProvider]] = {
    "bge-m3": BGEProvider,
    "all-MiniLM-L6-v2": MiniLMProvider,
}

DEFAULT_EMBEDDING_MODEL = "bge-m3"


def resolve_provider(model_name: str | None = None) -> BGEProvider | MiniLMProvider:
    """Resolve an EmbeddingProvider by config key value.

    Args:
        model_name: Value from ConfigRegistry key ``knowledge.embedding_model``.
            None or unrecognized values fall back to DEFAULT_EMBEDDING_MODEL.

    Returns:
        An instantiated provider satisfying EmbeddingProvider protocol.
    """
    key = model_name or DEFAULT_EMBEDDING_MODEL
    provider_cls = _PROVIDERS.get(key, _PROVIDERS[DEFAULT_EMBEDDING_MODEL])
    return provider_cls()
