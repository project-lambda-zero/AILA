"""Async companion for the sync ``.encode`` methods on the embedding
providers (design finding #64-3.1b).

Both :class:`BGEProvider` and :class:`MiniLMProvider` gained an
:meth:`encode_async` that offloads the CPU-bound ``model.encode(...)``
call to a platform-owned worker thread via ``run_blocking_io`` so async
callers never stall the event loop. These tests verify:

* ``encode_async`` is a coroutine function on the Protocol AND both
  concrete providers.
* The returned vector has the SAME shape (list length + element type) as
  the corresponding sync ``encode`` call for a fixed text.
* Execution genuinely offloads: the underlying ``model.encode`` call runs
  on a thread OTHER than the running event loop's thread. This is the
  observable proof that ``run_blocking_io`` is doing its job.

The sentence-transformers model is heavy to load, so the tests inject a
tiny fake ``_model`` on the provider instance (the private
``_ensure_model`` path is unchanged and still tested implicitly by the
sync path in production).
"""

from __future__ import annotations

import asyncio
import inspect
import threading

from aila.platform.services.embedding import (
    BGEProvider,
    EmbeddingProvider,
    MiniLMProvider,
)


class _FakeEncoder:
    """Stub in place of a loaded SentenceTransformer.

    ``encode`` records the thread it executed on so tests can prove the
    async path really offloaded. The returned object mimics numpy's array
    API just enough for ``.tolist()`` to succeed.
    """

    def __init__(self, dim: int) -> None:
        self._dim = dim
        self.calls: list[str] = []
        self.threads: list[threading.Thread] = []

    def encode(self, text: str):
        self.calls.append(text)
        self.threads.append(threading.current_thread())

        class _ArrayLike:
            def __init__(self, dim: int) -> None:
                self._dim = dim

            def tolist(self) -> list[float]:
                # Deterministic dummy vector: 0.0 * dim. Real embeddings are
                # not needed to prove shape-parity between sync/async.
                return [0.0] * self._dim

        return _ArrayLike(self._dim)


# ---------------------------------------------------------------------------
# Protocol / signature-level checks (no model load required)
# ---------------------------------------------------------------------------


def test_protocol_declares_encode_async() -> None:
    """The EmbeddingProvider Protocol exposes an async encode_async method."""
    assert hasattr(EmbeddingProvider, "encode_async"), (
        "EmbeddingProvider Protocol must expose encode_async (design #64-3.1b)"
    )
    # The Protocol method is defined as `async def` so its function object
    # is a coroutine function.
    assert inspect.iscoroutinefunction(EmbeddingProvider.encode_async)


def test_bge_provider_declares_encode_async_as_coroutine() -> None:
    """BGEProvider.encode_async is an async method (coroutine function)."""
    assert inspect.iscoroutinefunction(BGEProvider.encode_async)


def test_minilm_provider_declares_encode_async_as_coroutine() -> None:
    """MiniLMProvider.encode_async is an async method (coroutine function)."""
    assert inspect.iscoroutinefunction(MiniLMProvider.encode_async)


# ---------------------------------------------------------------------------
# Shape parity: encode() and encode_async() return the same vector shape.
# ---------------------------------------------------------------------------


async def _assert_shape_parity(
    provider: BGEProvider | MiniLMProvider, expected_dim: int,
) -> None:
    """Inject a fake encoder into ``provider`` and assert sync/async return
    identically-shaped vectors for the same input text.
    """
    fake = _FakeEncoder(dim=expected_dim)
    # Both providers cache the loaded model on the CLASS (BGEProvider._model
    # and MiniLMProvider._model). Patching the class attribute keeps the
    # test isolated from any process-wide singleton state.
    cls = type(provider)
    original = cls._model
    cls._model = fake  # type: ignore[assignment]
    try:
        sync_vec = provider.encode("hello world")
        async_vec = await provider.encode_async("hello world")

        assert isinstance(sync_vec, list)
        assert isinstance(async_vec, list)
        assert len(sync_vec) == len(async_vec) == expected_dim
        assert sync_vec == async_vec
        assert all(isinstance(x, float) for x in async_vec)
    finally:
        cls._model = original  # type: ignore[assignment]


async def test_bge_encode_async_matches_sync_shape() -> None:
    """BGEProvider.encode_async returns the same 1024-dim vector shape as encode()."""
    provider = BGEProvider()
    await _assert_shape_parity(provider, expected_dim=1024)


async def test_minilm_encode_async_matches_sync_shape() -> None:
    """MiniLMProvider.encode_async returns the same 384-dim vector shape as encode()."""
    provider = MiniLMProvider()
    await _assert_shape_parity(provider, expected_dim=384)


# ---------------------------------------------------------------------------
# Offload proof: async encode really runs on a worker thread, not the loop.
# ---------------------------------------------------------------------------


async def _assert_offloads(provider: BGEProvider | MiniLMProvider, dim: int) -> None:
    fake = _FakeEncoder(dim=dim)
    cls = type(provider)
    original = cls._model
    cls._model = fake  # type: ignore[assignment]
    try:
        loop = asyncio.get_running_loop()
        # Capture the event-loop thread ident by scheduling a no-op through
        # call_soon_threadsafe -- the callback fires on the loop thread.
        loop_thread_ident: list[int] = []
        done = asyncio.Event()

        def _capture() -> None:
            loop_thread_ident.append(threading.get_ident())
            loop.call_soon_threadsafe(done.set)

        loop.call_soon(_capture)
        await done.wait()

        await provider.encode_async("hello world")

        assert fake.threads, "fake encoder should have recorded a call thread"
        encode_thread = fake.threads[-1]
        assert encode_thread.ident != loop_thread_ident[0], (
            "encode_async must offload the blocking encode() to a worker "
            "thread (design #64-3.1b -- run_blocking_io contract)"
        )
    finally:
        cls._model = original  # type: ignore[assignment]


async def test_bge_encode_async_offloads_to_worker_thread() -> None:
    """BGE encode_async runs the blocking encode off the event-loop thread."""
    await _assert_offloads(BGEProvider(), dim=1024)


async def test_minilm_encode_async_offloads_to_worker_thread() -> None:
    """MiniLM encode_async runs the blocking encode off the event-loop thread."""
    await _assert_offloads(MiniLMProvider(), dim=384)
