"""Platform prompt registry (RFC-09)."""
from __future__ import annotations

from typing import NamedTuple

from .registry import PromptNotFoundError, PromptRegistry

__all__ = ["LoadedPrompt", "PromptNotFoundError", "PromptRegistry"]


class LoadedPrompt(NamedTuple):
    """Resolved system-prompt body plus the version it was resolved from.

    ``version`` is None when the caller fell back to the file registry
    (no store row, unpinnable, or the store failed open). Callers thread
    ``version`` into the correlation scope so every LLM call written by
    R1's cost / seal writers is attributable to the exact version.
    """

    body: str
    version: str | None
