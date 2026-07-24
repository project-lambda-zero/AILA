"""File-backed prompt registry (RFC-09 step 0).

The module tool researchers each carried a byte-identical
``_cached_read_prompt`` + ``_load_prompt`` pair differing only in the
fallback base filename and the error class. This platform registry owns
the single file-backed resolution path so no module reimplements it, and
gives RFC-09's later steps (DB overrides, immutable versions, release
aliases, per-investigation pins) one place to grow. This step is
behavior-preserving and file-backed only -- no database, no versioning.

Resolution mirrors the prior module logic exactly: the base prompt is
``system_<strategy-leaf>.md`` (the last dotted segment of the strategy
family), falling back to a module-supplied base filename; when a persona
voice is supplied and ``persona_<voice>.md`` exists, its content is
prepended to the base as a role-specific opening section.
"""
from __future__ import annotations

import functools
from pathlib import Path

__all__ = ["PromptNotFoundError", "PromptRegistry"]


class PromptNotFoundError(RuntimeError):
    """Raised when neither the strategy-specific base nor the fallback exists."""


@functools.lru_cache(maxsize=32)
def _cached_read_prompt(path_str: str) -> str:
    """Read a prompt file, cached by absolute path.

    Prompts are static files baked into the repo; reading the same large
    system prompt hundreds of times per investigation is pure overhead.
    The cache key is the absolute path, so entries never collide across
    modules.
    """
    return Path(path_str).read_text(encoding="utf-8")


class PromptRegistry:
    """Resolves a module's system prompt from its on-disk prompt directory."""

    def __init__(self, prompt_dir: Path | str, *, fallback_base: str) -> None:
        self._dir = Path(prompt_dir)
        self._fallback_base = fallback_base

    def load(self, strategy_family: str, persona_voice: str | None = None) -> str:
        """Return the system prompt for a strategy family + optional persona.

        The base is ``system_<strategy-leaf>.md`` (falling back to the
        module's base filename). When ``persona_voice`` is set and a
        ``persona_<voice>.md`` file exists, it is prepended to the base.
        Raises PromptNotFoundError when no base prompt can be resolved.
        """
        leaf = strategy_family.rsplit(".", 1)[-1]
        base_candidate = self._dir / f"system_{leaf}.md"
        if not base_candidate.exists():
            base_candidate = self._dir / self._fallback_base
        if not base_candidate.exists():
            raise PromptNotFoundError(f"prompt file missing: {base_candidate}")
        base = _cached_read_prompt(str(base_candidate))

        if persona_voice:
            persona_candidate = self._dir / f"persona_{persona_voice.lower()}.md"
            if persona_candidate.exists():
                persona_prefix = _cached_read_prompt(str(persona_candidate))
                return f"{persona_prefix}\n\n---\n\n{base}"
        return base
