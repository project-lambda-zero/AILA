"""DB-only prompt registry (RFC-09, req 20 cutover).

The module tool researchers each carried a byte-identical
``_cached_read_prompt`` + ``_load_prompt`` pair differing only in the
fallback base filename and the error class. This platform registry owns
the single resolution path so no module reimplements it, and gives
RFC-09's later steps (immutable versions, release aliases,
per-investigation pins) one place to grow.

Req 20 makes the version store the single source of truth: :meth:`load`
and :meth:`resolve` are DB-only, resolving through
:class:`PromptVersionStore` by the ``build_key`` convention and raising
:class:`PromptNotFoundError` when no row matches. There is no file
fallback at runtime. :meth:`load_from_file` is the one explicit on-disk
read, kept for seed-time reads and prompts that are not versioned in the
store.

Resolution keys the same role at ``module/role/strategy/model_family`` so
a shipped role can carry model-specific variants:

    {module}/{persona-or-base}/{strategy}/{family}

A missing ``model_family`` (None) short-circuits the family-specific
lookups so callers that do not track a routed model behave exactly as
before. A ``PromptVersionStore`` is instantiated lazily when none is
bound at construction.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, NamedTuple

from aila.platform.prompts.version_store import PromptVersionStore

__all__ = [
    "LoadedPrompt",
    "PromptNotFoundError",
    "PromptRegistry",
    "normalize_model_family",
]

_log = logging.getLogger(__name__)


class PromptNotFoundError(RuntimeError):
    """Raised when neither the strategy-specific base nor the fallback exists."""


class LoadedPrompt(NamedTuple):
    """Resolved system-prompt body plus the version it was resolved from.

    ``version`` is None when the caller resolved an unversioned baseline.
    Callers thread ``version`` into the correlation scope so every LLM
    call written by R1's cost / seal writers is attributable to the exact
    version.

    ``canary_key`` is the lifecycle key of the prompt when this turn's
    investigation is bucketed into an active canary cohort (RFC-10), else
    None. Callers thread it into the correlation scope so the seal step can
    feed the turn's drift + cost into that canary's hold gate.

    RFC-09 Amendment 2: ``roster`` / ``routing`` / ``exemplars`` carry the
    pinned agent-config bundle extras when they were populated on the
    resolved version, else None (every prompt-only bundle). ``body`` already
    has non-empty exemplars folded in by the resolver, so this trio is
    present for callers that need the raw bundle (persona-spawn, routing
    override) rather than a re-materialisation of the prompt body.
    """

    body: str
    version: str | None
    canary_key: str | None = None
    roster: dict | None = None
    routing: dict | None = None
    exemplars: list | None = None


def _decode_bundle_extras(
    row: Any,
) -> tuple[dict | None, dict | None, list | None]:
    """Return ``(roster, routing, exemplars)`` from a PromptVersionRecord.

    Missing / empty json (a prompt-only bundle) decodes to None so the
    caller can distinguish "no bundle extras" from "empty bundle". A
    corrupted json field is treated as None (log at DEBUG in caller)
    rather than crashing the resolve path -- the base body is still
    served.
    """
    def _load(field_value: str | None, empty: Any) -> Any | None:
        if not field_value or field_value in ("{}", "[]"):
            return None
        try:
            loaded = json.loads(field_value)
        except (TypeError, ValueError) as exc:
            _log.warning(
                "prompt bundle extras json corrupted -- treating as empty: %s",
                exc,
            )
            return None
        if loaded == empty:
            return None
        return loaded

    roster_raw = getattr(row, "roster_json", None)
    routing_raw = getattr(row, "routing_json", None)
    exemplars_raw = getattr(row, "exemplars_json", None)
    roster = _load(roster_raw, {})
    routing = _load(routing_raw, {})
    exemplars = _load(exemplars_raw, [])
    return (
        roster if isinstance(roster, dict) else None,
        routing if isinstance(routing, dict) else None,
        exemplars if isinstance(exemplars, list) else None,
    )


def _fold_exemplars(body: str, exemplars: list | None) -> str:
    """Return ``body`` with the pinned bundle's exemplars appended.

    Empty / None exemplars keep the body byte-identical so a prompt-only
    bundle is indistinguishable from the pre-amendment resolve path. Each
    exemplar renders as ``### Exemplar N`` followed by its content -- a
    string is inlined verbatim, a mapping serialises deterministically as
    JSON so the folded body is reproducible.
    """
    if not exemplars:
        return body
    lines: list[str] = ["", "---", "", "## Exemplars", ""]
    for index, item in enumerate(exemplars, start=1):
        lines.append(f"### Exemplar {index}")
        lines.append("")
        if isinstance(item, str):
            lines.append(item)
        else:
            lines.append(
                json.dumps(item, sort_keys=True, indent=2, ensure_ascii=False),
            )
        lines.append("")
    return body + "\n".join(lines)


# Known model families keyed by substring match against the tail of a
# provider-qualified model id ("anthropic/claude-opus-4-7" ->
# "claude"). Ordered by specificity so a longer marker wins first
# ("gpt-4o" and "o1" both match a mini variant, but "gpt" wins because
# it appears earlier in the tail). Unknown ids return None so the
# caller falls back to the generic variant.
_MODEL_FAMILY_MARKERS: tuple[str, ...] = (
    "claude",
    "gemini",
    "llama",
    "mistral",
    "mixtral",
    "deepseek",
    "qwen",
    "phi",
    "grok",
    "command",
    "yi",
    "gpt",
    "o3",
    "o1",
)


def normalize_model_family(model_id: str | None) -> str | None:
    """Return the coarse family name for a provider-qualified model id.

    Accepts the OpenRouter / provider-prefixed form used across the
    codebase ("anthropic/claude-opus-4-7", "openai/gpt-4o",
    "google/gemini-1.5-pro", "meta-llama/llama-3-70b", ...) and returns
    a short family label ("claude", "gpt", "gemini", ...). Returns
    ``None`` when the id is missing or does not carry a recognised
    marker so the caller falls back to the default variant.
    """
    if not model_id:
        return None
    tail = model_id.rsplit("/", 1)[-1].lower()
    for marker in _MODEL_FAMILY_MARKERS:
        if marker in tail:
            return marker
    return None


def _key_segment(value: str | None, default: str) -> str:
    """Coerce a keyable value to the segment written into the DB key."""
    segment = (value or "").strip().lower()
    return segment or default


class PromptRegistry:
    """Resolves a module's system prompt from the version store.

    ``module`` is the key prefix for the DB key, so the key is
    deterministic and stable across processes: two live workers for the
    same module build the same store key for the same role.

    ``version_store`` is optional -- when omitted, a
    :class:`PromptVersionStore` is instantiated lazily on the first
    :meth:`load` / :meth:`resolve` call. ``prompt_dir`` / ``fallback_base``
    are only used by the explicit :meth:`load_from_file` path and may be
    omitted when the registry is DB-only.
    """

    def __init__(
        self,
        prompt_dir: Path | str | None = None,
        *,
        fallback_base: str | None = None,
        module: str | None = None,
        version_store: Any | None = None,
        override_alias: str = "production",
    ) -> None:
        self._dir = Path(prompt_dir) if prompt_dir is not None else None
        self._fallback_base = fallback_base
        self._module = (
            (module or (self._dir.name if self._dir is not None else ""))
            .strip()
            .lower()
        )
        self._store = version_store
        self._override_alias = override_alias

    # ---------------------------------------------------------------- keys
    def build_key(
        self,
        strategy_family: str,
        persona_voice: str | None = None,
        *,
        model_family: str | None = None,
    ) -> str:
        """Return the ``module/role/strategy/model_family`` store key.

        ``role`` is the persona voice ("halvar", ...) or ``"base"`` when
        no persona applies. ``model_family`` normalises to ``"default"``
        when the caller did not route a specific family, matching the
        file-fallback behaviour.
        """
        role = _key_segment(persona_voice, "base")
        strategy = _key_segment(strategy_family, "default")
        family = _key_segment(model_family, "default")
        return f"{self._module}/{role}/{strategy}/{family}"

    # -------------------------------------------------------------- sync
    def load(
        self,
        strategy_family: str,
        persona_voice: str | None = None,
        *,
        model_family: str | None = None,
    ) -> str:
        """Return the DB-only system prompt for a strategy + persona.

        Resolves synchronously through the version store (instantiating a
        ``PromptVersionStore`` on first use when none was bound) using the
        ``build_key`` convention. Bundle extras are decoded and non-empty
        exemplars are folded into the returned body. Raises
        :class:`PromptNotFoundError` when no version-store row matches --
        there is no file fallback. Callers that need the on-disk baseline
        (seed-time reads, non-versioned prompts) use :meth:`load_from_file`.
        """
        store = self._store or PromptVersionStore()
        self._store = store
        effective_alias = self._override_alias
        for key, family in self._candidate_keys(
            strategy_family, persona_voice, model_family
        ):
            row = store.resolve_sync(
                key, alias=effective_alias, model_family=family,
            )
            if row is not None:
                _, _, exemplars = _decode_bundle_extras(row)
                return _fold_exemplars(row.body, exemplars)
        raise PromptNotFoundError(
            f"no version-store row for strategy {strategy_family!r} "
            f"(module={self._module!r})"
        )

    # -------------------------------------------------------------- async
    async def resolve(
        self,
        strategy_family: str,
        persona_voice: str | None = None,
        *,
        model_family: str | None = None,
        alias: str | None = None,
        version: str | None = None,
    ) -> LoadedPrompt:
        """Resolve the prompt, DB-only, preferring a released version.

        Consults the version store asynchronously (instantiating a
        ``PromptVersionStore`` on first use when none was bound) through
        the ``build_key`` convention. An explicit ``version`` wins over
        ``alias``; when neither is given the ``override_alias`` pointer is
        used. The family-specific key wins if a row exists, otherwise the
        default-variant key on the same (module/role/strategy) tuple is
        tried. Raises :class:`PromptNotFoundError` when nothing matches --
        there is no file fallback.
        """
        store = self._store or PromptVersionStore()
        self._store = store
        effective_alias = alias if alias is not None else self._override_alias
        for key, family in self._candidate_keys(
            strategy_family, persona_voice, model_family
        ):
            try:
                row = await store.resolve(
                    key,
                    alias=effective_alias,
                    version=version,
                    model_family=family,
                )
            except (OSError, RuntimeError) as exc:
                _log.warning(
                    "prompt version store resolve failed key=%s: %s",
                    key,
                    exc,
                )
                break
            if row is not None:
                roster, routing, exemplars = _decode_bundle_extras(row)
                # Fold non-empty exemplars into the body so the LLM
                # actually sees them (RFC-09 Amendment 2 -- exemplars
                # are part of the prompt body + bundle content_hash).
                resolved_body = _fold_exemplars(row.body, exemplars)
                return LoadedPrompt(
                    body=resolved_body,
                    version=row.version,
                    roster=roster,
                    routing=routing,
                    exemplars=exemplars,
                )
        raise PromptNotFoundError(
            f"no version-store row for strategy {strategy_family!r} "
            f"(module={self._module!r})"
        )

    # ---------------------------------------------------------- internals
    def _candidate_keys(
        self,
        strategy_family: str,
        persona_voice: str | None,
        model_family: str | None,
    ) -> list[tuple[str, str | None]]:
        """Return ``(key, family)`` lookup candidates, most specific first.

        The family-specific ``build_key`` is tried first, then the
        default-variant key on the same (module/role/strategy) tuple when a
        model family was routed, so a role never forked per model
        transparently resolves against its shared body. The ``family``
        element is threaded into ``store.resolve*`` so the store can try a
        per-family sub-key when present.
        """
        candidates: list[tuple[str, str | None]] = [
            (
                self.build_key(
                    strategy_family, persona_voice, model_family=model_family,
                ),
                model_family,
            ),
        ]
        if model_family is not None:
            candidates.append(
                (self.build_key(strategy_family, persona_voice), None),
            )
        return candidates
