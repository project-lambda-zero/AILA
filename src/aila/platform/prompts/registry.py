"""File-backed prompt registry with optional DB override (RFC-09).

The module tool researchers each carried a byte-identical
``_cached_read_prompt`` + ``_load_prompt`` pair differing only in the
fallback base filename and the error class. This platform registry owns
the single file-backed resolution path so no module reimplements it, and
gives RFC-09's later steps (DB overrides, immutable versions, release
aliases, per-investigation pins) one place to grow.

Resolution keys the same role at ``(module, role, strategy, model_family)``
so a shipped role can carry model-specific variants:

    system_<strategy-leaf>__<model_family>.md   # family-specific base
    system_<strategy-leaf>.md                   # generic base
    <fallback_base>__<model_family>.md          # family-specific fallback
    <fallback_base>                             # generic fallback
    persona_<voice>__<model_family>.md          # family-specific persona
    persona_<voice>.md                          # generic persona

A missing ``model_family`` (None) short-circuits the family-specific
lookups so callers that do not track a routed model behave exactly as
before. When a ``PromptVersionStore`` is bound at construction, the
registry consults the store first through
:meth:`PromptRegistry.resolve` and falls back to the file when the
store has no matching entry or fails. The sync :meth:`load` stays
file-only so the existing single-shot callers (human cost, knowledge
enrichment, forensics narrative, ...) keep their pure-file semantics
unchanged.
"""
from __future__ import annotations

import functools
import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple

if TYPE_CHECKING:
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

    ``version`` is None when the caller fell back to the file registry
    (no store row, no store bound, or the store failed open). Callers
    thread ``version`` into the correlation scope so every LLM call
    written by R1's cost / seal writers is attributable to the exact
    version.

    ``canary_key`` is the lifecycle key of the prompt when this turn's
    investigation is bucketed into an active canary cohort (RFC-10), else
    None. Callers thread it into the correlation scope so the seal step can
    feed the turn's drift + cost into that canary's hold gate.

    RFC-09 Amendment 2: ``roster`` / ``routing`` / ``exemplars`` carry the
    pinned agent-config bundle extras when they were populated on the
    resolved version, else None (file-fallback path and every prompt-only
    bundle). ``body`` already has non-empty exemplars folded in by the
    resolver, so this trio is present for callers that need the raw bundle
    (persona-spawn, routing override) rather than a re-materialisation of
    the prompt body.
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


@functools.lru_cache(maxsize=64)
def _cached_read_prompt(path_str: str) -> str:
    """Read a prompt file, cached by absolute path.

    Prompts are static files baked into the repo; reading the same large
    system prompt hundreds of times per investigation is pure overhead.
    The cache key is the absolute path, so entries never collide across
    modules.
    """
    return Path(path_str).read_text(encoding="utf-8")


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
    """Resolves a module's system prompt from its on-disk prompt directory.

    ``module`` is the key prefix used when a version store is bound, so
    the DB key is deterministic and stable across processes: two live
    workers reading the same on-disk prompt directory will build the
    same store key for the same role.

    ``version_store`` is optional -- when supplied, :meth:`resolve`
    consults the store first (a released version overrides the file);
    when omitted, the registry stays purely file-backed and behaves
    exactly like the pre-DB path.
    """

    def __init__(
        self,
        prompt_dir: Path | str,
        *,
        fallback_base: str,
        module: str | None = None,
        version_store: PromptVersionStore | None = None,
        override_alias: str = "production",
    ) -> None:
        self._dir = Path(prompt_dir)
        self._fallback_base = fallback_base
        self._module = (module or self._dir.name).strip().lower() or self._dir.name
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

    # -------------------------------------------------------- file-backed
    def load(
        self,
        strategy_family: str,
        persona_voice: str | None = None,
        *,
        model_family: str | None = None,
    ) -> str:
        """Return the file-backed system prompt for a strategy + persona.

        This sync path never touches the store. Model-family-specific
        variants on disk are preferred when ``model_family`` is set;
        missing them the resolver falls back to the generic file so a
        role that has not been forked per model still resolves.
        """
        return self._resolve_from_file(strategy_family, persona_voice, model_family)

    # ----------------------------------------------------- DB-then-file
    async def resolve(
        self,
        strategy_family: str,
        persona_voice: str | None = None,
        *,
        model_family: str | None = None,
        alias: str | None = None,
        version: str | None = None,
    ) -> LoadedPrompt:
        """Resolve the prompt, preferring a DB override over the file.

        A bound ``version_store`` is consulted first: the family-specific
        key wins if a row exists, otherwise the default-variant key on
        the same (module/role/strategy) tuple is tried, so a role that
        has no per-family override transparently uses its shared
        version-store body. A store fault (or an unbound store) falls
        through to the file with ``version=None``. The persona prepend
        applies to the file path only -- version-store bodies are stored
        under a persona-scoped key and are treated verbatim.
        """
        effective_alias = alias if alias is not None else self._override_alias
        if self._store is not None:
            # Family-specific key first; when the routed family has no row,
            # retry the default-variant key on the same module/role/strategy
            # tuple so a role that was never forked per model transparently
            # uses its shared version-store body.
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
            for key, family in candidates:
                try:
                    row = await self._store.resolve(
                        key,
                        alias=effective_alias,
                        version=version,
                        model_family=family,
                    )
                except (OSError, RuntimeError) as exc:
                    _log.warning(
                        "prompt version store resolve failed key=%s: %s (using file)",
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
        body = self._resolve_from_file(strategy_family, persona_voice, model_family)
        return LoadedPrompt(body=body, version=None)

    # ---------------------------------------------------------- internals
    def _resolve_from_file(
        self,
        strategy_family: str,
        persona_voice: str | None,
        model_family: str | None,
    ) -> str:
        base_candidate = self._pick_base(strategy_family, model_family)
        if base_candidate is None:
            attempted = list(self._base_candidates(strategy_family, model_family))
            raise PromptNotFoundError(
                f"prompt file missing: tried {[str(p) for p in attempted]}",
            )
        base = _cached_read_prompt(str(base_candidate))

        if not persona_voice:
            return base
        persona_candidate = self._pick_persona(persona_voice, model_family)
        if persona_candidate is None:
            return base
        persona_prefix = _cached_read_prompt(str(persona_candidate))
        return f"{persona_prefix}\n\n---\n\n{base}"

    def _base_candidates(
        self,
        strategy_family: str,
        model_family: str | None,
    ) -> list[Path]:
        leaf = strategy_family.rsplit(".", 1)[-1]
        fallback_stem = self._fallback_base.rsplit(".", 1)[0]
        family = (model_family or "").strip().lower()
        candidates: list[Path] = []
        if family:
            candidates.append(self._dir / f"system_{leaf}__{family}.md")
        candidates.append(self._dir / f"system_{leaf}.md")
        if family:
            candidates.append(self._dir / f"{fallback_stem}__{family}.md")
        candidates.append(self._dir / self._fallback_base)
        return candidates

    def _pick_base(
        self,
        strategy_family: str,
        model_family: str | None,
    ) -> Path | None:
        for candidate in self._base_candidates(strategy_family, model_family):
            if candidate.exists():
                return candidate
        return None

    def _pick_persona(
        self,
        persona_voice: str,
        model_family: str | None,
    ) -> Path | None:
        voice = persona_voice.lower()
        family = (model_family or "").strip().lower()
        candidates: list[Path] = []
        if family:
            candidates.append(self._dir / f"persona_{voice}__{family}.md")
        candidates.append(self._dir / f"persona_{voice}.md")
        for candidate in candidates:
            if candidate.exists():
                return candidate
        return None
