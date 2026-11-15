"""System prompts for forensics panel branches.

A panel branch's system prompt is its persona note, the shared panel
protocol, and the free-flow forensic investigator prompt for the project's
analyzer OS, in that order. Each (analyzer OS, persona) pair is one
version-store key, seeded from the files in ``prompts/`` and resolved through
the RFC-09 pin-per-investigation rule, so a production-alias change never
rewrites the prompt of a running panel.
"""
from __future__ import annotations

from pathlib import Path

from aila.modules.forensics.agents.investigator import (
    freeflow_analyzer_os,
    load_freeflow_prompt,
)
from aila.modules.forensics.db_models import InvestigationRunRecord
from aila.platform.contracts.enums import PersonaVoice
from aila.platform.prompts import LoadedPrompt, PromptNotFoundError
from aila.platform.prompts.pinning import resolve_pinned_prompt
from aila.platform.prompts.version_store import PromptVersionStore

__all__ = [
    "PANEL_PERSONAS",
    "compose_panel_prompt",
    "panel_prompt_key",
    "resolve_panel_prompt",
    "seed_prompt_versions",
]

_PROMPT_DIR = Path(__file__).parent / "prompts"
_PROTOCOL_FILE = "panel_protocol.md"
_PROMPT_VERSION_STORE = PromptVersionStore()

# The three panel voices. Setup forks HALVAR as the primary branch and
# spawns MADDIE and RENZO as siblings.
PANEL_PERSONAS: tuple[PersonaVoice, ...] = (
    PersonaVoice.HALVAR,
    PersonaVoice.MADDIE,
    PersonaVoice.RENZO,
)
_PANEL_PERSONA_VALUES = frozenset(p.value for p in PANEL_PERSONAS)


def _persona_value(persona_voice: str | None) -> str:
    value = (persona_voice or "").strip().lower()
    if value not in _PANEL_PERSONA_VALUES:
        raise PromptNotFoundError(f"forensics panel has no persona prompt for {persona_voice!r}")
    return value


def panel_prompt_key(analyzer_os: str, persona_voice: str | None) -> str:
    """Version-store key for one (analyzer OS, persona) panel prompt."""
    return f"forensics/panel/{freeflow_analyzer_os(analyzer_os)}/{_persona_value(persona_voice)}"


def compose_panel_prompt(analyzer_os: str, persona_voice: str | None) -> str:
    """Return the file baseline: persona note, panel protocol, investigator prompt."""
    persona = _persona_value(persona_voice)
    persona_note = (_PROMPT_DIR / f"persona_{persona}.md").read_text(encoding="utf-8")
    protocol = (_PROMPT_DIR / _PROTOCOL_FILE).read_text(encoding="utf-8")
    return f"{persona_note}\n\n---\n\n{protocol}\n\n---\n\n{load_freeflow_prompt(analyzer_os)}"


async def resolve_panel_prompt(
    analyzer_os: str,
    persona_voice: str | None,
    *,
    investigation_id: str | None,
    model_family: str | None = None,
) -> LoadedPrompt:
    """Resolve a branch's system prompt through the version store.

    The first turn pins the production-alias version onto the investigation
    row and later turns resolve that version. With no deployed version (or a
    store fault) the file baseline is returned with ``version=None``.
    """
    key = panel_prompt_key(analyzer_os, persona_voice)
    body, version = await resolve_pinned_prompt(
        investigation_id=investigation_id,
        key=key,
        investigation_model=InvestigationRunRecord,
        store=_PROMPT_VERSION_STORE,
        model_family=model_family,
    )
    if body is not None:
        return LoadedPrompt(body=body, version=version)
    return LoadedPrompt(body=compose_panel_prompt(analyzer_os, persona_voice), version=None)


async def seed_prompt_versions() -> int:
    """Register every panel prompt baseline and set missing production aliases.

    Same lifecycle as the free-flow seed: ``register`` deduplicates by content
    hash, and ``production`` is pointed at the seeded version only when the key
    has no production alias yet. Returns the count of aliases newly set.
    """
    seeded = 0
    for analyzer_os in ("linux", "windows"):
        for persona in PANEL_PERSONAS:
            key = panel_prompt_key(analyzer_os, persona.value)
            version = await _PROMPT_VERSION_STORE.register(
                key,
                compose_panel_prompt(analyzer_os, persona.value),
                author="bootstrap",
                notes="forensics panel file baseline",
            )
            if await _PROMPT_VERSION_STORE.resolve(key, alias="production") is not None:
                continue
            await _PROMPT_VERSION_STORE.set_alias(
                key, "production", version,
                actor="bootstrap", reason="initial file baseline",
            )
            seeded += 1
    return seeded
