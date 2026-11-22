"""Prompt builder that wraps, but never rewrites, an upstream SAST skill."""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from aila.modules.vr.sast.catalog import SAST_UPSTREAM_COMMIT, SAST_UPSTREAM_URL, load_sast_skill
from aila.modules.vr.sast.models import SastSkill

__all__ = ["SastSeedBuilder"]


@lru_cache(maxsize=1)
def _adapter_template() -> str:
    return (Path(__file__).parent / "prompts" / "sast_seed_template.md").read_text(encoding="utf-8")


class SastSeedBuilder:
    """Bind one exact skill to VR's persisted investigation output model."""

    @staticmethod
    def build(skill: SastSkill, stage_context: str = "") -> str:
        context = stage_context.strip()
        if context:
            context += "\n"
        return _adapter_template().format(
            skill_id=skill.id,
            title=skill.title,
            phase=skill.phase.value,
            upstream_url=SAST_UPSTREAM_URL,
            upstream_commit=SAST_UPSTREAM_COMMIT,
            skill_body=load_sast_skill(skill),
            stage_context=context,
        )
